package migrations

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/pressly/goose/v3/lock"
)

var validRef = UserRef{Table: "users", IDColumn: "id", IDType: "bigint"}

func TestRenderReportsBrokenTemplates(t *testing.T) {
	cases := []struct {
		name string
		fsys fs.FS
		msg  string
	}{
		{"missing sql dir", fstest.MapFS{}, "file does not exist"},
		{"unreadable template", fstest.MapFS{"sql/a.sql.tmpl": {Mode: fs.ModeDir}}, ""},
		{"parse error", fstest.MapFS{"sql/a.sql.tmpl": {Data: []byte("{{")}}, "parse a.sql.tmpl"},
		{"execute error", fstest.MapFS{"sql/a.sql.tmpl": {Data: []byte("{{.Nope}}")}}, "render a.sql.tmpl"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			old := templates
			templates = c.fsys
			defer func() { templates = old }()
			if _, err := Render(validRef); err == nil || !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("err = %v, want containing %q", err, c.msg)
			}
		})
	}
}

func TestRenderSkipsNonTemplateFiles(t *testing.T) {
	old := templates
	templates = fstest.MapFS{"sql/README.md": {Data: []byte("x")}, "sql/a.sql.tmpl": {Data: []byte("{{.UserIDType}}")}}
	defer func() { templates = old }()
	fsys, err := Render(validRef)
	if err != nil {
		t.Fatal(err)
	}
	if m := fsys.(fstest.MapFS); len(m) != 1 || string(m["a.sql"].Data) != "bigint" {
		t.Fatalf("rendered = %v", m)
	}
}

type failingFS struct{}

func (failingFS) Open(string) (fs.File, error) { return nil, fs.ErrPermission }

func TestWriteReportsFilesystemErrors(t *testing.T) {
	t.Run("invalid ref", func(t *testing.T) {
		if _, err := Write(t.TempDir(), UserRef{}); err == nil {
			t.Fatal("want validation error")
		}
	})
	t.Run("dir path is a file", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Write(filepath.Join(f, "sub"), validRef); err == nil {
			t.Fatal("want mkdir error")
		}
	})
	t.Run("unlistable source", func(t *testing.T) {
		if _, err := writeFS(t.TempDir(), failingFS{}); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unreadable source file", func(t *testing.T) {
		if _, err := writeFS(t.TempDir(), fstest.MapFS{"sub/x": {}}); err == nil {
			t.Fatal("want read error")
		}
	})
	t.Run("unstatable destination", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "locked")
		if err := os.Mkdir(dir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		if _, err := Write(dir, validRef); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unwritable destination", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "ro")
		if err := os.Mkdir(dir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		if _, err := Write(dir, validRef); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestDetectRejectsEmptyTableWithoutQuerying(t *testing.T) {
	if _, err := Detect(context.Background(), nil, "  ", ""); err == nil || !strings.Contains(err.Error(), "user table is empty") {
		t.Fatalf("err = %v", err)
	}
}

func TestDetectStorageErrorsIntegration(t *testing.T) {
	ctx := context.Background()
	pool := freshDB(t)
	if _, err := pool.Exec(ctx, `CREATE DOMAIN "UserId" AS bigint;
		CREATE TABLE users (id bigserial PRIMARY KEY);
		CREATE TABLE odd_users (id "UserId" PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	t.Run("column query fails", func(t *testing.T) {
		if _, err := Detect(ctx, pool, "users", "i\xffd"); err == nil || !strings.Contains(err.Error(), "detect column") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("detected type fails validation", func(t *testing.T) {
		if _, err := Detect(ctx, pool, "odd_users", "id"); err == nil || !strings.Contains(err.Error(), "disallowed characters") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("table query fails", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := Detect(cctx, pool, "users", "id"); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestUpDownErrorsIntegration(t *testing.T) {
	ctx := context.Background()
	pool := freshDB(t)
	for name, run := range map[string]func(context.Context, string, UserRef) error{
		"Up":   func(c context.Context, d string, r UserRef) error { return Up(c, pool, d, r) },
		"Down": func(c context.Context, d string, r UserRef) error { return Down(c, pool, d, r) },
	} {
		t.Run(name+" invalid ref", func(t *testing.T) {
			if err := run(ctx, "", UserRef{}); err == nil || !strings.Contains(err.Error(), "empty") {
				t.Fatalf("err = %v", err)
			}
		})
		t.Run(name+" dir without migrations", func(t *testing.T) {
			if err := run(ctx, t.TempDir(), UserRef{}); err == nil {
				t.Fatal("want provider error")
			}
		})
		t.Run(name+" cancelled context", func(t *testing.T) {
			cctx, cancel := context.WithCancel(ctx)
			cancel()
			if err := run(cctx, "", validRef); err == nil || !strings.HasPrefix(err.Error(), "guard migrations: ") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestProviderReportsLockerError(t *testing.T) {
	old := newSessionLocker
	newSessionLocker = func() (lock.SessionLocker, error) { return nil, errBoomLocker }
	defer func() { newSessionLocker = old }()
	if err := Up(context.Background(), nil, "", validRef); !errors.Is(err, errBoomLocker) {
		t.Fatalf("err = %v", err)
	}
}

var errBoomLocker = errors.New("locker boom")
