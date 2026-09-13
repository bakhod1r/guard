package migrations

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func renderAll(t *testing.T, ref UserRef) map[string]string {
	t.Helper()
	fsys, err := Render(ref)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		b, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

func TestRenderSubstitutes(t *testing.T) {
	for _, typ := range []string{"bigint", "uuid", "character varying(36)"} {
		files := renderAll(t, UserRef{Table: "users", IDColumn: "id", IDType: typ})
		if len(files) != 3 {
			t.Fatalf("%s: want 3 files, got %d", typ, len(files))
		}
		for _, name := range []string{"00001_guard_init.sql", "00002_guard_seed.sql", "00003_guard_api_key.sql"} {
			body, ok := files[name]
			if !ok {
				t.Fatalf("missing %s", name)
			}
			if strings.Contains(body, "{{") || strings.Contains(body, "}}") {
				t.Fatalf("%s: unrendered template action", name)
			}
		}
		want := "user_id          " + typ + ` PRIMARY KEY REFERENCES "users" ("id")`
		if !strings.Contains(files["00001_guard_init.sql"], want) {
			t.Fatalf("%s: init missing %q", typ, want)
		}
		if !strings.Contains(files["00003_guard_api_key.sql"], typ+` NOT NULL REFERENCES "users" ("id")`) {
			t.Fatalf("%s: api key FK not rendered", typ)
		}
	}
}

func TestRenderSchemaQualified(t *testing.T) {
	files := renderAll(t, UserRef{Table: "auth.users", IDColumn: "user id", IDType: "uuid"})
	if !strings.Contains(files["00001_guard_init.sql"], `REFERENCES "auth"."users" ("user id")`) {
		t.Fatal(`want "auth"."users" ("user id") quoting`)
	}
}

func TestRenderRejectsInvalidRef(t *testing.T) {
	bad := []UserRef{
		{Table: "", IDColumn: "id", IDType: "bigint"},
		{Table: "users", IDColumn: "", IDType: "bigint"},
		{Table: "users", IDColumn: "id", IDType: ""},
		{Table: "users", IDColumn: "id", IDType: "bigint); DROP TABLE users; --"},
		{Table: "users", IDColumn: "id", IDType: "BIGINT"},
		{Table: "users", IDColumn: "id", IDType: "bigint\n"},
		{Table: ".users", IDColumn: "id", IDType: "bigint"},
	}
	for _, ref := range bad {
		if _, err := Render(ref); err == nil {
			t.Errorf("Render(%+v): want error", ref)
		}
		if _, err := Write(t.TempDir(), ref); err == nil {
			t.Errorf("Write(%+v): want error", ref)
		}
	}
}

func TestWriteDoesNotOverwrite(t *testing.T) {
	ref := UserRef{Table: "users", IDColumn: "id", IDType: "bigint"}
	dir := filepath.Join(t.TempDir(), "db", "guard")
	written, err := Write(dir, ref)
	if err != nil || len(written) != 3 {
		t.Fatalf("first write: %v %v", written, err)
	}
	for _, p := range written {
		if strings.HasSuffix(p, ".tmpl") {
			t.Fatalf("written file keeps .tmpl: %s", p)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "00001_guard_init.sql"))
	if !strings.Contains(string(b), `bigint PRIMARY KEY REFERENCES "users" ("id")`) {
		t.Fatal("written file not rendered")
	}
	custom := filepath.Join(dir, "00001_guard_init.sql")
	if err := os.WriteFile(custom, []byte("-- edited"), 0o644); err != nil {
		t.Fatal(err)
	}
	written, err = Write(dir, ref)
	if err != nil || len(written) != 0 {
		t.Fatalf("second write: %v %v", written, err)
	}
	if b, _ := os.ReadFile(custom); string(b) != "-- edited" {
		t.Fatal("existing file overwritten")
	}
}
