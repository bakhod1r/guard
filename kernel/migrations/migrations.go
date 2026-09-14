// Package migrations ships Guard's PostgreSQL schema as goose migrations.
//
// Guard does not own a users table: the migrations are text/templates rendered
// against the host application's existing user table.
//
// Typical flow in a host application:
//
//	ref, _ := migrations.Detect(ctx, pool, "users", "id") // inspect the host table
//	migrations.Write("./migrations/guard", ref)           // render SQL into the project
//	migrations.Up(ctx, pool, "./migrations/guard", ref)   // apply it
package migrations

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing/fstest"
	"text/template"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

// VersionTable tracks applied Guard migrations separately from the host's goose table.
const VersionTable = "guard_schema_version"

const tmplExt = ".tmpl"

// LockID is the PostgreSQL advisory lock key held while Guard migrations run.
// It differs from goose's default key so a host application running its own
// goose migrations (possibly while calling Guard's) never waits on Guard.
const LockID int64 = 0x6775617264_6d67 // "guard" "mg"

// newSessionLocker is a variable only so tests can inject a failing locker.
var newSessionLocker = func() (lock.SessionLocker, error) {
	return lock.NewPostgresSessionLocker(lock.WithLockID(LockID))
}

//go:embed sql/*.sql.tmpl
var embedded embed.FS

// templates is the template source; a variable only so tests can inject broken templates.
var templates fs.FS = embedded

// UserRef points Guard at the host application's user table.
type UserRef struct {
	Table    string // as given, e.g. "users" or "auth.users"
	IDColumn string // e.g. "id"
	IDType   string // from format_type(), e.g. "bigint"
}

// idTypePattern is an injection guard: IDType is spliced into DDL verbatim.
var idTypePattern = regexp.MustCompile(`^[a-z0-9 _(),."]+$`)

// Validate reports whether ref is safe to render.
func (r UserRef) Validate() error {
	switch {
	case strings.TrimSpace(r.Table) == "":
		return errors.New("guard migrations: user table is empty")
	case strings.TrimSpace(r.IDColumn) == "":
		return errors.New("guard migrations: user id column is empty")
	case strings.TrimSpace(r.IDType) == "":
		return errors.New("guard migrations: user id type is empty")
	case !idTypePattern.MatchString(r.IDType):
		return fmt.Errorf("guard migrations: user id type %q contains disallowed characters", r.IDType)
	}
	if schema, table, ok := strings.Cut(r.Table, "."); ok && (schema == "" || table == "") {
		return fmt.Errorf("guard migrations: user table %q is malformed", r.Table)
	}
	return nil
}

func (r UserRef) tableIdent() string {
	if schema, table, ok := strings.Cut(r.Table, "."); ok {
		return pgx.Identifier{schema, table}.Sanitize()
	}
	return pgx.Identifier{r.Table}.Sanitize()
}

// Detect inspects the host user table and returns a UserRef for it. table may be
// schema-qualified ("auth.users"); unqualified names follow search_path.
// column defaults to "id". The column must be a PRIMARY KEY or carry a
// single-column UNIQUE constraint/index, and must not be an array.
func Detect(ctx context.Context, pool *pgxpool.Pool, table, column string) (UserRef, error) {
	if column == "" {
		column = "id"
	}
	if strings.TrimSpace(table) == "" {
		return UserRef{}, errors.New("guard migrations: detect: user table is empty")
	}
	var schemaQualified = strings.Contains(table, ".")
	var qualified string
	if schema, tbl, ok := strings.Cut(table, "."); ok {
		qualified = pgx.Identifier{schema, tbl}.Sanitize()
	} else {
		qualified = pgx.Identifier{table}.Sanitize()
	}

	var (
		oid              *uint32
		nspname, relname string
	)
	err := pool.QueryRow(ctx, `
		SELECT c.oid, n.nspname, c.relname
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.oid = to_regclass($1) AND c.relkind IN ('r', 'p')`, qualified).Scan(&oid, &nspname, &relname)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserRef{}, fmt.Errorf("guard migrations: detect: user table %q not found", table)
	}
	if err != nil {
		return UserRef{}, fmt.Errorf("guard migrations: detect table %q: %w", table, err)
	}

	var (
		attnum   int16
		typ      string
		isArray  bool
		isUnique bool
	)
	err = pool.QueryRow(ctx, `
		SELECT a.attnum,
		       format_type(a.atttypid, a.atttypmod),
		       (a.attndims > 0 OR t.typcategory = 'A'),
		       EXISTS (
		           SELECT 1 FROM pg_index i
		           WHERE i.indrelid = a.attrelid
		             AND i.indisunique
		             AND i.indnkeyatts = 1
		             AND i.indkey[0] = a.attnum
		             AND i.indpred IS NULL
		             AND i.indexprs IS NULL)
		FROM pg_attribute a JOIN pg_type t ON t.oid = a.atttypid
		WHERE a.attrelid = $1 AND a.attname = $2 AND a.attnum > 0 AND NOT a.attisdropped`,
		*oid, column).Scan(&attnum, &typ, &isArray, &isUnique)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserRef{}, fmt.Errorf("guard migrations: detect: column %q not found in %s.%s", column, nspname, relname)
	}
	if err != nil {
		return UserRef{}, fmt.Errorf("guard migrations: detect column %q: %w", column, err)
	}
	if isArray {
		return UserRef{}, fmt.Errorf("guard migrations: detect: column %s.%s.%s has array type %s; foreign keys need a scalar id", nspname, relname, column, typ)
	}
	if !isUnique {
		return UserRef{}, fmt.Errorf("guard migrations: detect: column %s.%s.%s is not a PRIMARY KEY and has no single-column UNIQUE constraint or index; foreign keys require one", nspname, relname, column)
	}

	// Canonical catalog names so rendered (quoted) identifiers match what
	// to_regclass resolved, e.g. unquoted "Users" -> "users".
	name := relname
	if schemaQualified {
		name = nspname + "." + relname
	}
	ref := UserRef{Table: name, IDColumn: column, IDType: typ}
	if err := ref.Validate(); err != nil {
		return UserRef{}, fmt.Errorf("guard migrations: detect: %w", err)
	}
	return ref, nil
}

// Render executes the embedded templates with ref and returns the *.sql files.
func Render(ref UserRef) (fs.FS, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	data := struct{ UserTable, UserIDColumn, UserIDType string }{
		UserTable:    ref.tableIdent(),
		UserIDColumn: pgx.Identifier{ref.IDColumn}.Sanitize(),
		UserIDType:   ref.IDType,
	}
	entries, err := fs.ReadDir(templates, "sql")
	if err != nil {
		return nil, err
	}
	out := fstest.MapFS{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), tmplExt) {
			continue
		}
		b, err := fs.ReadFile(templates, "sql/"+e.Name())
		if err != nil {
			return nil, err
		}
		t, err := template.New(e.Name()).Option("missingkey=error").Parse(string(b))
		if err != nil {
			return nil, fmt.Errorf("guard migrations: parse %s: %w", e.Name(), err)
		}
		var buf bytes.Buffer
		if err := t.Execute(&buf, data); err != nil {
			return nil, fmt.Errorf("guard migrations: render %s: %w", e.Name(), err)
		}
		out[strings.TrimSuffix(e.Name(), tmplExt)] = &fstest.MapFile{Data: buf.Bytes(), Mode: 0o644}
	}
	return out, nil
}

// Write renders the migrations into dir. Existing files are left untouched
// so local edits survive; the returned slice lists files actually written.
func Write(dir string, ref UserRef) ([]string, error) {
	fsys, err := Render(ref)
	if err != nil {
		return nil, err
	}
	return writeFS(dir, fsys)
}

func writeFS(dir string, fsys fs.FS) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // migration files are committed source, must be readable by the host repo
		return nil, err
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var written []string
	for _, e := range entries {
		dst := filepath.Join(dir, e.Name())
		if _, err := os.Stat(dst); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return written, err
		}
		b, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return written, err
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil { //nolint:gosec // SQL migrations are non-secret source files
			return written, err
		}
		written = append(written, dst)
	}
	return written, nil
}

// Up applies pending migrations. dir == "" renders the embedded templates with
// ref; otherwise the files in dir are applied and ref is ignored.
func Up(ctx context.Context, pool *pgxpool.Pool, dir string, ref UserRef) error {
	p, db, err := provider(pool, dir, ref)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("guard migrations: %w", err)
	}
	return nil
}

// Down rolls back every Guard migration. Destroys all Guard data; the host
// user table is never touched.
func Down(ctx context.Context, pool *pgxpool.Pool, dir string, ref UserRef) error {
	p, db, err := provider(pool, dir, ref)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if _, err := p.DownTo(ctx, 0); err != nil {
		return fmt.Errorf("guard migrations: %w", err)
	}
	return nil
}

func provider(pool *pgxpool.Pool, dir string, ref UserRef) (*goose.Provider, *sql.DB, error) {
	var fsys fs.FS
	if dir != "" {
		fsys = os.DirFS(dir)
	} else {
		var err error
		if fsys, err = Render(ref); err != nil {
			return nil, nil, err
		}
	}
	// Replicas starting together serialise on a session advisory lock, so each
	// migration is applied exactly once.
	locker, err := newSessionLocker()
	if err != nil {
		return nil, nil, fmt.Errorf("guard migrations: session locker: %w", err)
	}
	db := stdlib.OpenDBFromPool(pool)
	p, err := goose.NewProvider(goose.DialectPostgres, db, fsys,
		goose.WithTableName(VersionTable), goose.WithDisableGlobalRegistry(true), goose.WithSessionLocker(locker))
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return p, db, nil
}
