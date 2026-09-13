// Package migrations ships Guard's PostgreSQL schema as goose migrations.
//
// Typical flow in a host application:
//
//	migrations.Write("./migrations/guard")          // copy SQL into the project
//	migrations.Up(ctx, pool, "./migrations/guard")  // apply it
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// VersionTable tracks applied Guard migrations separately from the host's goose table.
const VersionTable = "guard_schema_version"

//go:embed sql/*.sql
var embedded embed.FS

// FS returns the embedded migration files.
func FS() fs.FS {
	sub, err := fs.Sub(embedded, "sql")
	if err != nil {
		panic(err)
	}
	return sub
}

// Write copies the migration files into dir. Existing files are left untouched
// so local edits survive; the returned slice lists files actually written.
func Write(dir string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(FS(), ".")
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
		b, err := fs.ReadFile(FS(), e.Name())
		if err != nil {
			return written, err
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			return written, err
		}
		written = append(written, dst)
	}
	return written, nil
}

// Up applies pending migrations. dir == "" uses the embedded files;
// otherwise the files in dir are applied (see Write).
func Up(ctx context.Context, pool *pgxpool.Pool, dir string) error {
	p, db, err := provider(pool, dir)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("guard migrations: %w", err)
	}
	return nil
}

// Down rolls back every Guard migration. Destroys all Guard data.
func Down(ctx context.Context, pool *pgxpool.Pool, dir string) error {
	p, db, err := provider(pool, dir)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := p.DownTo(ctx, 0); err != nil {
		return fmt.Errorf("guard migrations: %w", err)
	}
	return nil
}

func provider(pool *pgxpool.Pool, dir string) (*goose.Provider, *sql.DB, error) {
	fsys := FS()
	if dir != "" {
		fsys = os.DirFS(dir)
	}
	db := stdlib.OpenDBFromPool(pool)
	p, err := goose.NewProvider(goose.DialectPostgres, db, fsys,
		goose.WithTableName(VersionTable), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	return p, db, nil
}
