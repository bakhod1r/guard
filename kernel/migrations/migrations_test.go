package migrations

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteDoesNotOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "db", "guard")
	written, err := Write(dir)
	if err != nil || len(written) != 3 {
		t.Fatalf("first write: %v %v", written, err)
	}
	custom := filepath.Join(dir, "00001_guard_init.sql")
	if err := os.WriteFile(custom, []byte("-- edited"), 0o644); err != nil {
		t.Fatal(err)
	}
	written, err = Write(dir)
	if err != nil || len(written) != 0 {
		t.Fatalf("second write: %v %v", written, err)
	}
	if b, _ := os.ReadFile(custom); string(b) != "-- edited" {
		t.Fatal("existing file overwritten")
	}
}
