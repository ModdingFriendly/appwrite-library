package rows

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoRuntimeOrSiblingImports enforces the package boundary: the rows
// helpers must stay runtime-independent so any Function (OpenRuntimes, a
// gateway or a test) can drive them. It also rejects a sibling-module replace
// directive, which would make the published module unreproducible.
func TestNoRuntimeOrSiblingImports(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(source)
		for _, forbidden := range []string{"openruntimes", "/functions/", "types-for-go/v4/openruntimes"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s imports a forbidden runtime/function dependency: %s", name, forbidden)
			}
		}
	}
	mod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mod), "\nreplace ") || strings.HasPrefix(string(mod), "replace ") {
		t.Fatal("go.mod must not contain replace directives")
	}
}
