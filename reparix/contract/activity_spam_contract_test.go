package contract_test

// Package-boundary contract for the activity and spam packages. Both are
// consumed by service Functions, so they must stay runtime-independent and the
// published module must not rely on a sibling-module replace directive.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestActivityAndSpamAvoidRuntimeImports(t *testing.T) {
	for _, dir := range []string{"../activity", "../spam"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read %s: %v", filepath.Join(dir, name), err)
			}
			source := string(raw)
			for _, forbidden := range []string{
				"openruntimes",
				"types-for-go/v4/openruntimes",
				"/functions/",
				"github.com/ModdingFriendly/Reparix",
			} {
				if strings.Contains(source, forbidden) {
					t.Errorf("%s/%s depends on forbidden runtime/function source %q", dir, name, forbidden)
				}
			}
		}
	}
}

func TestModuleHasNoReplaceDirectives(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "replace ") {
			t.Fatalf("go.mod must not contain a replace directive: %s", line)
		}
	}
}
