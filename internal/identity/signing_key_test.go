package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsSymlinkAndBroadPermissions(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	target := filepath.Join(directory, "target.pem")
	if _, generated, err := LoadOrGenerate(target, true); err != nil {
		t.Fatalf("generate target signing key: %v", err)
	} else if !generated {
		t.Fatalf("first key load should generate a key")
	}

	link := filepath.Join(directory, "link.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create signing-key symlink: %v", err)
	}
	if _, err := Load(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}

	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatalf("broaden signing-key permissions: %v", err)
	}
	if _, err := Load(target); err == nil || !strings.Contains(err.Error(), "group or other") {
		t.Fatalf("expected broad-permission rejection, got %v", err)
	}
}

func TestLoadOrGenerateIsStableAndGenerationCanBeDisabled(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "registry.pem")
	first, generated, err := LoadOrGenerate(path, true)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if !generated {
		t.Fatalf("first load must report generation")
	}
	second, generated, err := LoadOrGenerate(path, true)
	if err != nil {
		t.Fatalf("reload signing key: %v", err)
	}
	if generated {
		t.Fatalf("reload must not generate a replacement key")
	}
	if first.KeyID() != second.KeyID() {
		t.Fatalf("key ID changed across reload: %s != %s", first.KeyID(), second.KeyID())
	}

	missingPath := filepath.Join(t.TempDir(), "absent.pem")
	if _, _, err := LoadOrGenerate(missingPath, false); err == nil {
		t.Fatalf("disabled first-run generation must reject a missing key")
	}
}
