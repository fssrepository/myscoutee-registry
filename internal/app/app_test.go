package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/config"
	"github.com/fssrepository/myscoutee-registry/internal/identity"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func TestBootstrapPersistsIdentityAndRefusesKeyLossOrReplacement(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	cfg := testConfig(directory)
	now := func() time.Time {
		return time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	}

	first, err := Bootstrap(context.Background(), cfg, Options{Now: now})
	if err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	firstKeyID := first.SigningKey.KeyID()
	if err := first.Close(); err != nil {
		t.Fatalf("close first runtime: %v", err)
	}

	restarted, err := Bootstrap(context.Background(), cfg, Options{Now: now})
	if err != nil {
		t.Fatalf("restart bootstrap: %v", err)
	}
	if restarted.SigningKey.KeyID() != firstKeyID {
		t.Fatalf("registry key changed across restart")
	}
	if err := restarted.Close(); err != nil {
		t.Fatalf("close restarted runtime: %v", err)
	}

	originalKey, err := os.ReadFile(cfg.SigningKeyPath)
	if err != nil {
		t.Fatalf("read persisted signing key: %v", err)
	}
	if err := os.Remove(cfg.SigningKeyPath); err != nil {
		t.Fatalf("remove signing key for loss test: %v", err)
	}
	if _, err := Bootstrap(context.Background(), cfg, Options{Now: now}); err == nil {
		t.Fatalf("non-pristine registry must not generate a replacement for a lost key")
	}

	if err := os.WriteFile(cfg.SigningKeyPath, originalKey, 0o600); err != nil {
		t.Fatalf("restore original signing key: %v", err)
	}
	otherPath := filepath.Join(directory, "other.pem")
	if _, _, err := identity.LoadOrGenerate(otherPath, true); err != nil {
		t.Fatalf("generate replacement test key: %v", err)
	}
	otherKey, err := os.ReadFile(otherPath)
	if err != nil {
		t.Fatalf("read replacement test key: %v", err)
	}
	if err := os.WriteFile(cfg.SigningKeyPath, otherKey, 0o600); err != nil {
		t.Fatalf("replace configured key: %v", err)
	}
	if _, err := Bootstrap(context.Background(), cfg, Options{Now: now}); !errors.Is(err, store.ErrRegistryKeyMismatch) {
		t.Fatalf("expected persisted identity mismatch, got %v", err)
	}
}

func TestBootstrapHonorsDisabledFirstRunGeneration(t *testing.T) {
	t.Parallel()

	cfg := testConfig(t.TempDir())
	cfg.GenerateSigningKey = false
	if _, err := Bootstrap(context.Background(), cfg, Options{}); err == nil {
		t.Fatalf("missing key with generation disabled must fail")
	}
}

func TestBootstrapDoesNotSilentlyReuseKeyAfterDatabaseLoss(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	cfg := testConfig(directory)
	runtime, err := Bootstrap(context.Background(), cfg, Options{})
	if err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close first runtime: %v", err)
	}
	if err := os.Remove(cfg.DatabasePath); err != nil {
		t.Fatalf("remove test database: %v", err)
	}

	if _, err := Bootstrap(context.Background(), cfg, Options{}); err == nil {
		t.Fatalf("existing key plus lost database must not silently create a fresh registry")
	}

	cfg.GenerateSigningKey = false
	if _, err := Bootstrap(context.Background(), cfg, Options{}); err == nil {
		t.Fatalf("ordinary no-generation startup must still reject existing key plus lost database")
	}
}

func TestProvisionedKeyRequiresOneShotInitialization(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	cfg := testConfig(directory)
	cfg.GenerateSigningKey = false
	provisionedKey, _, err := identity.LoadOrGenerate(cfg.SigningKeyPath, true)
	if err != nil {
		t.Fatalf("create externally provisioned test key: %v", err)
	}
	if _, err := Bootstrap(context.Background(), cfg, Options{}); err == nil {
		t.Fatalf("ordinary startup must not initialize a pristine database from an existing key")
	}
	keyID, err := InitializeProvisioned(context.Background(), cfg, Options{})
	if err != nil {
		t.Fatalf("one-shot provisioned identity initialization: %v", err)
	}
	if keyID != provisionedKey.KeyID() {
		t.Fatalf("initialized key ID = %s, want %s", keyID, provisionedKey.KeyID())
	}
	runtime, err := Bootstrap(context.Background(), cfg, Options{})
	if err != nil {
		t.Fatalf("ordinary startup after one-shot initialization: %v", err)
	}
	defer runtime.Close()
	if runtime.SigningKey.KeyID() != provisionedKey.KeyID() {
		t.Fatalf("runtime did not use the provisioned key")
	}
}

func testConfig(directory string) config.Config {
	return config.Config{
		ListenAddress:       "127.0.0.1:0",
		RegistryScope:       "example:test-primary",
		DatabasePath:        filepath.Join(directory, "registry.db"),
		SigningKeyPath:      filepath.Join(directory, "registry-key.pem"),
		GenerateSigningKey:  true,
		TimestampSkew:       5 * time.Minute,
		MaxRequestBodyBytes: 64 * 1024,
		CheckpointInterval:  time.Minute,
		ShutdownTimeout:     5 * time.Second,
		HealthcheckURL:      "http://127.0.0.1/healthz",
	}
}
