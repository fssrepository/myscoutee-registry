package config

import "testing"

func TestRegistryScopeIsExplicitAndValidated(t *testing.T) {
	t.Setenv("REGISTRY_SCOPE", "")
	if _, err := Load(); err == nil {
		t.Fatalf("configuration must reject a missing registry scope")
	}

	t.Setenv("REGISTRY_SCOPE", "Example:Region")
	if _, err := Load(); err == nil {
		t.Fatalf("configuration must reject a non-canonical registry scope")
	}

	t.Setenv("REGISTRY_SCOPE", "example:region-a")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load explicit registry scope: %v", err)
	}
	if cfg.RegistryScope != "example:region-a" {
		t.Fatalf("registry scope = %q", cfg.RegistryScope)
	}
}
