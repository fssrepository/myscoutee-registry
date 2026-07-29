package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

type Config struct {
	ListenAddress       string
	RegistryScope       string
	DatabasePath        string
	SigningKeyPath      string
	GenerateSigningKey  bool
	DemoSeedEnabled     bool
	TimestampSkew       time.Duration
	MaxRequestBodyBytes int64
	ValuationMultiplierBasisPoints int64
	CheckpointInterval  time.Duration
	ShutdownTimeout     time.Duration
	HealthcheckURL      string
}

func Load() (Config, error) {
	cfg := Config{
		ListenAddress:       envOrDefault("REGISTRY_LISTEN_ADDR", ":8080"),
		RegistryScope:       envOrDefault("REGISTRY_SCOPE", ""),
		DatabasePath:        envOrDefault("REGISTRY_DATABASE_PATH", "/data/registry.db"),
		SigningKeyPath:      envOrDefault("REGISTRY_SIGNING_KEY_PATH", "/data/registry-signing-key.pem"),
		GenerateSigningKey:  true,
		DemoSeedEnabled:     false,
		TimestampSkew:       5 * time.Minute,
		MaxRequestBodyBytes: 64 * 1024,
		ValuationMultiplierBasisPoints:
			protocol.SettlementDefaultValuationMultiplierBasisPoints,
		CheckpointInterval:  time.Minute,
		ShutdownTimeout:     10 * time.Second,
		HealthcheckURL:      envOrDefault("REGISTRY_HEALTHCHECK_URL", "http://127.0.0.1:8080/healthz"),
	}

	var err error
	if cfg.GenerateSigningKey, err = envBool("REGISTRY_GENERATE_SIGNING_KEY", cfg.GenerateSigningKey); err != nil {
		return Config{}, err
	}
	if cfg.DemoSeedEnabled, err = envBool("REGISTRY_DEMO_SEED", cfg.DemoSeedEnabled); err != nil {
		return Config{}, err
	}
	if cfg.TimestampSkew, err = envDuration("REGISTRY_TIMESTAMP_SKEW", cfg.TimestampSkew); err != nil {
		return Config{}, err
	}
	if cfg.CheckpointInterval, err = envDuration("REGISTRY_CHECKPOINT_INTERVAL", cfg.CheckpointInterval); err != nil {
		return Config{}, err
	}
	if cfg.ShutdownTimeout, err = envDuration("REGISTRY_SHUTDOWN_TIMEOUT", cfg.ShutdownTimeout); err != nil {
		return Config{}, err
	}
	if cfg.MaxRequestBodyBytes, err = envInt64("REGISTRY_MAX_REQUEST_BODY_BYTES", cfg.MaxRequestBodyBytes); err != nil {
		return Config{}, err
	}
	if cfg.ValuationMultiplierBasisPoints, err = envInt64(
		"REGISTRY_VALUATION_MULTIPLIER_BASIS_POINTS",
		cfg.ValuationMultiplierBasisPoints,
	); err != nil {
		return Config{}, err
	}

	if strings.TrimSpace(cfg.ListenAddress) == "" {
		return Config{}, fmt.Errorf("REGISTRY_LISTEN_ADDR must not be empty")
	}
	if !validScope(cfg.RegistryScope) {
		return Config{}, fmt.Errorf("REGISTRY_SCOPE must be 3-128 lowercase ASCII letters, digits, dots, colons, underscores, or hyphens")
	}
	if strings.TrimSpace(cfg.DatabasePath) == "" {
		return Config{}, fmt.Errorf("REGISTRY_DATABASE_PATH must not be empty")
	}
	if strings.TrimSpace(cfg.SigningKeyPath) == "" {
		return Config{}, fmt.Errorf("REGISTRY_SIGNING_KEY_PATH must not be empty")
	}
	if cfg.TimestampSkew <= 0 {
		return Config{}, fmt.Errorf("REGISTRY_TIMESTAMP_SKEW must be positive")
	}
	if cfg.CheckpointInterval <= 0 {
		return Config{}, fmt.Errorf("REGISTRY_CHECKPOINT_INTERVAL must be positive")
	}
	if cfg.ShutdownTimeout <= 0 {
		return Config{}, fmt.Errorf("REGISTRY_SHUTDOWN_TIMEOUT must be positive")
	}
	if cfg.MaxRequestBodyBytes < 1024 || cfg.MaxRequestBodyBytes > 1024*1024 {
		return Config{}, fmt.Errorf("REGISTRY_MAX_REQUEST_BODY_BYTES must be between 1024 and 1048576")
	}
	if cfg.ValuationMultiplierBasisPoints <
		protocol.SettlementMinimumBaseValuationMultiplierBasisPoints ||
		cfg.ValuationMultiplierBasisPoints >
			protocol.SettlementMaximumBaseValuationMultiplierBasisPoints {
		return Config{}, fmt.Errorf(
			"REGISTRY_VALUATION_MULTIPLIER_BASIS_POINTS must be between 1000 and 100000",
		)
	}
	return cfg, nil
}

func validScope(value string) bool {
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	for index, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == ':' || character == '_' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

func envOrDefault(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return strings.TrimSpace(value)
	}
	return fallback
}

func envBool(name string, fallback bool) (bool, error) {
	value, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}

func envDuration(name string, fallback time.Duration) (time.Duration, error) {
	value, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}

func envInt64(name string, fallback int64) (int64, error) {
	value, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}
