package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/config"
	"github.com/fssrepository/myscoutee-registry/internal/globalidentity"
	"github.com/fssrepository/myscoutee-registry/internal/identity"
	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/service"
	"github.com/fssrepository/myscoutee-registry/internal/store"
	"github.com/fssrepository/myscoutee-registry/internal/store/sqlite"
)

type Options struct {
	Now    func() time.Time
	NewID  func(prefix string) (string, error)
	Logger *slog.Logger
}

type Runtime struct {
	Store      *sqlite.Store
	Service    *service.Service
	SigningKey *identity.SigningKey
	GlobalIdentityKeys *globalidentity.KeyRing
}

func Bootstrap(ctx context.Context, cfg config.Config, options Options) (*Runtime, error) {
	return bootstrap(ctx, cfg, options, false)
}

// BootstrapExisting is the only bootstrap path used by operational CLI
// commands. It refuses to create a database, directory, signing key, or
// registry identity when a path is missing or points at pristine state.
func BootstrapExisting(
	ctx context.Context,
	cfg config.Config,
	options Options,
) (*Runtime, error) {
	absoluteKeyPath, err := filepath.Abs(cfg.SigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("resolve registry signing key path: %w", err)
	}
	keyInfo, err := os.Lstat(absoluteKeyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf(
				"registry signing key does not exist: %s",
				absoluteKeyPath,
			)
		}
		return nil, fmt.Errorf("inspect registry signing key: %w", err)
	}
	if keyInfo.Mode()&os.ModeSymlink != 0 || !keyInfo.Mode().IsRegular() {
		return nil, fmt.Errorf(
			"registry signing key must be an existing regular non-symlink file: %s",
			absoluteKeyPath,
		)
	}
	if !protocol.IsRegistryScope(cfg.RegistryScope) {
		return nil, fmt.Errorf(
			"REGISTRY_SCOPE is required and must contain a valid explicit registry scope",
		)
	}
	signingKey, generated, err := identity.LoadOrGenerate(absoluteKeyPath, false)
	if err != nil {
		return nil, fmt.Errorf("load existing registry signing key: %w", err)
	}
	if generated {
		return nil, fmt.Errorf("operational registry bootstrap must not generate a signing key")
	}
	persistedIdentity, err := sqlite.InspectExistingRegistryIdentity(cfg.DatabasePath)
	if err != nil {
		return nil, err
	}
	if persistedIdentity.ProtocolVersion != protocol.Version ||
		persistedIdentity.RegistryScope != cfg.RegistryScope ||
		persistedIdentity.RegistryKeyID != signingKey.KeyID() ||
		!bytes.Equal(persistedIdentity.PublicKeyDER, signingKey.PublicKeyDER()) {
		return nil, fmt.Errorf(
			"%w: configured database, scope, and signing key identity do not match",
			store.ErrInconsistentState,
		)
	}
	cfg.GenerateSigningKey = false
	cfg.GenerateGlobalIdentityVOPRFKey = false
	return bootstrap(ctx, cfg, options, true)
}

func bootstrap(
	ctx context.Context,
	cfg config.Config,
	options Options,
	requireExisting bool,
) (*Runtime, error) {
	registryScope := cfg.RegistryScope
	if !protocol.IsRegistryScope(registryScope) {
		return nil, fmt.Errorf("REGISTRY_SCOPE is required and must contain a valid explicit registry scope")
	}
	var registryStore *sqlite.Store
	var err error
	if requireExisting {
		registryStore, err = sqlite.OpenExisting(cfg.DatabasePath)
	} else {
		registryStore, err = sqlite.Open(cfg.DatabasePath)
	}
	if err != nil {
		return nil, err
	}
	closeOnError := func(cause error) (*Runtime, error) {
		if closeErr := registryStore.Close(); closeErr != nil {
			return nil, fmt.Errorf("%w (also close registry database: %v)", cause, closeErr)
		}
		return nil, cause
	}

	persistedIdentity, err := registryStore.RegistryIdentity(ctx)
	if err != nil {
		return closeOnError(err)
	}
	pristine, err := registryStore.PersistentStateIsPristine(ctx)
	if err != nil {
		return closeOnError(err)
	}
	if persistedIdentity == nil && !pristine {
		return closeOnError(fmt.Errorf(
			"%w: durable records exist without a registry identity",
			store.ErrInconsistentState,
		))
	}
	if requireExisting && persistedIdentity == nil {
		return closeOnError(fmt.Errorf(
			"registry database has no initialized identity; run the explicit initialize command",
		))
	}

	// Generation is deliberately restricted to a truly pristine database. A
	// lost key must stop an established registry instead of silently creating
	// a new identity that cannot verify its existing receipts.
	signingKey, generated, err := identity.LoadOrGenerate(
		cfg.SigningKeyPath,
		cfg.GenerateSigningKey && pristine,
	)
	if err != nil {
		return closeOnError(err)
	}
	if persistedIdentity == nil && pristine && !generated {
		return closeOnError(fmt.Errorf(
			"an existing registry signing key cannot initialize a pristine database during ordinary server startup; restore the database or run the explicit one-shot initialize command",
		))
	}

	now := options.Now
	if now == nil {
		now = time.Now
	}
	expectedIdentity := store.RegistryIdentity{
		ProtocolVersion: protocol.Version,
		RegistryScope:   registryScope,
		RegistryKeyID:   signingKey.KeyID(),
		PublicKeyDER:    signingKey.PublicKeyDER(),
		CreatedAt:       now().UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	if err := registryStore.EnsureRegistryIdentity(ctx, expectedIdentity); err != nil {
		return closeOnError(err)
	}

	globalIdentityKeyPath := cfg.GlobalIdentityVOPRFKeyRingPath
	implicitGlobalIdentityKeyConfiguration := globalIdentityKeyPath == ""
	if globalIdentityKeyPath == "" {
		globalIdentityKeyPath = filepath.Join(
			filepath.Dir(cfg.DatabasePath),
			"registry-global-identity-voprf-keyring.json",
		)
	}
	globalIdentityKeys, globalIdentityKeyGenerated, err :=
		globalidentity.LoadOrGenerate(
			globalIdentityKeyPath,
			(cfg.GenerateGlobalIdentityVOPRFKey ||
				implicitGlobalIdentityKeyConfiguration) &&
				!requireExisting,
			now,
		)
	if err != nil {
		return closeOnError(err)
	}
	keyMetadata := make([]store.GlobalIdentityVOPRFKey, 0)
	for _, key := range globalIdentityKeys.PublicKeys() {
		keyMetadata = append(keyMetadata, store.GlobalIdentityVOPRFKey{
			KeyVersion:  key.Version,
			Suite:       key.Suite,
			PublicKey:   key.PublicKey,
			ActivatedAt: key.ActivatedAt,
		})
	}
	if err := registryStore.EnsureGlobalIdentityVOPRFKeys(
		ctx,
		keyMetadata,
	); err != nil {
		return closeOnError(err)
	}

	registryService := service.New(registryStore, signingKey, service.Options{
		TimestampSkew: cfg.TimestampSkew,
		RegistryScope: registryScope,
		ValuationMultiplierBasisPoints: cfg.ValuationMultiplierBasisPoints,
		GlobalIdentityKeys: globalIdentityKeys,
		Now:           now,
		NewID:         options.NewID,
		Logger:        options.Logger,
	})
	if err := registryService.VerifyState(ctx); err != nil {
		return closeOnError(err)
	}
	if generated && options.Logger != nil {
		options.Logger.Info(
			"generated first-run registry signing key",
			"registry_key_id", signingKey.KeyID(),
			"path", cfg.SigningKeyPath,
		)
	}
	if globalIdentityKeyGenerated && options.Logger != nil {
		options.Logger.Info(
			"generated first global identity VOPRF key",
			"path", globalIdentityKeyPath,
			"key_version",
			globalIdentityKeys.ActivePublicKey().Version,
		)
	}

	return &Runtime{
		Store:      registryStore,
		Service:    registryService,
		SigningKey: signingKey,
		GlobalIdentityKeys: globalIdentityKeys,
	}, nil
}

func InitializeProvisioned(
	ctx context.Context,
	cfg config.Config,
	options Options,
) (string, error) {
	if cfg.GenerateSigningKey {
		return "", fmt.Errorf(
			"one-shot provisioned-key initialization requires REGISTRY_GENERATE_SIGNING_KEY=false",
		)
	}
	if !protocol.IsRegistryScope(cfg.RegistryScope) {
		return "", fmt.Errorf("REGISTRY_SCOPE is required and must contain a valid explicit registry scope")
	}
	registryStore, err := sqlite.Open(cfg.DatabasePath)
	if err != nil {
		return "", err
	}
	defer registryStore.Close()

	persistedIdentity, err := registryStore.RegistryIdentity(ctx)
	if err != nil {
		return "", err
	}
	pristine, err := registryStore.PersistentStateIsPristine(ctx)
	if err != nil {
		return "", err
	}
	if persistedIdentity == nil && !pristine {
		return "", fmt.Errorf(
			"%w: durable records exist without a registry identity",
			store.ErrInconsistentState,
		)
	}
	signingKey, generated, err := identity.LoadOrGenerate(cfg.SigningKeyPath, false)
	if err != nil {
		return "", err
	}
	if generated {
		return "", fmt.Errorf("provisioned-key initialization must never generate a signing key")
	}

	now := options.Now
	if now == nil {
		now = time.Now
	}
	expectedIdentity := store.RegistryIdentity{
		ProtocolVersion: protocol.Version,
		RegistryScope:   cfg.RegistryScope,
		RegistryKeyID:   signingKey.KeyID(),
		PublicKeyDER:    signingKey.PublicKeyDER(),
		CreatedAt:       now().UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	if err := registryStore.EnsureRegistryIdentity(ctx, expectedIdentity); err != nil {
		return "", err
	}
	registryService := service.New(registryStore, signingKey, service.Options{
		TimestampSkew: cfg.TimestampSkew,
		RegistryScope: cfg.RegistryScope,
		ValuationMultiplierBasisPoints: cfg.ValuationMultiplierBasisPoints,
		Now:           now,
		NewID:         options.NewID,
		Logger:        options.Logger,
	})
	if err := registryService.VerifyState(ctx); err != nil {
		return "", err
	}
	return signingKey.KeyID(), nil
}

func (runtime *Runtime) Close() error {
	return runtime.Store.Close()
}
