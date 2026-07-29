package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"

	"github.com/fssrepository/myscoutee-registry/internal/app"
	"github.com/fssrepository/myscoutee-registry/internal/config"
	"github.com/fssrepository/myscoutee-registry/internal/globalidentity"
	"github.com/fssrepository/myscoutee-registry/internal/service"
)

type globalIdentityKeyRotationOutput struct {
	KeyVersion  int64  `json:"key_version"`
	Suite       string `json:"suite"`
	PublicKey   string `json:"public_key"`
	ActivatedAt string `json:"activated_at"`
	RestartRequired bool `json:"restart_required"`
}

func runRotateGlobalIdentityKey(
	args []string,
	stdout io.Writer,
	logger *slog.Logger,
) error {
	flags := flag.NewFlagSet(
		"rotate-global-identity-key",
		flag.ContinueOnError,
	)
	flags.SetOutput(stdout)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry rotate-global-identity-key",
		)
		fmt.Fprintln(
			stdout,
			"Appends a fresh RFC 9497 VOPRF key version. Existing versions are retained for explicit correction. Restart the registry after rotation.",
		)
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil {
		return err
	}
	if help {
		return nil
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	runtime, err := app.BootstrapExisting(ctx, cfg, app.Options{
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("verify registry before VOPRF rotation: %w", err)
	}
	if err := runtime.Close(); err != nil {
		return fmt.Errorf("close verified registry before VOPRF rotation: %w", err)
	}
	key, err := globalidentity.Rotate(
		cfg.GlobalIdentityVOPRFKeyRingPath,
		nil,
	)
	if err != nil {
		return fmt.Errorf("rotate global identity VOPRF key: %w", err)
	}
	runtime, err = app.BootstrapExisting(ctx, cfg, app.Options{
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf(
			"persist and verify rotated VOPRF public metadata: %w",
			err,
		)
	}
	if err := runtime.Close(); err != nil {
		return fmt.Errorf("close registry after VOPRF rotation: %w", err)
	}
	return writeCLIJSON(stdout, globalIdentityKeyRotationOutput{
		KeyVersion:  key.Version,
		Suite:       key.Suite,
		PublicKey:   base64.StdEncoding.EncodeToString(key.PublicKey),
		ActivatedAt: key.ActivatedAt,
		RestartRequired: true,
	})
}

func runGlobalIdentityDedup(
	args []string,
	stdout io.Writer,
) error {
	flags := flag.NewFlagSet("global-identity-dedup", flag.ContinueOnError)
	flags.SetOutput(stdout)
	period := flags.String(
		"period",
		"",
		"qualified MAU UTC month in YYYY-MM",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry global-identity-dedup --period YYYY-MM",
		)
		fmt.Fprintln(
			stdout,
			"Reads the latest signed-event-bound aggregate global QMAU snapshot. No opaque identity commitment is printed.",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil {
		return err
	}
	if help {
		return nil
	}
	if *period == "" {
		flags.Usage()
		return errors.New("global-identity-dedup requires --period")
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		snapshot, err := registryService.GlobalIdentityDedupSnapshot(
			ctx,
			*period,
		)
		if err != nil {
			return fmt.Errorf("query global identity dedup snapshot: %w", err)
		}
		return writeCLIJSON(stdout, snapshot)
	})
}
