package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/announcementfile"
	"github.com/fssrepository/myscoutee-registry/internal/app"
	"github.com/fssrepository/myscoutee-registry/internal/config"
	"github.com/fssrepository/myscoutee-registry/internal/demoseed"
	"github.com/fssrepository/myscoutee-registry/internal/httpapi"
	"github.com/fssrepository/myscoutee-registry/internal/service"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	var err error
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		err = runHealthcheck()
	} else if len(os.Args) == 2 && os.Args[1] == "initialize" {
		err = runInitialize(logger)
	} else if len(os.Args) == 2 && os.Args[1] == "start-demo" {
		err = runDemoServer(logger)
	} else if len(os.Args) >= 2 && os.Args[1] == "publish-announcement" {
		err = runPublishAnnouncement(
			os.Args[2:],
			os.Stdin,
			os.Stdout,
		)
	} else if len(os.Args) >= 2 && os.Args[1] == "list-operator-claims" {
		err = runListOperatorClaims(os.Args[2:], os.Stdout)
	} else if len(os.Args) >= 2 && os.Args[1] == "show-operator-claim" {
		err = runShowOperatorClaim(os.Args[2:], os.Stdout)
	} else if len(os.Args) >= 2 && os.Args[1] == "approve-operator-claim" {
		err = runApproveOperatorClaim(os.Args[2:], os.Stdout)
	} else if len(os.Args) >= 2 && os.Args[1] == "leaderboard" {
		err = runLeaderboard(os.Args[2:], os.Stdout)
	} else if len(os.Args) >= 2 && os.Args[1] == "revenue" {
		err = runRevenue(os.Args[2:], os.Stdout)
	} else if len(os.Args) >= 2 && os.Args[1] == "merkle-proof" {
		err = runMerkleProof(os.Args[2:], os.Stdout)
	} else if len(os.Args) >= 2 && os.Args[1] == "merkle-consistency" {
		err = runMerkleConsistency(os.Args[2:], os.Stdout)
	} else if len(os.Args) >= 2 && os.Args[1] == "verify-merkle-proof" {
		err = runVerifyMerkleProof(os.Args[2:], os.Stdin, os.Stdout)
	} else if len(os.Args) >= 2 && os.Args[1] == "verify-merkle-consistency" {
		err = runVerifyMerkleConsistency(os.Args[2:], os.Stdin, os.Stdout)
	} else if len(os.Args) != 1 {
		err = fmt.Errorf(
			"usage: %s [healthcheck|initialize|start-demo|publish-announcement|list-operator-claims|show-operator-claim|approve-operator-claim|leaderboard|revenue|merkle-proof|merkle-consistency|verify-merkle-proof|verify-merkle-consistency]",
			os.Args[0],
		)
	} else {
		err = runServer(logger)
	}
	if err != nil {
		logger.Error("registry stopped", "error", err)
		os.Exit(1)
	}
}

func runRevenue(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("revenue", flag.ContinueOnError)
	flags.SetOutput(stdout)
	period := flags.String(
		"period",
		"",
		"exact original revenue UTC day in YYYY-MM-DD",
	)
	currency := flags.String(
		"currency",
		"",
		"one supported uppercase ISO-4217 settlement currency",
	)
	deploymentID := flags.String(
		"deployment-id",
		"",
		"optional exact deployment ID breakdown",
	)
	groupID := flags.String(
		"group-id",
		"",
		"optional current claimed operator group breakdown",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry revenue --period YYYY-MM-DD --currency CODE [--deployment-id ID|--group-id ID]",
		)
		fmt.Fprintln(
			stdout,
			"Reads immutable active revenue rows from the local registry database. Currencies are never combined.",
		)
		fmt.Fprintln(
			stdout,
			"network_commission_pool_minor is the registry-wide period/currency floor(overall active commission basis × 500 / 10000), even for a filtered breakdown.",
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
	if *period == "" || *currency == "" {
		flags.Usage()
		return errors.New("revenue requires --period and --currency")
	}
	if *deploymentID != "" && *groupID != "" {
		return errors.New(
			"revenue --deployment-id and --group-id are mutually exclusive",
		)
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		summary, err := registryService.RevenueSummary(
			ctx,
			*period,
			*currency,
			*deploymentID,
			*groupID,
		)
		if err != nil {
			return fmt.Errorf("query revenue: %w", err)
		}
		return writeCLIJSON(stdout, summary)
	})
}

func runListOperatorClaims(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("list-operator-claims", flag.ContinueOnError)
	flags.SetOutput(stdout)
	status := flags.String(
		"status",
		"PENDING_REVIEW",
		"PENDING_REVIEW, APPROVED, or WITHDRAWN",
	)
	limit := flags.Int("limit", 50, "number of summary rows (1-200)")
	afterDeploymentID := flags.String(
		"after-deployment-id",
		"",
		"exclusive deployment cursor copied from next_deployment_id",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry list-operator-claims [--status STATUS] [--limit N] [--after-deployment-id DEPLOYMENT_ID]",
		)
		fmt.Fprintln(stdout, "Outputs review-safe summaries only; pagination cursors are opaque.")
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil {
		return err
	}
	if help {
		return nil
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		page, err := registryService.OperatorClaimsForReview(
			ctx,
			*status,
			*limit,
			*afterDeploymentID,
		)
		if err != nil {
			return fmt.Errorf("list operator claims: %w", err)
		}
		return writeCLIJSON(stdout, page)
	})
}

func runShowOperatorClaim(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("show-operator-claim", flag.ContinueOnError)
	flags.SetOutput(stdout)
	deploymentID := flags.String("deployment-id", "", "exact deployment ID")
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry show-operator-claim --deployment-id DEPLOYMENT_ID",
		)
		fmt.Fprintln(
			stdout,
			"WARNING: output contains private address and verification-contact data; do not send it to shared logs.",
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
	if *deploymentID == "" {
		flags.Usage()
		return errors.New("show-operator-claim requires --deployment-id")
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		detail, err := registryService.OperatorClaimForReview(ctx, *deploymentID)
		if err != nil {
			return fmt.Errorf("show operator claim: %w", err)
		}
		return writeCLIJSON(stdout, detail)
	})
}

func runApproveOperatorClaim(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("approve-operator-claim", flag.ContinueOnError)
	flags.SetOutput(stdout)
	deploymentID := flags.String("deployment-id", "", "exact deployment ID from show")
	claimActionID := flags.String("claim-action-id", "", "exact current claim action ID from show")
	groupID := flags.String("group-id", "", "exact operator group ID from show")
	legalName := flags.String("legal-name", "", "exact legal name from show")
	reviewerID := flags.String(
		"reviewer-id",
		"",
		"bounded non-empty legal audit actor identifier",
	)
	reviewReference := flags.String(
		"review-reference",
		"",
		"bounded non-empty external review/case reference",
	)
	idempotencyKey := flags.String(
		"idempotency-key",
		"",
		"8-128 character printable ASCII retry key",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry approve-operator-claim --deployment-id ID --claim-action-id ID --group-id ID --legal-name NAME --reviewer-id ID --review-reference REF --idempotency-key KEY",
		)
		fmt.Fprintln(
			stdout,
			"All claim identity fields must be copied from show-operator-claim; stale targets fail closed.",
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
	if *deploymentID == "" ||
		*claimActionID == "" ||
		*groupID == "" ||
		*legalName == "" ||
		*reviewerID == "" ||
		*reviewReference == "" ||
		*idempotencyKey == "" {
		flags.Usage()
		return errors.New("approve-operator-claim requires every documented argument")
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		result, err := registryService.ApproveOperatorClaim(
			ctx,
			service.OperatorClaimApproval{
				DeploymentID:    *deploymentID,
				ClaimActionID:   *claimActionID,
				GroupID:         *groupID,
				LegalName:       *legalName,
				ReviewerID:      *reviewerID,
				ReviewReference: *reviewReference,
				IdempotencyKey:  *idempotencyKey,
			},
		)
		if err != nil {
			return fmt.Errorf("approve operator claim: %w", err)
		}
		return writeCLIJSON(stdout, result)
	})
}

func runLeaderboard(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("leaderboard", flag.ContinueOnError)
	flags.SetOutput(stdout)
	view := flags.String("view", "claimed", "founder, claimed, or unclaimed")
	groupID := flags.String(
		"group-id",
		"",
		"return deployments for this group instead of leaderboard rows",
	)
	throughPeriod := flags.String(
		"through-period",
		"",
		"completed UTC month in YYYY-MM format",
	)
	limit := flags.Int("limit", 20, "page size (1-100)")
	cursor := flags.String("cursor", "", "opaque next_cursor from the previous JSON page")
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry leaderboard [--view VIEW|--group-id GROUP_ID] [--through-period YYYY-MM] [--limit N] [--cursor OPAQUE]",
		)
		fmt.Fprintln(stdout, "Outputs the same signed snapshot/page shape as the HTTP leaderboard API.")
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil {
		return err
	}
	if help {
		return nil
	}
	viewExplicit := false
	flags.Visit(func(item *flag.Flag) {
		if item.Name == "view" {
			viewExplicit = true
		}
	})
	if *groupID != "" && viewExplicit {
		return errors.New("leaderboard --group-id cannot be combined with --view")
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		if *groupID != "" {
			page, err := registryService.LeaderboardDeployments(
				ctx,
				*groupID,
				*throughPeriod,
				*limit,
				*cursor,
			)
			if err != nil {
				return fmt.Errorf("query group leaderboard: %w", err)
			}
			return writeCLIJSON(stdout, page)
		}
		page, err := registryService.Leaderboard(
			ctx,
			*view,
			*throughPeriod,
			*limit,
			*cursor,
		)
		if err != nil {
			return fmt.Errorf("query leaderboard: %w", err)
		}
		return writeCLIJSON(stdout, page)
	})
}

func parseCLIFlags(flags *flag.FlagSet, args []string) (bool, error) {
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return true, nil
		}
		return false, err
	}
	if flags.NArg() != 0 {
		flags.Usage()
		return false, errors.New("unexpected positional arguments")
	}
	return false, nil
}

func withRegistryService(
	operation func(context.Context, *service.Service) error,
) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runtime, err := app.BootstrapExisting(ctx, cfg, app.Options{})
	if err != nil {
		return fmt.Errorf("open local registry: %w", err)
	}
	defer runtime.Close()
	return operation(ctx, runtime.Service)
}

func writeCLIJSON(stdout io.Writer, value any) error {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("write JSON result: %w", err)
	}
	return nil
}

func runPublishAnnouncement(
	args []string,
	stdin io.Reader,
	stdout io.Writer,
) error {
	flags := flag.NewFlagSet("publish-announcement", flag.ContinueOnError)
	flags.SetOutput(stdout)
	filePath := flags.String(
		"file",
		"",
		"strict announcement JSON file, or - to read JSON from stdin",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry publish-announcement --file PATH|-",
		)
		fmt.Fprintln(
			stdout,
			"Appends one registry-signed announcement directly to the local registry database.",
		)
		fmt.Fprintln(
			stdout,
			"Use --file - with docker compose exec -T to pipe a strict JSON document.",
		)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || *filePath == "" {
		flags.Usage()
		return errors.New("publish-announcement requires exactly one --file value")
	}

	reader := stdin
	var file *os.File
	if *filePath != "-" {
		var err error
		file, err = os.Open(*filePath)
		if err != nil {
			return fmt.Errorf("open announcement file: %w", err)
		}
		defer file.Close()
		reader = file
	}
	draft, err := announcementfile.Decode(reader)
	if err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runtime, err := app.Bootstrap(ctx, cfg, app.Options{})
	if err != nil {
		return fmt.Errorf("open registry for announcement publication: %w", err)
	}
	defer runtime.Close()

	result, err := runtime.Service.PublishAnnouncement(ctx, draft)
	if err != nil {
		return fmt.Errorf("publish announcement: %w", err)
	}
	if err := runtime.Service.VerifyState(ctx); err != nil {
		return fmt.Errorf("verify registry after announcement publication: %w", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("write publication result: %w", err)
	}
	return nil
}

func runInitialize(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	keyID, err := app.InitializeProvisioned(ctx, cfg, app.Options{Logger: logger})
	if err != nil {
		return fmt.Errorf("initialize provisioned registry identity: %w", err)
	}
	logger.Info(
		"provisioned registry identity is initialized",
		"registry_scope", cfg.RegistryScope,
		"registry_key_id", keyID,
	)
	return nil
}

func runServer(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.DemoSeedEnabled {
		return errors.New(
			"REGISTRY_DEMO_SEED=true is accepted only by the explicit start-demo command",
		)
	}
	return serveRegistry(logger, cfg)
}

func runDemoServer(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	seedContext, cancelSeed := context.WithTimeout(
		context.Background(),
		2*time.Minute,
	)
	defer cancelSeed()
	summary, err := demoseed.Seed(seedContext, cfg, logger)
	if err != nil {
		return fmt.Errorf("seed isolated demo registry: %w", err)
	}
	refresh, err := demoseed.RefreshQualifiedMAU(
		seedContext,
		cfg,
		logger,
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("refresh isolated demo QMAU window: %w", err)
	}
	logger.Info(
		"isolated demo registry is ready",
		"registry_scope", summary.RegistryScope,
		"seed_version", summary.SeedVersion,
		"already_seeded", summary.AlreadySeeded,
		"ledger_entries", summary.LedgerEntries,
		"qmau_through_period", refresh.ThroughPeriod,
		"qmau_snapshots_added", refresh.AddedSnapshots,
	)
	return serveRegistry(logger, cfg)
}

func serveRegistry(logger *slog.Logger, cfg config.Config) error {
	rootContext, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	runtime, err := app.Bootstrap(rootContext, cfg, app.Options{Logger: logger})
	if err != nil {
		return fmt.Errorf("bootstrap registry: %w", err)
	}
	defer runtime.Close()

	listener, err := net.Listen("tcp", cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.ListenAddress, err)
	}
	defer listener.Close()

	handler := httpapi.New(runtime.Service, httpapi.Options{
		MaxRequestBodyBytes: cfg.MaxRequestBodyBytes,
		Logger:              logger,
	})
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}

	workerContext, cancelWorker := context.WithCancel(rootContext)
	defer cancelWorker()
	go runtime.Service.RunCheckpointWorker(workerContext, cfg.CheckpointInterval)

	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.Serve(listener)
	}()
	logger.Info(
		"registry is accepting requests",
		"address", listener.Addr().String(),
		"registry_key_id", runtime.SigningKey.KeyID(),
	)

	select {
	case serveErr := <-serverErrors:
		if errors.Is(serveErr, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve registry HTTP: %w", serveErr)
	case <-rootContext.Done():
	}

	cancelWorker()
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("shut down registry HTTP server: %w", err)
	}
	serveErr := <-serverErrors
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("serve registry HTTP: %w", serveErr)
	}
	logger.Info("registry shut down cleanly")
	return nil
}

func runHealthcheck() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	request, err := http.NewRequest(http.MethodGet, cfg.HealthcheckURL, nil)
	if err != nil {
		return fmt.Errorf("build health-check request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("call registry health endpoint: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("registry health endpoint returned %s", response.Status)
	}
	return nil
}
