package demoseed

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/app"
	"github.com/fssrepository/myscoutee-registry/internal/config"
	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/service"
	"github.com/fssrepository/myscoutee-registry/internal/store"
	"github.com/fssrepository/myscoutee-registry/internal/store/sqlite"
)

const (
	Version = "myscoutee-registry-demo-v1"

	// QualifiedMAURule documents the local rule whose aggregate result the
	// demo commitments represent. No user identifier or evidence leaves the
	// deployment.
	QualifiedMAURule = "distinct non-demo/non-test/non-admin human; at least two substantive actions on at least two days in the rolling 30-day window; substantive actions are rate, join, message, host, book, or verified attendance"

	seedDefinition = Version + "\n" +
		"four deterministic Ed25519 deployments\n" +
		"six complete monthly qmau-v1 snapshots per deployment\n" +
		"one installation test and one daily revenue batch per deployment\n" +
		"one approved two-deployment operator group through a client code\n" +
		"one pending claim and one unclaimed deployment\n" +
		"two signed community announcements\n" +
		QualifiedMAURule
)

var (
	seedTime       = time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	completionTime = time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	qmauPeriods    = []string{
		"2026-01",
		"2026-02",
		"2026-03",
		"2026-04",
		"2026-05",
		"2026-06",
	}
)

type Summary struct {
	SeedVersion   string   `json:"seed_version"`
	RegistryScope string   `json:"registry_scope"`
	DeploymentIDs []string `json:"deployment_ids"`
	LedgerEntries int64    `json:"ledger_entries"`
	AlreadySeeded bool     `json:"already_seeded"`
}

type RefreshSummary struct {
	ThroughPeriod  string `json:"through_period"`
	AddedSnapshots int    `json:"added_snapshots"`
}

type seedDeployment struct {
	ID              string
	PrivateKey      ed25519.PrivateKey
	QualifiedMAU    int64
	CapturedMinor   int64
	RefundedMinor   int64
	PaymentCount    int64
	SoftwareVersion string
}

type mutableClock struct {
	value time.Time
}

func (clock *mutableClock) Now() time.Time {
	return clock.value
}

type deterministicIDs struct {
	counts map[string]int64
}

func (ids *deterministicIDs) New(prefix string) (string, error) {
	if ids.counts == nil {
		ids.counts = make(map[string]int64)
	}
	ids.counts[prefix]++
	return deterministicID(prefix, ids.counts[prefix]), nil
}

func deterministicID(prefix string, index int64) string {
	return fmt.Sprintf("%s%032x", prefix, index)
}

func Seed(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
) (Summary, error) {
	if err := validateDemoConfig(cfg); err != nil {
		return Summary{}, err
	}

	clock := &mutableClock{value: seedTime}
	ids := &deterministicIDs{}
	runtime, err := app.Bootstrap(ctx, cfg, app.Options{
		Now:    clock.Now,
		NewID:  ids.New,
		Logger: logger,
	})
	if err != nil {
		return Summary{}, fmt.Errorf("bootstrap isolated demo registry: %w", err)
	}
	defer runtime.Close()

	digest := protocol.Digest([]byte(seedDefinition))
	complete, err := runtime.Store.BeginDemoSeed(
		ctx,
		Version,
		cfg.RegistryScope,
		digest,
		seedTime.Format(time.RFC3339),
	)
	if err != nil {
		return Summary{}, err
	}
	if complete {
		if err := runtime.Service.VerifyState(ctx); err != nil {
			return Summary{}, fmt.Errorf(
				"verify existing seeded demo registry: %w",
				err,
			)
		}
		head, err := runtime.Store.LedgerHead(ctx)
		if err != nil {
			return Summary{}, err
		}
		return Summary{
			SeedVersion:   Version,
			RegistryScope: cfg.RegistryScope,
			LedgerEntries: head.EntryCount,
			AlreadySeeded: true,
		}, nil
	}

	deployments, err := seedDeployments(ctx, runtime.Service, cfg.RegistryScope)
	if err != nil {
		return Summary{}, err
	}
	if err := seedLedger(ctx, runtime.Service, cfg.RegistryScope, deployments); err != nil {
		return Summary{}, err
	}
	if err := seedOperatorNetwork(
		ctx,
		runtime.Service,
		cfg.RegistryScope,
		deployments,
	); err != nil {
		return Summary{}, err
	}
	if err := seedAnnouncements(ctx, runtime.Service); err != nil {
		return Summary{}, err
	}

	clock.value = completionTime
	if err := runtime.Service.FinalizeCompletedCheckpoints(ctx); err != nil {
		return Summary{}, fmt.Errorf("finalize demo checkpoint: %w", err)
	}
	if err := runtime.Service.VerifyState(ctx); err != nil {
		return Summary{}, fmt.Errorf("verify generated demo registry: %w", err)
	}
	expected := sqlite.DemoSeedExpectedState{
		Deployments:            4,
		UsedNonces:             36,
		IdempotencyRecords:     36,
		LedgerEntries:          32,
		MerkleNodes:            31,
		LedgerWeightRows:       28,
		MAUBatches:             28,
		RevenueBatches:         4,
		RevenueQueryRows:       4,
		Checkpoints:            1,
		OperatorAuditEvents:    4,
		OperatorActionNonces:   4,
		OperatorNetworkRows:    4,
		ClaimSubmissions:       3,
		ClaimReviews:           2,
		ClaimStatuses:          3,
		ClaimEligibilityEvents:  0,
		ClaimEligibilityCurrent: 3,
		Announcements:          2,
	}
	if err := runtime.Store.CompleteDemoSeed(
		ctx,
		Version,
		cfg.RegistryScope,
		digest,
		completionTime.Format(time.RFC3339),
		expected,
	); err != nil {
		return Summary{}, err
	}
	if err := ensureDemoSettlement(
		ctx,
		runtime.Service,
		cfg.RegistryScope,
		deployments[0],
		completionTime,
	); err != nil {
		return Summary{}, err
	}
	if err := runtime.Service.VerifyState(ctx); err != nil {
		return Summary{}, fmt.Errorf(
			"verify generated demo settlement: %w",
			err,
		)
	}
	head, err := runtime.Store.LedgerHead(ctx)
	if err != nil {
		return Summary{}, err
	}

	deploymentIDs := make([]string, 0, len(deployments))
	for _, deployment := range deployments {
		deploymentIDs = append(deploymentIDs, deployment.ID)
	}
	return Summary{
		SeedVersion:   Version,
		RegistryScope: cfg.RegistryScope,
		DeploymentIDs: deploymentIDs,
		LedgerEntries: head.EntryCount,
		AlreadySeeded: false,
	}, nil
}

// RefreshQualifiedMAU keeps a long-lived Explore registry useful without
// rewriting its baseline. It appends only missing snapshots for the six
// complete months visible to the leaderboard at the supplied clock time.
// The guard, marker, deterministic deployment keys, aggregate-only payload,
// and ordinary signed service path are the same as the initial seed.
func RefreshQualifiedMAU(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
	now time.Time,
) (RefreshSummary, error) {
	if err := validateDemoConfig(cfg); err != nil {
		return RefreshSummary{}, err
	}
	now = now.UTC().Truncate(time.Second)
	runtime, err := app.BootstrapExisting(ctx, cfg, app.Options{
		Now:    func() time.Time { return now },
		Logger: logger,
	})
	if err != nil {
		return RefreshSummary{}, fmt.Errorf(
			"open isolated demo registry for QMAU refresh: %w",
			err,
		)
	}
	defer runtime.Close()

	digest := protocol.Digest([]byte(seedDefinition))
	complete, err := runtime.Store.BeginDemoSeed(
		ctx,
		Version,
		cfg.RegistryScope,
		digest,
		seedTime.Format(time.RFC3339),
	)
	if err != nil {
		return RefreshSummary{}, err
	}
	if !complete {
		return RefreshSummary{}, fmt.Errorf(
			"demo QMAU refresh requires a completed baseline",
		)
	}
	firstDeployment := demoDeployment(1)
	firstDeployment.ID = deterministicID("dep_", 1)
	if err := ensureDemoSettlement(
		ctx,
		runtime.Service,
		cfg.RegistryScope,
		firstDeployment,
		now,
	); err != nil {
		return RefreshSummary{}, err
	}

	periods := sixCompleteMonths(now)
	added := 0
	for deploymentIndex := 1; deploymentIndex <= 4; deploymentIndex++ {
		deployment := demoDeployment(deploymentIndex)
		deployment.ID = deterministicID("dep_", int64(deploymentIndex))
		for _, period := range periods {
			exists, err := runtime.Store.HasQualifiedMAU(
				ctx,
				deployment.ID,
				period,
			)
			if err != nil {
				return RefreshSummary{}, err
			}
			if exists {
				continue
			}
			request := qmauRequestAt(
				deployment,
				cfg.RegistryScope,
				deploymentIndex,
				period,
				now,
			)
			if _, err := runtime.Service.SubmitBatch(ctx, request); err != nil {
				return RefreshSummary{}, fmt.Errorf(
					"append refreshed demo QMAU for deployment %d period %s: %w",
					deploymentIndex,
					period,
					err,
				)
			}
			added++
		}
	}
	if err := runtime.Service.VerifyState(ctx); err != nil {
		return RefreshSummary{}, fmt.Errorf(
			"verify refreshed demo QMAU state: %w",
			err,
		)
	}
	return RefreshSummary{
		ThroughPeriod:  periods[len(periods)-1],
		AddedSnapshots: added,
	}, nil
}

func seedDeployments(
	ctx context.Context,
	registry *service.Service,
	registryScope string,
) ([]seedDeployment, error) {
	specifications := make([]seedDeployment, 4)
	for index := range specifications {
		specifications[index] = demoDeployment(index + 1)
	}
	for index := range specifications {
		request, err := registrationRequest(
			specifications[index].PrivateKey,
			registryScope,
			index+1,
			specifications[index].SoftwareVersion,
		)
		if err != nil {
			return nil, err
		}
		response, err := registry.RegisterDeployment(ctx, request)
		if err != nil {
			return nil, fmt.Errorf(
				"seed deployment %d registration: %w",
				index+1,
				err,
			)
		}
		expectedID := deterministicID("dep_", int64(index+1))
		if response.DeploymentID != expectedID {
			return nil, fmt.Errorf(
				"seed deployment %d received ID %q, expected %q",
				index+1,
				response.DeploymentID,
				expectedID,
			)
		}
		specifications[index].ID = response.DeploymentID
	}
	return specifications, nil
}

func seedLedger(
	ctx context.Context,
	registry *service.Service,
	registryScope string,
	deployments []seedDeployment,
) error {
	for deploymentIndex, deployment := range deployments {
		installation := installationRequest(
			deployment,
			registryScope,
			deploymentIndex+1,
		)
		if _, err := registry.SubmitBatch(ctx, installation); err != nil {
			return fmt.Errorf(
				"seed deployment %d installation test: %w",
				deploymentIndex+1,
				err,
			)
		}
		for _, period := range qmauPeriods {
			request := qmauRequest(
				deployment,
				registryScope,
				deploymentIndex+1,
				period,
			)
			if _, err := registry.SubmitBatch(ctx, request); err != nil {
				return fmt.Errorf(
					"seed deployment %d QMAU period %s: %w",
					deploymentIndex+1,
					period,
					err,
				)
			}
		}
		revenue := revenueRequest(
			deployment,
			registryScope,
			deploymentIndex+1,
		)
		if _, err := registry.SubmitRevenueBatch(ctx, revenue); err != nil {
			return fmt.Errorf(
				"seed deployment %d revenue: %w",
				deploymentIndex+1,
				err,
			)
		}
	}
	return nil
}

// ensureDemoSettlement adds a small deterministic three-window revenue
// history through ordinary signed deployment requests, then invokes the same
// registry calculation used by an administrator. It is deliberately guarded
// by the immutable settlement history, so a long-lived demo registry receives
// the baseline once without creating a revision on every QMAU refresh.
func ensureDemoSettlement(
	ctx context.Context,
	registry *service.Service,
	registryScope string,
	deployment seedDeployment,
	now time.Time,
) error {
	history, err := registry.SettlementHistoryForAdmin(
		ctx,
		store.SettlementHistoryQuery{
			Period:            "2026-06",
			CurrencyCode:      "USD",
			IncludeSuperseded: true,
			Limit:             1,
		},
	)
	if err != nil {
		return fmt.Errorf("inspect demo settlement baseline: %w", err)
	}
	if len(history.Items) != 0 {
		return nil
	}

	sources := []struct {
		period          string
		commissionBasis int64
		paymentCount    int64
	}{
		{"2025-10-31", 90_000, 9},
		{"2026-01-31", 120_000, 12},
		{"2026-06-30", 180_000, 18},
	}
	for index, source := range sources {
		summary, err := registry.RevenueSummary(
			ctx,
			source.period,
			"USD",
			deployment.ID,
			"",
		)
		if err != nil {
			return fmt.Errorf(
				"inspect demo settlement revenue %s: %w",
				source.period,
				err,
			)
		}
		if summary.ActiveBatchCount != 0 {
			continue
		}
		request := settlementRevenueRequest(
			deployment,
			registryScope,
			index+1,
			source.period,
			source.commissionBasis,
			source.paymentCount,
			now,
		)
		if _, err := registry.SubmitRevenueBatch(ctx, request); err != nil {
			return fmt.Errorf(
				"seed demo settlement revenue %s: %w",
				source.period,
				err,
			)
		}
	}
	calculated, err := registry.CalculateSettlement(ctx, "2026-06", "USD")
	if err != nil {
		return fmt.Errorf("calculate demo settlement: %w", err)
	}
	if calculated.Duplicate {
		return fmt.Errorf(
			"demo settlement baseline unexpectedly resolved as a duplicate",
		)
	}
	return nil
}

func seedOperatorNetwork(
	ctx context.Context,
	registry *service.Service,
	registryScope string,
	deployments []seedDeployment,
) error {
	campusClaim := operatorClaimRequest(
		deployments[0],
		registryScope,
		"campus-claim",
		"Campus Operator s.r.o.",
		"SK-DEMO-2026-001",
		"https://demo.myscoutee.invalid/operators/campus",
		"https://demo.myscoutee.invalid/assets/campus-operator.png",
	)
	campusResponse, err := registry.ApplyOperatorAction(ctx, campusClaim)
	if err != nil {
		return fmt.Errorf("seed campus operator claim: %w", err)
	}
	if _, err := registry.ApproveOperatorClaim(
		ctx,
		service.OperatorClaimApproval{
			DeploymentID:    deployments[0].ID,
			ClaimActionID:   campusResponse.Receipt.ActionID,
			GroupID:         campusResponse.Receipt.GroupID,
			LegalName:       campusClaim.LegalName,
			ReviewerID:      "demo-network-reviewer",
			ReviewReference: "demo-case:campus-primary",
			IdempotencyKey:  "demo_approve_campus_primary",
		},
	); err != nil {
		return fmt.Errorf("approve demo campus operator claim: %w", err)
	}

	issue := operatorActionRequest(
		deployments[0],
		registryScope,
		"campus-client-code",
		protocol.OperatorActionIssueClientToken,
	)
	issue.TokenTTLSeconds = 900
	signOperatorAction(deployments[0].PrivateKey, &issue)
	issued, err := registry.ApplyOperatorAction(ctx, issue)
	if err != nil {
		return fmt.Errorf("issue demo operator client code: %w", err)
	}
	clientToken := issued.Receipt.ClientToken
	expectedClientToken := deterministicID("opc_", 1)
	if clientToken == "" {
		clientToken = expectedClientToken
	}
	if clientToken != expectedClientToken {
		return fmt.Errorf("demo client code does not match deterministic seed")
	}

	redeem := operatorActionRequest(
		deployments[1],
		registryScope,
		"campus-client-code-redeem",
		protocol.OperatorActionRedeemClientToken,
	)
	redeem.ClientToken = clientToken
	signOperatorAction(deployments[1].PrivateKey, &redeem)
	if _, err := registry.ApplyOperatorAction(ctx, redeem); err != nil {
		return fmt.Errorf("redeem demo operator client code: %w", err)
	}
	linkedClaim, err := registry.OperatorClaimForReview(ctx, deployments[1].ID)
	if err != nil {
		return fmt.Errorf("read linked demo claim: %w", err)
	}
	if _, err := registry.ApproveOperatorClaim(
		ctx,
		service.OperatorClaimApproval{
			DeploymentID:    deployments[1].ID,
			ClaimActionID:   linkedClaim.ClaimActionID,
			GroupID:         linkedClaim.GroupID,
			LegalName:       linkedClaim.LegalName,
			ReviewerID:      "demo-network-reviewer",
			ReviewReference: "demo-case:campus-linked",
			IdempotencyKey:  "demo_approve_campus_linked",
		},
	); err != nil {
		return fmt.Errorf("approve linked demo operator claim: %w", err)
	}

	cityClaim := operatorClaimRequest(
		deployments[2],
		registryScope,
		"city-claim",
		"City Operator kft.",
		"HU-DEMO-2026-002",
		"https://demo.myscoutee.invalid/operators/city",
		"https://demo.myscoutee.invalid/assets/city-operator.png",
	)
	if _, err := registry.ApplyOperatorAction(ctx, cityClaim); err != nil {
		return fmt.Errorf("seed pending city operator claim: %w", err)
	}
	return nil
}

func seedAnnouncements(
	ctx context.Context,
	registry *service.Service,
) error {
	drafts := []protocol.AnnouncementDraft{
		{
			ProtocolVersion: protocol.Version,
			PublicationID:   "demo_community_welcome_2026_07",
			Kind:            protocol.AnnouncementKindGeneral,
			Severity:        protocol.AnnouncementSeverityInfo,
			PublishedAt:     seedTime.Format(time.RFC3339),
			Localizations: []protocol.AnnouncementLocalization{
				{
					Locale: "en",
					Title:  "Welcome to the operator community",
					Body:   "Use the configured Discord or forum link for operator coordination and support.",
				},
				{
					Locale: "hu",
					Title:  "Üdvözlünk az operátori közösségben",
					Body:   "Az operátori egyeztetéshez és támogatáshoz használd a beállított Discord- vagy fórumhivatkozást.",
				},
			},
			Links: []protocol.AnnouncementLink{
				{
					Relation: "community",
					URL:      "https://discord.com/",
				},
			},
		},
		{
			ProtocolVersion: protocol.Version,
			PublicationID:   "demo_maintenance_2026_07",
			Kind:            protocol.AnnouncementKindMaintenance,
			Severity:        protocol.AnnouncementSeverityNotice,
			PublishedAt:     seedTime.Format(time.RFC3339),
			Localizations: []protocol.AnnouncementLocalization{
				{
					Locale: "en",
					Title:  "Registry maintenance drill",
					Body:   "This demo announcement shows how operators receive centrally signed maintenance notices.",
				},
				{
					Locale: "hu",
					Title:  "Nyilvántartási karbantartási próba",
					Body:   "Ez a bemutató közlemény megmutatja, hogyan kapják meg az operátorok a központilag aláírt karbantartási értesítéseket.",
				},
			},
		},
	}
	for index, draft := range drafts {
		if _, err := registry.PublishAnnouncement(ctx, draft); err != nil {
			return fmt.Errorf("seed announcement %d: %w", index+1, err)
		}
	}
	return nil
}

func deploymentKey(index int) ed25519.PrivateKey {
	sum := sha256.Sum256([]byte(fmt.Sprintf(
		"%s/deployment/%d",
		Version,
		index,
	)))
	return ed25519.NewKeyFromSeed(sum[:])
}

func demoDeployment(index int) seedDeployment {
	specifications := []seedDeployment{
		{
			QualifiedMAU:  45_000,
			CapturedMinor: 120_000,
			RefundedMinor: 5_000,
			PaymentCount:  30,
		},
		{
			QualifiedMAU:  20_000,
			CapturedMinor: 80_000,
			RefundedMinor: 0,
			PaymentCount:  20,
		},
		{
			QualifiedMAU:  30_000,
			CapturedMinor: 52_000,
			RefundedMinor: 2_000,
			PaymentCount:  14,
		},
		{
			QualifiedMAU:  12_000,
			CapturedMinor: 24_000,
			RefundedMinor: 1_000,
			PaymentCount:  8,
		},
	}
	deployment := specifications[index-1]
	deployment.PrivateKey = deploymentKey(index)
	deployment.SoftwareVersion = "1.0.0-demo"
	return deployment
}

func registrationRequest(
	privateKey ed25519.PrivateKey,
	registryScope string,
	index int,
	softwareVersion string,
) (protocol.RegistrationRequest, error) {
	publicKey := privateKey.Public().(ed25519.PublicKey)
	encodedPublicKey, publicKeyDER, err := protocol.EncodePublicKey(publicKey)
	if err != nil {
		return protocol.RegistrationRequest{}, err
	}
	request := protocol.RegistrationRequest{
		ProtocolVersion: protocol.Version,
		RegistryScope:   registryScope,
		Timestamp:       seedTime.Format(time.RFC3339),
		Nonce:           fmt.Sprintf("demo_registration_nonce_%02d", index),
		IdempotencyKey:  fmt.Sprintf("demo_registration_%02d", index),
		KeyAlgorithm:    protocol.KeyAlgorithmEd25519,
		PublicKey:       encodedPublicKey,
		SoftwareVersion: softwareVersion,
	}
	request.PayloadHash = protocol.Digest(protocol.RegistrationPayload(
		request.KeyAlgorithm,
		request.PublicKey,
		request.SoftwareVersion,
	))
	fingerprint := protocol.PublicKeyFingerprint(publicKeyDER)
	request.Signature = protocol.EncodeSignature(ed25519.Sign(
		privateKey,
		protocol.CanonicalRequest(
			http.MethodPost,
			protocol.RegistrationPath,
			request.ProtocolVersion,
			request.RegistryScope,
			fingerprint,
			request.Timestamp,
			request.Nonce,
			request.IdempotencyKey,
			request.PayloadHash,
		),
	))
	return request, nil
}

func installationRequest(
	deployment seedDeployment,
	registryScope string,
	index int,
) protocol.BatchRequest {
	request := protocol.BatchRequest{
		ProtocolVersion:   protocol.Version,
		RegistryScope:     registryScope,
		DeploymentID:      deployment.ID,
		Timestamp:         seedTime.Format(time.RFC3339),
		Nonce:             fmt.Sprintf("demo_installation_nonce_%02d", index),
		IdempotencyKey:    fmt.Sprintf("demo_installation_%02d", index),
		Kind:              protocol.InstallationTestKind,
		Period:            "2026-06",
		RulesetVersion:    protocol.InstallationTestRuleset,
		QualifiedMAUCount: 0,
	}
	request.CommitmentHash = protocol.Digest(
		protocol.InstallationTestCommitment(
			request.DeploymentID,
			request.IdempotencyKey,
		),
	)
	request.PayloadHash = protocol.Digest(protocol.BatchPayload(
		request.Kind,
		request.Period,
		request.RulesetVersion,
		request.QualifiedMAUCount,
		request.CommitmentHash,
	))
	signBatch(deployment.PrivateKey, &request)
	return request
}

func qmauRequest(
	deployment seedDeployment,
	registryScope string,
	deploymentIndex int,
	period string,
) protocol.BatchRequest {
	return qmauRequestAt(
		deployment,
		registryScope,
		deploymentIndex,
		period,
		seedTime,
	)
}

func qmauRequestAt(
	deployment seedDeployment,
	registryScope string,
	deploymentIndex int,
	period string,
	timestamp time.Time,
) protocol.BatchRequest {
	periodToken := strings.ReplaceAll(period, "-", "_")
	request := protocol.BatchRequest{
		ProtocolVersion:   protocol.Version,
		RegistryScope:     registryScope,
		DeploymentID:      deployment.ID,
		Timestamp:         timestamp.UTC().Format(time.RFC3339),
		Nonce:             fmt.Sprintf("demo_qmau_nonce_%02d_%s", deploymentIndex, periodToken),
		IdempotencyKey:    fmt.Sprintf("demo_qmau_%02d_%s", deploymentIndex, periodToken),
		Kind:              protocol.QualifiedMAUKind,
		Period:            period,
		RulesetVersion:    protocol.QualifiedMAURuleset,
		QualifiedMAUCount: deployment.QualifiedMAU,
		Revision:          1,
	}
	request.CommitmentHash = protocol.Digest([]byte(strings.Join(
		[]string{
			"myscoutee-demo-qmau-evidence-commitment-v1",
			QualifiedMAURule,
			deployment.ID,
			period,
			fmt.Sprintf("%d", deployment.QualifiedMAU),
		},
		"\n",
	)))
	request.PayloadHash = protocol.Digest(protocol.QualifiedMAUPayload(
		request.Period,
		request.RulesetVersion,
		request.QualifiedMAUCount,
		request.CommitmentHash,
		request.Revision,
		request.SupersedesBatchID,
	))
	signBatch(deployment.PrivateKey, &request)
	return request
}

func sixCompleteMonths(now time.Time) []string {
	firstOfCurrentMonth := time.Date(
		now.UTC().Year(),
		now.UTC().Month(),
		1,
		0,
		0,
		0,
		0,
		time.UTC,
	)
	periods := make([]string, 6)
	for index := range periods {
		monthsBack := 6 - index
		periods[index] = firstOfCurrentMonth.
			AddDate(0, -monthsBack, 0).
			Format("2006-01")
	}
	return periods
}

func validateDemoConfig(cfg config.Config) error {
	if !cfg.DemoSeedEnabled {
		return fmt.Errorf("start-demo requires REGISTRY_DEMO_SEED=true")
	}
	if !strings.HasPrefix(cfg.RegistryScope, "demo:") {
		return fmt.Errorf(
			"start-demo requires REGISTRY_SCOPE to begin with demo:",
		)
	}
	if !strings.Contains(
		strings.ToLower(filepath.Base(cfg.DatabasePath)),
		"demo",
	) || !strings.Contains(
		strings.ToLower(filepath.Base(cfg.SigningKeyPath)),
		"demo",
	) {
		return fmt.Errorf(
			"start-demo requires dedicated database and signing-key filenames containing \"demo\"",
		)
	}
	return nil
}

func signBatch(
	privateKey ed25519.PrivateKey,
	request *protocol.BatchRequest,
) {
	request.Signature = protocol.EncodeSignature(ed25519.Sign(
		privateKey,
		protocol.CanonicalRequest(
			http.MethodPost,
			protocol.BatchPath,
			request.ProtocolVersion,
			request.RegistryScope,
			request.DeploymentID,
			request.Timestamp,
			request.Nonce,
			request.IdempotencyKey,
			request.PayloadHash,
		),
	))
}

func revenueRequest(
	deployment seedDeployment,
	registryScope string,
	index int,
) protocol.RevenueBatchRequest {
	netMinor := deployment.CapturedMinor - deployment.RefundedMinor
	currencies := []protocol.RevenueCurrency{
		{
			CurrencyCode:             "USD",
			FractionDigits:           2,
			CapturedMinor:            deployment.CapturedMinor,
			RefundedMinor:            deployment.RefundedMinor,
			NetMinor:                 netMinor,
			CommissionBasisMinor:     netMinor,
			EstimatedCommissionMinor: protocol.RevenueCommissionMinor(netMinor),
			PaymentCount:             deployment.PaymentCount,
		},
	}
	request := protocol.RevenueBatchRequest{
		ProtocolVersion:           protocol.Version,
		RegistryScope:             registryScope,
		DeploymentID:              deployment.ID,
		Timestamp:                 seedTime.Format(time.RFC3339),
		Nonce:                     fmt.Sprintf("demo_revenue_nonce_%02d", index),
		IdempotencyKey:            fmt.Sprintf("demo_revenue_%02d", index),
		Kind:                      protocol.RevenueKind,
		Period:                    "2026-07-28",
		Revision:                  1,
		RulesetVersion:            protocol.RevenueRulesetVersion,
		CommissionRateBasisPoints: protocol.RevenueCommissionBasisPoints,
		Currencies:                currencies,
	}
	request.PayloadHash = protocol.Digest(protocol.RevenuePayload(
		request.Kind,
		request.Period,
		request.Revision,
		request.SupersedesBatchID,
		request.RulesetVersion,
		request.CommissionRateBasisPoints,
		request.Currencies,
	))
	request.Signature = protocol.EncodeSignature(ed25519.Sign(
		deployment.PrivateKey,
		protocol.CanonicalRequest(
			http.MethodPost,
			protocol.RevenueBatchPath,
			request.ProtocolVersion,
			request.RegistryScope,
			request.DeploymentID,
			request.Timestamp,
			request.Nonce,
			request.IdempotencyKey,
			request.PayloadHash,
		),
	))
	return request
}

func settlementRevenueRequest(
	deployment seedDeployment,
	registryScope string,
	index int,
	period string,
	commissionBasisMinor int64,
	paymentCount int64,
	now time.Time,
) protocol.RevenueBatchRequest {
	request := protocol.RevenueBatchRequest{
		ProtocolVersion: protocol.Version,
		RegistryScope:   registryScope,
		DeploymentID:    deployment.ID,
		Timestamp:       now.UTC().Truncate(time.Second).Format(time.RFC3339),
		Nonce: fmt.Sprintf(
			"demo_settlement_revenue_nonce_%02d",
			index,
		),
		IdempotencyKey: fmt.Sprintf(
			"demo_settlement_revenue_%02d",
			index,
		),
		Kind:                      protocol.RevenueKind,
		Period:                    period,
		Revision:                  1,
		RulesetVersion:            protocol.RevenueRulesetVersion,
		CommissionRateBasisPoints: protocol.RevenueCommissionBasisPoints,
		Currencies: []protocol.RevenueCurrency{{
			CurrencyCode:             "USD",
			FractionDigits:           2,
			CapturedMinor:            commissionBasisMinor,
			RefundedMinor:            0,
			NetMinor:                 commissionBasisMinor,
			CommissionBasisMinor:     commissionBasisMinor,
			EstimatedCommissionMinor: protocol.RevenueCommissionMinor(
				commissionBasisMinor,
			),
			PaymentCount: paymentCount,
		}},
	}
	request.PayloadHash = protocol.Digest(protocol.RevenuePayload(
		request.Kind,
		request.Period,
		request.Revision,
		request.SupersedesBatchID,
		request.RulesetVersion,
		request.CommissionRateBasisPoints,
		request.Currencies,
	))
	request.Signature = protocol.EncodeSignature(ed25519.Sign(
		deployment.PrivateKey,
		protocol.CanonicalRequest(
			http.MethodPost,
			protocol.RevenueBatchPath,
			request.ProtocolVersion,
			request.RegistryScope,
			request.DeploymentID,
			request.Timestamp,
			request.Nonce,
			request.IdempotencyKey,
			request.PayloadHash,
		),
	))
	return request
}

func operatorClaimRequest(
	deployment seedDeployment,
	registryScope string,
	suffix string,
	legalName string,
	registrationNumber string,
	website string,
	avatarURL string,
) protocol.OperatorActionRequest {
	request := operatorActionRequest(
		deployment,
		registryScope,
		suffix,
		protocol.OperatorActionClaim,
	)
	request.LegalName = legalName
	request.RegistrationNumber = registrationNumber
	request.Jurisdiction = "European Union"
	request.RegisteredAddress = "Demo Street 1, 811 01 Bratislava, Slovakia"
	request.Website = website
	request.VerificationContactName = "Demo Review Contact"
	request.VerificationContactRole = "Director"
	request.VerificationContactEmail = "review@demo.myscoutee.invalid"
	request.AuthorityAttested = true
	request.OperatorAvatarURL = avatarURL
	signOperatorAction(deployment.PrivateKey, &request)
	return request
}

func operatorActionRequest(
	deployment seedDeployment,
	registryScope string,
	suffix string,
	action string,
) protocol.OperatorActionRequest {
	return protocol.OperatorActionRequest{
		ProtocolVersion: protocol.Version,
		RegistryScope:   registryScope,
		DeploymentID:    deployment.ID,
		Timestamp:       seedTime.Format(time.RFC3339),
		Nonce:           "demo_operator_nonce_" + suffix,
		IdempotencyKey:  "demo_operator_" + suffix,
		Action:          action,
	}
}

func signOperatorAction(
	privateKey ed25519.PrivateKey,
	request *protocol.OperatorActionRequest,
) {
	clientTokenHash := ""
	if request.Action == protocol.OperatorActionRedeemClientToken {
		clientTokenHash = protocol.Digest([]byte(request.ClientToken))
	}
	request.PayloadHash = protocol.Digest(protocol.OperatorActionPayload(
		request.Action,
		request.OperatorName,
		request.OperatorAvatarURL,
		clientTokenHash,
		request.TokenTTLSeconds,
		request.TokenID,
		request.LinkID,
	))
	if request.Action == protocol.OperatorActionClaim {
		request.PayloadHash = protocol.Digest(protocol.OperatorClaimPayload(
			request.LegalName,
			request.RegistrationNumber,
			request.Jurisdiction,
			request.RegisteredAddress,
			request.Website,
			request.VerificationContactName,
			request.VerificationContactRole,
			request.VerificationContactEmail,
			request.AuthorityAttested,
			request.OperatorAvatarURL,
		))
	}
	request.Signature = protocol.EncodeSignature(ed25519.Sign(
		privateKey,
		protocol.CanonicalRequest(
			http.MethodPost,
			protocol.OperatorActionPath,
			request.ProtocolVersion,
			request.RegistryScope,
			request.DeploymentID,
			request.Timestamp,
			request.Nonce,
			request.IdempotencyKey,
			request.PayloadHash,
		),
	))
}
