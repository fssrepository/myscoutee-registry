package demoseed

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/app"
	"github.com/fssrepository/myscoutee-registry/internal/config"
	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func TestSeedCreatesAuditableIdempotentDemoRegistry(t *testing.T) {
	t.Parallel()

	cfg := demoConfig(t)
	first, err := Seed(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("seed demo registry: %v", err)
	}
	if first.AlreadySeeded ||
		first.RegistryScope != cfg.RegistryScope ||
		first.LedgerEntries != 36 ||
		len(first.DeploymentIDs) != 4 ||
		first.DeploymentIDs[3] != deterministicID("dep_", 4) {
		t.Fatalf("unexpected first seed summary: %+v", first)
	}

	second, err := Seed(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("repeat demo seed: %v", err)
	}
	if !second.AlreadySeeded || second.LedgerEntries != 36 {
		t.Fatalf("repeat seed was not an idempotent no-op: %+v", second)
	}

	runtime, err := app.BootstrapExisting(
		context.Background(),
		cfg,
		app.Options{Now: func() time.Time { return completionTime }},
	)
	if err != nil {
		t.Fatalf("reopen seeded demo registry: %v", err)
	}
	defer runtime.Close()

	claimed, err := runtime.Service.Leaderboard(
		context.Background(),
		"claimed",
		"2026-06",
		100,
		"",
	)
	if err != nil {
		t.Fatalf("query seeded claimed leaderboard: %v", err)
	}
	if len(claimed.Items) != 2 ||
		claimed.Items[0].Label != "Campus Operator s.r.o." ||
		claimed.Items[0].DeploymentCount != 2 ||
		claimed.Items[0].WeightNumerator != "65000" ||
		claimed.Items[0].ClaimState != protocol.OperatorClaimStateApproved ||
		claimed.Items[1].Label != "City Operator kft." ||
		claimed.Items[1].ClaimState != protocol.OperatorClaimStatePendingReview ||
		claimed.Items[1].WeightNumerator != "30000" {
		t.Fatalf("unexpected seeded claimed leaderboard: %+v", claimed.Items)
	}

	unclaimed, err := runtime.Service.Leaderboard(
		context.Background(),
		"unclaimed",
		"2026-06",
		100,
		"",
	)
	if err != nil {
		t.Fatalf("query seeded unclaimed leaderboard: %v", err)
	}
	if len(unclaimed.Items) != 1 ||
		unclaimed.Items[0].RowID != deterministicID("dep_", 4) ||
		unclaimed.Items[0].WeightNumerator != "12000" {
		t.Fatalf("unexpected seeded unclaimed leaderboard: %+v", unclaimed.Items)
	}

	revenue, err := runtime.Service.RevenueSummary(
		context.Background(),
		"2026-07-28",
		"USD",
		"",
		"",
	)
	if err != nil {
		t.Fatalf("query seeded revenue: %v", err)
	}
	if revenue.DeploymentCount != 4 ||
		revenue.CapturedMinor != 276_000 ||
		revenue.RefundedMinor != 8_000 ||
		revenue.NetMinor != 268_000 ||
		revenue.PaymentCount != 72 {
		t.Fatalf("unexpected seeded revenue: %+v", revenue)
	}

	settlements, err := runtime.Service.SettlementHistoryForAdmin(
		context.Background(),
		store.SettlementHistoryQuery{
			Period:       "2026-06",
			CurrencyCode: "USD",
			Limit:        20,
		},
	)
	if err != nil {
		t.Fatalf("query seeded settlement: %v", err)
	}
	if len(settlements.Items) != 2 {
		t.Fatalf(
			"seeded settlement allocations = %+v, want founder and operator",
			settlements.Items,
		)
	}
	item := settlements.Items[0]
	if item.EarlierThreeMonthAverageMinor != 30_000 ||
		item.PriorThreeMonthAverageMinor != 40_000 ||
		item.RecentThreeMonthAverageMinor != 60_000 ||
		item.PriorGrowthBasisPoints != 3_333 ||
		item.RecentGrowthBasisPoints != 5_000 ||
		item.AccelerationBasisPoints != 1_667 ||
		item.ValuationAdjustmentBasisPoints != 1_666 ||
		item.EffectiveValuationMultiplierBasisPoints != 34_998 ||
		item.TTMCommissionBasisMinor != 390_000 ||
		item.TTMNetworkCommissionPoolMinor != 19_500 ||
		item.IndicativeNetworkValueMinor != 1_364_922 ||
		!item.ValuationIsNonBinding {
		t.Fatalf("unexpected seeded settlement valuation: %+v", item)
	}

	proof, err := runtime.Service.MerkleInclusionProof(
		context.Background(),
		1,
		36,
	)
	if err != nil {
		t.Fatalf("read seeded Merkle proof: %v", err)
	}
	if err := protocol.VerifyMerkleInclusionProof(proof); err != nil {
		t.Fatalf("verify seeded Merkle proof: %v", err)
	}
}

func TestSeededDemoBackupRestorePreservesIdentityLedgerAndMerkle(t *testing.T) {
	t.Parallel()

	source := demoConfig(t)
	if _, err := Seed(context.Background(), source, nil); err != nil {
		t.Fatalf("seed source demo registry: %v", err)
	}
	sourceRuntime, err := app.BootstrapExisting(
		context.Background(),
		source,
		app.Options{Now: func() time.Time { return completionTime }},
	)
	if err != nil {
		t.Fatalf("open source demo registry: %v", err)
	}
	sourceIdentity, err := sourceRuntime.Service.Identity(context.Background())
	if err != nil {
		sourceRuntime.Close()
		t.Fatalf("read source demo identity: %v", err)
	}
	sourceHead, err := sourceRuntime.Store.LedgerHead(context.Background())
	if err != nil {
		sourceRuntime.Close()
		t.Fatalf("read source demo ledger head: %v", err)
	}
	if err := sourceRuntime.Close(); err != nil {
		t.Fatalf("close source before backup: %v", err)
	}

	restoreDirectory := t.TempDir()
	restored := source
	restored.DatabasePath = filepath.Join(
		restoreDirectory,
		"restored-registry-demo.db",
	)
	restored.SigningKeyPath = filepath.Join(
		restoreDirectory,
		"restored-registry-demo-signing-key.pem",
	)
	copyDemoBackupFile(t, source.DatabasePath, restored.DatabasePath, 0o600)
	copyDemoBackupFile(t, source.SigningKeyPath, restored.SigningKeyPath, 0o600)

	restoredRuntime, err := app.BootstrapExisting(
		context.Background(),
		restored,
		app.Options{Now: func() time.Time { return completionTime }},
	)
	if err != nil {
		t.Fatalf("bootstrap restored demo registry: %v", err)
	}
	defer restoredRuntime.Close()
	if err := restoredRuntime.Service.VerifyState(context.Background()); err != nil {
		t.Fatalf("verify restored demo registry: %v", err)
	}
	restoredIdentity, err := restoredRuntime.Service.Identity(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("read restored demo identity: %v", err)
	}
	restoredHead, err := restoredRuntime.Store.LedgerHead(
		context.Background(),
	)
	if err != nil {
		t.Fatalf("read restored demo ledger head: %v", err)
	}
	if restoredIdentity.RegistryKeyID != sourceIdentity.RegistryKeyID ||
		restoredIdentity.RegistryScope != sourceIdentity.RegistryScope ||
		restoredHead != sourceHead {
		t.Fatalf(
			"restored registry changed identity or ledger: identity=%+v head=%+v",
			restoredIdentity,
			restoredHead,
		)
	}
	proof, err := restoredRuntime.Service.MerkleInclusionProof(
		context.Background(),
		36,
		36,
	)
	if err != nil {
		t.Fatalf("read restored Merkle proof: %v", err)
	}
	if err := protocol.VerifyMerkleInclusionProof(proof); err != nil {
		t.Fatalf("verify restored Merkle proof: %v", err)
	}
}

func TestSeedFailsClosedWithoutDedicatedDemoConfiguration(t *testing.T) {
	t.Parallel()

	cfg := demoConfig(t)
	cfg.DemoSeedEnabled = false
	if _, err := Seed(context.Background(), cfg, nil); err == nil {
		t.Fatal("seed unexpectedly accepted a disabled demo guard")
	}

	cfg = demoConfig(t)
	cfg.RegistryScope = "production:myscoutee"
	if _, err := Seed(context.Background(), cfg, nil); err == nil {
		t.Fatal("seed unexpectedly accepted a production scope")
	}

	cfg = demoConfig(t)
	cfg.DatabasePath = filepath.Join(t.TempDir(), "registry.db")
	if _, err := Seed(context.Background(), cfg, nil); err == nil {
		t.Fatal("seed unexpectedly accepted a non-demo database path")
	}
}

func copyDemoBackupFile(
	t *testing.T,
	sourcePath string,
	targetPath string,
	mode os.FileMode,
) {
	t.Helper()
	content, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read demo backup source %s: %v", sourcePath, err)
	}
	if err := os.WriteFile(targetPath, content, mode); err != nil {
		t.Fatalf("write demo backup target %s: %v", targetPath, err)
	}
}

func TestSeedResumesOnlyAnExplicitlyMarkedPartialDemo(t *testing.T) {
	t.Parallel()

	cfg := demoConfig(t)
	clock := &mutableClock{value: seedTime}
	ids := &deterministicIDs{}
	runtime, err := app.Bootstrap(
		context.Background(),
		cfg,
		app.Options{Now: clock.Now, NewID: ids.New},
	)
	if err != nil {
		t.Fatalf("bootstrap partial demo seed: %v", err)
	}
	digest := protocol.Digest([]byte(seedDefinition))
	complete, err := runtime.Store.BeginDemoSeed(
		context.Background(),
		Version,
		cfg.RegistryScope,
		digest,
		seedTime.Format(time.RFC3339),
	)
	if err != nil || complete {
		t.Fatalf("begin partial demo seed: complete=%v err=%v", complete, err)
	}
	if _, err := seedDeployments(
		context.Background(),
		runtime.Service,
		cfg.RegistryScope,
	); err != nil {
		t.Fatalf("write partial demo registrations: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close partial demo seed: %v", err)
	}

	resumed, err := Seed(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("resume explicitly marked partial demo seed: %v", err)
	}
	if resumed.AlreadySeeded || resumed.LedgerEntries != 36 {
		t.Fatalf("unexpected resumed seed summary: %+v", resumed)
	}
}

func TestSeedRejectsPopulatedUnmarkedRegistry(t *testing.T) {
	t.Parallel()

	cfg := demoConfig(t)
	clock := &mutableClock{value: seedTime}
	ids := &deterministicIDs{}
	runtime, err := app.Bootstrap(
		context.Background(),
		cfg,
		app.Options{Now: clock.Now, NewID: ids.New},
	)
	if err != nil {
		t.Fatalf("bootstrap unmarked registry: %v", err)
	}
	if _, err := seedDeployments(
		context.Background(),
		runtime.Service,
		cfg.RegistryScope,
	); err != nil {
		t.Fatalf("populate unmarked registry: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close unmarked registry: %v", err)
	}

	if _, err := Seed(context.Background(), cfg, nil); err == nil {
		t.Fatal("seed unexpectedly accepted a populated unmarked database")
	}
}

func TestRefreshQualifiedMAUKeepsSixCompleteMonthsPopulated(t *testing.T) {
	t.Parallel()

	cfg := demoConfig(t)
	if _, err := Seed(context.Background(), cfg, nil); err != nil {
		t.Fatalf("seed demo registry before refresh: %v", err)
	}
	future := time.Date(2026, 10, 15, 9, 30, 0, 0, time.UTC)
	first, err := RefreshQualifiedMAU(
		context.Background(),
		cfg,
		nil,
		future,
	)
	if err != nil {
		t.Fatalf("refresh future demo QMAU: %v", err)
	}
	if first.ThroughPeriod != "2026-09" || first.AddedSnapshots != 12 {
		t.Fatalf("unexpected first refresh: %+v", first)
	}
	second, err := RefreshQualifiedMAU(
		context.Background(),
		cfg,
		nil,
		future,
	)
	if err != nil {
		t.Fatalf("repeat future demo QMAU refresh: %v", err)
	}
	if second.ThroughPeriod != "2026-09" || second.AddedSnapshots != 0 {
		t.Fatalf("refresh was not idempotent: %+v", second)
	}

	runtime, err := app.BootstrapExisting(
		context.Background(),
		cfg,
		app.Options{Now: func() time.Time { return future }},
	)
	if err != nil {
		t.Fatalf("reopen refreshed demo registry: %v", err)
	}
	defer runtime.Close()
	claimed, err := runtime.Service.Leaderboard(
		context.Background(),
		"claimed",
		"2026-09",
		100,
		"",
	)
	if err != nil {
		t.Fatalf("query refreshed leaderboard: %v", err)
	}
	if len(claimed.Items) != 2 ||
		claimed.Items[0].WeightNumerator != "65000" ||
		claimed.Items[1].WeightNumerator != "30000" {
		t.Fatalf("refreshed QMAU window changed demo weights: %+v", claimed.Items)
	}
}

func demoConfig(t *testing.T) config.Config {
	t.Helper()
	directory := t.TempDir()
	return config.Config{
		ListenAddress:       "127.0.0.1:0",
		RegistryScope:       "demo:myscoutee",
		DatabasePath:        filepath.Join(directory, "registry-demo.db"),
		SigningKeyPath:      filepath.Join(directory, "registry-demo-signing-key.pem"),
		GenerateSigningKey:  true,
		DemoSeedEnabled:     true,
		TimestampSkew:       5 * time.Minute,
		MaxRequestBodyBytes: 64 * 1024,
		CheckpointInterval:  time.Minute,
		ShutdownTimeout:     5 * time.Second,
		HealthcheckURL:      "http://127.0.0.1/healthz",
	}
}
