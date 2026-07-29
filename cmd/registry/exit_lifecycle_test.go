package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/app"
	"github.com/fssrepository/myscoutee-registry/internal/config"
	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/service"
)

type exitLifecycleClaim struct {
	deploymentID  string
	claimActionID string
	groupID       string
	legalName     string
	privateKey    ed25519.PrivateKey
}

type exitLifecycleFixture struct {
	config           config.Config
	databasePath     string
	recordDate       string
	effectiveDate    string
	settlementPeriod string
	source           exitLifecycleClaim
	target           exitLifecycleClaim
}

func TestExitOwnershipAndFinalAllocationCLILifecycle(t *testing.T) {
	fixture := newExitLifecycleFixture(t)

	freezeArgs := []string{
		"--record-date", fixture.recordDate,
		"--deployment-id", fixture.source.deploymentID,
		"--claim-action-id", fixture.source.claimActionID,
		"--group-id", fixture.source.groupID,
		"--actor-role", protocol.ExitReviewActorBuyer,
		"--actor-id", "buyer-system",
		"--reference", "deal:exit-lifecycle",
		"--evidence-hash", protocol.Digest([]byte("exit freeze evidence")),
		"--idempotency-key", "freeze-exit-lifecycle-0001",
	}
	frozen := runExitLifecycleCLI[protocol.ExitReviewMutationResult](
		t,
		runFreezeExitReview,
		freezeArgs,
	)
	if frozen.Duplicate ||
		frozen.Review.Status != protocol.ExitReviewStatusPending ||
		frozen.Event.Action != protocol.ExitReviewActionFreeze ||
		frozen.Review.Record.RecordDate != fixture.recordDate ||
		frozen.Review.Record.TargetDeploymentID !=
			fixture.source.deploymentID ||
		frozen.Review.Record.ClaimActionID != fixture.source.claimActionID ||
		frozen.Review.Record.GroupID != fixture.source.groupID {
		t.Fatalf("unexpected frozen exit review: %+v", frozen)
	}
	assertFrozenExitBoundary(t, frozen.Review.Record)

	freezeReplay := runExitLifecycleCLI[protocol.ExitReviewMutationResult](
		t,
		runFreezeExitReview,
		freezeArgs,
	)
	if !freezeReplay.Duplicate ||
		!reflect.DeepEqual(freezeReplay.Event, frozen.Event) ||
		!reflect.DeepEqual(freezeReplay.Review.Record, frozen.Review.Record) {
		t.Fatalf(
			"exit freeze retry did not return the original signed event: got=%+v want=%+v",
			freezeReplay,
			frozen,
		)
	}
	duplicateFreezeArgs := replaceExitLifecycleFlag(
		freezeArgs,
		"--idempotency-key",
		"freeze-exit-lifecycle-0002",
	)
	assertExitLifecycleCLIErrorContains(
		t,
		runFreezeExitReview,
		duplicateFreezeArgs,
		"already has an exit review",
	)

	prepareBeforeVerifyArgs := ownershipPrepareArgs(
		fixture,
		frozen.Review.Record.ReviewID,
		protocol.ExitReviewZeroHash,
		"prepare-transfer-before-exit-verify",
	)
	assertExitLifecycleCLIErrorContains(
		t,
		runPrepareOwnershipTransfer,
		prepareBeforeVerifyArgs,
		"verified exit-review event",
	)

	verifyExitArgs := []string{
		"--review-id", frozen.Review.Record.ReviewID,
		"--decision", protocol.ExitReviewActionVerify,
		"--effective-date", fixture.effectiveDate,
		"--actor-role", protocol.ExitReviewActorAuditor,
		"--actor-id", "exit-auditor",
		"--reference", "audit:exit-verified",
		"--evidence-hash", protocol.Digest([]byte("verified exit evidence")),
		"--idempotency-key", "verify-exit-lifecycle-0001",
	}
	verifiedExit := runExitLifecycleCLI[protocol.ExitReviewMutationResult](
		t,
		runDecideExitReview,
		verifyExitArgs,
	)
	if verifiedExit.Duplicate ||
		verifiedExit.Review.Status != protocol.ExitReviewStatusEligible ||
		verifiedExit.Event.Action != protocol.ExitReviewActionVerify ||
		verifiedExit.Event.PreviousReviewEventHash != frozen.Event.EventHash ||
		verifiedExit.Event.RecordHash != frozen.Review.Record.RecordHash {
		t.Fatalf("unexpected verified exit review: %+v", verifiedExit)
	}
	verifyExitReplay := runExitLifecycleCLI[protocol.ExitReviewMutationResult](
		t,
		runDecideExitReview,
		verifyExitArgs,
	)
	if !verifyExitReplay.Duplicate ||
		!reflect.DeepEqual(verifyExitReplay.Event, verifiedExit.Event) {
		t.Fatalf(
			"exit verification retry did not return the original event: got=%+v want=%+v",
			verifyExitReplay,
			verifiedExit,
		)
	}
	verifyExitConflictArgs := replaceExitLifecycleFlag(
		verifyExitArgs,
		"--reference",
		"audit:changed-exit-verification",
	)
	assertExitLifecycleCLIErrorContains(
		t,
		runDecideExitReview,
		verifyExitConflictArgs,
		"idempotency_key conflicts",
	)
	secondVerifyArgs := replaceExitLifecycleFlag(
		verifyExitArgs,
		"--idempotency-key",
		"verify-exit-lifecycle-0002",
	)
	assertExitLifecycleCLIErrorContains(
		t,
		runDecideExitReview,
		secondVerifyArgs,
		"state transition is not allowed",
	)

	prepareArgs := ownershipPrepareArgs(
		fixture,
		frozen.Review.Record.ReviewID,
		verifiedExit.Event.EventHash,
		"prepare-transfer-lifecycle-0001",
	)
	prepared := runExitLifecycleCLI[protocol.OwnershipTransferMutationResult](
		t,
		runPrepareOwnershipTransfer,
		prepareArgs,
	)
	if prepared.Duplicate ||
		prepared.Transfer.Status != protocol.OwnershipTransferStatusPrepared ||
		prepared.Event.Action != protocol.OwnershipTransferActionPrepare ||
		prepared.Transfer.Record.ExitRecordHash !=
			frozen.Review.Record.RecordHash ||
		prepared.Transfer.Record.ExitVerificationEventHash !=
			verifiedExit.Event.EventHash {
		t.Fatalf("unexpected prepared ownership transfer: %+v", prepared)
	}
	prepareReplay := runExitLifecycleCLI[protocol.OwnershipTransferMutationResult](
		t,
		runPrepareOwnershipTransfer,
		prepareArgs,
	)
	if !prepareReplay.Duplicate ||
		!reflect.DeepEqual(prepareReplay.Event, prepared.Event) {
		t.Fatalf(
			"ownership prepare retry did not return the original event: got=%+v want=%+v",
			prepareReplay,
			prepared,
		)
	}
	conflictingPrepareArgs := replaceExitLifecycleFlag(
		prepareArgs,
		"--idempotency-key",
		"prepare-transfer-lifecycle-0002",
	)
	assertExitLifecycleCLIErrorContains(
		t,
		runPrepareOwnershipTransfer,
		conflictingPrepareArgs,
		"conflicts with another active transfer",
	)

	completeArgs := ownershipCompleteArgs(
		prepared.Transfer.Record.TransferID,
		fixture.effectiveDate,
		"complete-transfer-lifecycle-0001",
	)
	assertExitLifecycleCLIErrorContains(
		t,
		runCompleteOwnershipTransfer,
		completeArgs,
		"state transition is not allowed",
	)

	approveArgs := []string{
		"--transfer-id", prepared.Transfer.Record.TransferID,
		"--decision", protocol.OwnershipTransferActionApprove,
		"--effective-date", fixture.effectiveDate,
		"--manager-id", "registry-manager",
		"--reference", "decision:transfer-approved",
		"--evidence-hash", protocol.Digest([]byte("transfer approval evidence")),
		"--idempotency-key", "approve-transfer-lifecycle-0001",
	}
	approved := runExitLifecycleCLI[protocol.OwnershipTransferMutationResult](
		t,
		runDecideOwnershipTransfer,
		approveArgs,
	)
	if approved.Duplicate ||
		approved.Transfer.Status != protocol.OwnershipTransferStatusApproved ||
		approved.Event.Action != protocol.OwnershipTransferActionApprove ||
		approved.Event.PreviousTransferEventHash != prepared.Event.EventHash {
		t.Fatalf("unexpected approved ownership transfer: %+v", approved)
	}

	completed := runExitLifecycleCLI[protocol.OwnershipTransferMutationResult](
		t,
		runCompleteOwnershipTransfer,
		completeArgs,
	)
	if completed.Duplicate ||
		completed.Transfer.Status != protocol.OwnershipTransferStatusCompleted ||
		completed.Event.Action != protocol.OwnershipTransferActionComplete ||
		completed.Event.PreviousTransferEventHash != approved.Event.EventHash ||
		completed.Transfer.Membership == nil ||
		completed.Transfer.Membership.SourceGroupID != fixture.source.groupID ||
		completed.Transfer.Membership.TargetGroupID != fixture.target.groupID ||
		completed.Transfer.Membership.CompletionEventHash !=
			completed.Event.EventHash {
		t.Fatalf("unexpected completed ownership transfer: %+v", completed)
	}
	completedReplay := runExitLifecycleCLI[protocol.OwnershipTransferMutationResult](
		t,
		runCompleteOwnershipTransfer,
		completeArgs,
	)
	if !completedReplay.Duplicate ||
		!reflect.DeepEqual(completedReplay.Event, completed.Event) ||
		!reflect.DeepEqual(
			completedReplay.Transfer.Membership,
			completed.Transfer.Membership,
		) {
		t.Fatalf(
			"ownership completion retry did not return the original event and membership: got=%+v want=%+v",
			completedReplay,
			completed,
		)
	}
	cancelAfterCompleteArgs := []string{
		"--transfer-id", prepared.Transfer.Record.TransferID,
		"--effective-date", fixture.effectiveDate,
		"--manager-id", "registry-manager",
		"--reference", "decision:late-cancel",
		"--evidence-hash", protocol.Digest([]byte("late cancel evidence")),
		"--reason-code", "late-cancel",
		"--idempotency-key", "cancel-transfer-lifecycle-0001",
	}
	assertExitLifecycleCLIErrorContains(
		t,
		runCancelOwnershipTransfer,
		cancelAfterCompleteArgs,
		"state transition is not allowed",
	)

	persistedReview := runExitLifecycleCLI[protocol.ExitReview](
		t,
		runShowExitReview,
		[]string{"--review-id", frozen.Review.Record.ReviewID},
	)
	if persistedReview.Status != protocol.ExitReviewStatusEligible ||
		!reflect.DeepEqual(persistedReview.Record, frozen.Review.Record) {
		t.Fatalf(
			"ownership completion changed the frozen exit boundary: got=%+v want=%+v",
			persistedReview.Record,
			frozen.Review.Record,
		)
	}

	noTransferArgs := []string{
		"--exit-review-id", frozen.Review.Record.ReviewID,
		"--exit-verification-event-hash", verifiedExit.Event.EventHash,
		"--decision-mode", protocol.ExitAllocationDecisionNoTransfer,
		"--beneficiary-id", "contract:legacy-beneficiary",
		"--contract-reference", "contract:no-transfer-invalid",
		"--contract-terms-hash", protocol.Digest([]byte("invalid no-transfer terms")),
		"--evidence-hash", protocol.Digest([]byte("invalid no-transfer evidence")),
		"--allocator-id", "allocation-system",
		"--idempotency-key", "create-allocation-no-transfer-invalid",
	}
	assertExitLifecycleCLIErrorContains(
		t,
		runCreateExitAllocation,
		noTransferArgs,
		"beneficiary decision is not valid",
	)

	createAllocationArgs := []string{
		"--exit-review-id", frozen.Review.Record.ReviewID,
		"--exit-verification-event-hash", verifiedExit.Event.EventHash,
		"--decision-mode", protocol.ExitAllocationDecisionCompletedTransfer,
		"--ownership-transfer-id", completed.Transfer.Record.TransferID,
		"--ownership-transfer-completion-event-hash", completed.Event.EventHash,
		"--contract-reference", "contract:completed-transfer",
		"--contract-terms-hash", protocol.Digest([]byte("completed transfer terms")),
		"--evidence-hash", protocol.Digest([]byte("completed transfer allocation evidence")),
		"--allocator-id", "allocation-system",
		"--idempotency-key", "create-allocation-lifecycle-0001",
	}
	createdAllocation := runExitLifecycleCLI[protocol.ExitAllocationMutationResult](
		t,
		runCreateExitAllocation,
		createAllocationArgs,
	)
	if createdAllocation.Duplicate ||
		createdAllocation.Allocation.Status !=
			protocol.ExitAllocationStatusRecorded ||
		createdAllocation.Event.Action != protocol.ExitAllocationActionCreate ||
		createdAllocation.Allocation.Record.BeneficiaryType !=
			protocol.ExitAllocationBeneficiaryOperatorGroup ||
		createdAllocation.Allocation.Record.BeneficiaryID !=
			fixture.target.groupID ||
		createdAllocation.Allocation.Record.OwnershipTransferID !=
			completed.Transfer.Record.TransferID {
		t.Fatalf(
			"unexpected recorded final exit allocation: %+v",
			createdAllocation,
		)
	}
	assertExitAllocationConservation(t, createdAllocation.Allocation.Record)

	createAllocationReplay := runExitLifecycleCLI[protocol.ExitAllocationMutationResult](
		t,
		runCreateExitAllocation,
		createAllocationArgs,
	)
	if !createAllocationReplay.Duplicate ||
		!reflect.DeepEqual(
			createAllocationReplay.Event,
			createdAllocation.Event,
		) ||
		!reflect.DeepEqual(
			createAllocationReplay.Allocation.Record,
			createdAllocation.Allocation.Record,
		) {
		t.Fatalf(
			"allocation create retry did not return the original event: got=%+v want=%+v",
			createAllocationReplay,
			createdAllocation,
		)
	}
	secondAllocationArgs := replaceExitLifecycleFlag(
		createAllocationArgs,
		"--idempotency-key",
		"create-allocation-lifecycle-0002",
	)
	assertExitLifecycleCLIErrorContains(
		t,
		runCreateExitAllocation,
		secondAllocationArgs,
		"already has a final allocation",
	)

	verifyAllocationArgs := []string{
		"--allocation-id",
		createdAllocation.Allocation.Record.AllocationID,
		"--verifier-id", "allocation-verifier",
		"--reference", "audit:allocation-verified",
		"--evidence-hash", protocol.Digest([]byte("final allocation verification evidence")),
		"--idempotency-key", "verify-allocation-lifecycle-0001",
	}
	verifiedAllocation := runExitLifecycleCLI[protocol.ExitAllocationMutationResult](
		t,
		runVerifyExitAllocation,
		verifyAllocationArgs,
	)
	if verifiedAllocation.Duplicate ||
		verifiedAllocation.Allocation.Status !=
			protocol.ExitAllocationStatusVerifiedFinal ||
		verifiedAllocation.Event.Action != protocol.ExitAllocationActionVerify ||
		verifiedAllocation.Event.PreviousAllocationEventHash !=
			createdAllocation.Event.EventHash ||
		verifiedAllocation.Event.RecordHash !=
			createdAllocation.Allocation.Record.RecordHash {
		t.Fatalf(
			"unexpected verified final exit allocation: %+v",
			verifiedAllocation,
		)
	}
	verifyAllocationReplay :=
		runExitLifecycleCLI[protocol.ExitAllocationMutationResult](
			t,
			runVerifyExitAllocation,
			verifyAllocationArgs,
		)
	if !verifyAllocationReplay.Duplicate ||
		!reflect.DeepEqual(
			verifyAllocationReplay.Event,
			verifiedAllocation.Event,
		) {
		t.Fatalf(
			"allocation verification retry did not return the original event: got=%+v want=%+v",
			verifyAllocationReplay,
			verifiedAllocation,
		)
	}
	secondAllocationVerifyArgs := replaceExitLifecycleFlag(
		verifyAllocationArgs,
		"--idempotency-key",
		"verify-allocation-lifecycle-0002",
	)
	assertExitLifecycleCLIErrorContains(
		t,
		runVerifyExitAllocation,
		secondAllocationVerifyArgs,
		"state transition is not allowed",
	)

	assertExitLifecycleLists(
		t,
		frozen.Review.Record.ReviewID,
		completed.Transfer.Record.TransferID,
		verifiedAllocation.Allocation.Record.AllocationID,
	)
	assertExitLifecyclePersistenceAndVerification(
		t,
		fixture,
		frozen,
		verifiedExit,
		prepared,
		completed,
		createdAllocation,
		verifiedAllocation,
	)
	assertExitAllocationTamperingFailsClosed(
		t,
		fixture.databasePath,
		verifiedAllocation.Allocation.Record.AllocationID,
	)
}

func newExitLifecycleFixture(t *testing.T) exitLifecycleFixture {
	t.Helper()
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "registry.db")
	t.Setenv("REGISTRY_SCOPE", "example:cli-exit-lifecycle")
	t.Setenv("REGISTRY_DATABASE_PATH", databasePath)
	t.Setenv(
		"REGISTRY_SIGNING_KEY_PATH",
		filepath.Join(directory, "registry-signing-key.pem"),
	)
	t.Setenv(
		"REGISTRY_GLOBAL_IDENTITY_VOPRF_KEYRING_PATH",
		filepath.Join(directory, "registry-global-identity-voprf-keyring.json"),
	)
	t.Setenv("REGISTRY_GENERATE_SIGNING_KEY", "true")
	t.Setenv("REGISTRY_GENERATE_GLOBAL_IDENTITY_VOPRF_KEY", "true")
	t.Setenv("REGISTRY_DEMO_SEED", "false")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load exit lifecycle config: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	today := time.Date(
		now.Year(),
		now.Month(),
		now.Day(),
		0,
		0,
		0,
		0,
		time.UTC,
	)
	recordDay := today.AddDate(0, 0, -1)
	seedAt := recordDay.Add(12 * time.Hour)
	ctx := context.Background()
	runtime, err := app.Bootstrap(
		ctx,
		cfg,
		app.Options{Now: func() time.Time { return seedAt }},
	)
	if err != nil {
		t.Fatalf("bootstrap lifecycle seed registry: %v", err)
	}
	source := seedExitLifecycleClaim(
		t,
		runtime,
		cfg.RegistryScope,
		seedAt,
		"source",
		"Source Cooperative",
	)
	target := seedExitLifecycleClaim(
		t,
		runtime,
		cfg.RegistryScope,
		seedAt,
		"target",
		"Target Cooperative",
	)
	approveExitLifecycleClaim(t, runtime, source, "source")
	approveExitLifecycleClaim(t, runtime, target, "target")

	settlementMonth := today.AddDate(0, -1, 0)
	revenuePeriod := time.Date(
		settlementMonth.Year(),
		settlementMonth.Month(),
		1,
		0,
		0,
		0,
		0,
		time.UTC,
	).Format("2006-01-02")
	submitExitLifecycleRevenue(
		t,
		runtime,
		cfg.RegistryScope,
		source,
		seedAt,
		revenuePeriod,
	)
	settlement, err := runtime.Service.CalculateSettlement(
		ctx,
		settlementMonth.Format("2006-01"),
		"EUR",
	)
	if err != nil {
		runtime.Close()
		t.Fatalf("calculate lifecycle settlement: %v", err)
	}
	if settlement.Duplicate ||
		settlement.Receipt.CurrencyCode != "EUR" ||
		settlement.Receipt.ThroughLedgerIndex != 1 ||
		settlement.Receipt.LedgerIndex != 2 {
		runtime.Close()
		t.Fatalf("unexpected lifecycle settlement: %+v", settlement)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close lifecycle seed registry: %v", err)
	}

	runtime, err = app.BootstrapExisting(
		ctx,
		cfg,
		app.Options{Now: func() time.Time { return now }},
	)
	if err != nil {
		t.Fatalf("reopen lifecycle registry for checkpoint: %v", err)
	}
	if err := runtime.Service.FinalizeCompletedCheckpoints(ctx); err != nil {
		runtime.Close()
		t.Fatalf("finalize lifecycle record-date checkpoint: %v", err)
	}
	if err := runtime.Service.VerifyState(ctx); err != nil {
		runtime.Close()
		t.Fatalf("verify lifecycle seed state: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close lifecycle checkpoint registry: %v", err)
	}

	return exitLifecycleFixture{
		config:           cfg,
		databasePath:     databasePath,
		recordDate:       recordDay.Format("2006-01-02"),
		effectiveDate:    today.Format("2006-01-02"),
		settlementPeriod: settlementMonth.Format("2006-01"),
		source:           source,
		target:           target,
	}
}

func seedExitLifecycleClaim(
	t *testing.T,
	runtime *app.Runtime,
	registryScope string,
	now time.Time,
	suffix string,
	legalName string,
) exitLifecycleClaim {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate %s lifecycle deployment key: %v", suffix, err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal %s lifecycle deployment key: %v", suffix, err)
	}
	registration := protocol.RegistrationRequest{
		ProtocolVersion: protocol.Version,
		RegistryScope:   registryScope,
		Timestamp:       now.Format(time.RFC3339),
		Nonce:           "nonce_exit_lifecycle_registration_" + suffix,
		IdempotencyKey:  "exit_lifecycle_registration_" + suffix,
		KeyAlgorithm:    protocol.KeyAlgorithmEd25519,
		PublicKey:       base64.StdEncoding.EncodeToString(publicKeyDER),
		SoftwareVersion: "exit-lifecycle-test",
	}
	registration.PayloadHash = protocol.Digest(protocol.RegistrationPayload(
		registration.KeyAlgorithm,
		registration.PublicKey,
		registration.SoftwareVersion,
	))
	registration.Signature = protocol.EncodeSignature(ed25519.Sign(
		privateKey,
		protocol.CanonicalRequest(
			"POST",
			protocol.RegistrationPath,
			registration.ProtocolVersion,
			registration.RegistryScope,
			protocol.PublicKeyFingerprint(publicKeyDER),
			registration.Timestamp,
			registration.Nonce,
			registration.IdempotencyKey,
			registration.PayloadHash,
		),
	))
	registered, err := runtime.Service.RegisterDeployment(
		context.Background(),
		registration,
	)
	if err != nil {
		t.Fatalf("register %s lifecycle deployment: %v", suffix, err)
	}

	claimRequest := protocol.OperatorActionRequest{
		ProtocolVersion:          protocol.Version,
		RegistryScope:            registryScope,
		DeploymentID:             registered.DeploymentID,
		Timestamp:                now.Format(time.RFC3339),
		Nonce:                    "nonce_exit_lifecycle_claim_" + suffix,
		IdempotencyKey:           "exit_lifecycle_claim_" + suffix,
		Action:                   protocol.OperatorActionClaim,
		LegalName:                legalName,
		RegistrationNumber:       "EXIT-" + strings.ToUpper(suffix),
		Jurisdiction:             "Slovakia",
		RegisteredAddress:        "Lifecycle Street 1, Bratislava",
		Website:                  "https://" + suffix + ".exit.example.test",
		VerificationContactName:  "Lifecycle Reviewer",
		VerificationContactRole:  "Director",
		VerificationContactEmail: suffix + "@exit.example.test",
		AuthorityAttested:        true,
	}
	claimRequest.PayloadHash = protocol.Digest(protocol.OperatorClaimPayload(
		claimRequest.LegalName,
		claimRequest.RegistrationNumber,
		claimRequest.Jurisdiction,
		claimRequest.RegisteredAddress,
		claimRequest.Website,
		claimRequest.VerificationContactName,
		claimRequest.VerificationContactRole,
		claimRequest.VerificationContactEmail,
		claimRequest.AuthorityAttested,
		claimRequest.OperatorAvatarURL,
	))
	claimRequest.Signature = protocol.EncodeSignature(ed25519.Sign(
		privateKey,
		protocol.CanonicalRequest(
			"POST",
			protocol.OperatorActionPath,
			claimRequest.ProtocolVersion,
			claimRequest.RegistryScope,
			claimRequest.DeploymentID,
			claimRequest.Timestamp,
			claimRequest.Nonce,
			claimRequest.IdempotencyKey,
			claimRequest.PayloadHash,
		),
	))
	claim, err := runtime.Service.ApplyOperatorAction(
		context.Background(),
		claimRequest,
	)
	if err != nil {
		t.Fatalf("submit %s lifecycle claim: %v", suffix, err)
	}
	return exitLifecycleClaim{
		deploymentID:  registered.DeploymentID,
		claimActionID: claim.Receipt.ActionID,
		groupID:       claim.Receipt.GroupID,
		legalName:     legalName,
		privateKey:    privateKey,
	}
}

func approveExitLifecycleClaim(
	t *testing.T,
	runtime *app.Runtime,
	claim exitLifecycleClaim,
	suffix string,
) {
	t.Helper()
	result, err := runtime.Service.ApproveOperatorClaim(
		context.Background(),
		service.OperatorClaimApproval{
			DeploymentID:    claim.deploymentID,
			ClaimActionID:   claim.claimActionID,
			GroupID:         claim.groupID,
			LegalName:       claim.legalName,
			ReviewerID:      "exit-lifecycle-reviewer",
			ReviewReference: "review:exit-lifecycle-" + suffix,
			IdempotencyKey:  "approve-exit-lifecycle-" + suffix,
		},
	)
	if err != nil {
		t.Fatalf("approve %s lifecycle claim: %v", suffix, err)
	}
	if result.Duplicate ||
		result.Receipt.Decision != protocol.OperatorClaimReviewApproved {
		t.Fatalf("unexpected %s lifecycle approval: %+v", suffix, result)
	}
}

func submitExitLifecycleRevenue(
	t *testing.T,
	runtime *app.Runtime,
	registryScope string,
	claim exitLifecycleClaim,
	now time.Time,
	period string,
) {
	t.Helper()
	const capturedMinor = int64(200_000)
	currency := protocol.RevenueCurrency{
		CurrencyCode:             "EUR",
		FractionDigits:           2,
		CapturedMinor:            capturedMinor,
		RefundedMinor:            0,
		NetMinor:                 capturedMinor,
		CommissionBasisMinor:     capturedMinor,
		EstimatedCommissionMinor: protocol.RevenueCommissionMinor(capturedMinor),
		PaymentCount:             10,
	}
	request := protocol.RevenueBatchRequest{
		ProtocolVersion:           protocol.Version,
		RegistryScope:             registryScope,
		DeploymentID:              claim.deploymentID,
		Timestamp:                 now.Format(time.RFC3339),
		Nonce:                     "nonce_exit_lifecycle_revenue",
		IdempotencyKey:            "exit_lifecycle_revenue",
		Kind:                      protocol.RevenueKind,
		Period:                    period,
		Revision:                  1,
		RulesetVersion:            protocol.RevenueRulesetVersion,
		CommissionRateBasisPoints: protocol.RevenueCommissionBasisPoints,
		Currencies:                []protocol.RevenueCurrency{currency},
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
		claim.privateKey,
		protocol.CanonicalRequest(
			"POST",
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
	result, err := runtime.Service.SubmitRevenueBatch(
		context.Background(),
		request,
	)
	if err != nil {
		t.Fatalf("submit lifecycle revenue: %v", err)
	}
	if result.Duplicate || result.Receipt.LedgerIndex != 1 {
		t.Fatalf("unexpected lifecycle revenue receipt: %+v", result)
	}
}

func ownershipPrepareArgs(
	fixture exitLifecycleFixture,
	reviewID string,
	exitEventHash string,
	idempotencyKey string,
) []string {
	return []string{
		"--exit-review-id", reviewID,
		"--deployment-id", fixture.source.deploymentID,
		"--claim-action-id", fixture.source.claimActionID,
		"--source-group-id", fixture.source.groupID,
		"--target-group-id", fixture.target.groupID,
		"--exit-verification-event-hash", exitEventHash,
		"--requester-id", "transfer-request-system",
		"--reference", "request:ownership-transfer",
		"--evidence-hash", protocol.Digest([]byte("ownership transfer request evidence")),
		"--idempotency-key", idempotencyKey,
	}
}

func ownershipCompleteArgs(
	transferID string,
	effectiveDate string,
	idempotencyKey string,
) []string {
	return []string{
		"--transfer-id", transferID,
		"--effective-date", effectiveDate,
		"--manager-id", "registry-manager",
		"--reference", "decision:transfer-completed",
		"--evidence-hash", protocol.Digest([]byte("transfer completion evidence")),
		"--idempotency-key", idempotencyKey,
	}
}

func runExitLifecycleCLI[T any](
	t *testing.T,
	runner func([]string, io.Writer) error,
	args []string,
) T {
	t.Helper()
	var output bytes.Buffer
	if err := runner(args, &output); err != nil {
		t.Fatalf("run lifecycle CLI with %v: %v", args, err)
	}
	var result T
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf(
			"decode lifecycle CLI output for %v: %v; output=%s",
			args,
			err,
			output.String(),
		)
	}
	return result
}

func assertExitLifecycleCLIErrorContains(
	t *testing.T,
	runner func([]string, io.Writer) error,
	args []string,
	want string,
) {
	t.Helper()
	var output bytes.Buffer
	err := runner(args, &output)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf(
			"lifecycle CLI error for %v = %v, want substring %q; output=%s",
			args,
			err,
			want,
			output.String(),
		)
	}
}

func replaceExitLifecycleFlag(
	args []string,
	name string,
	value string,
) []string {
	replaced := append([]string(nil), args...)
	for index := 0; index+1 < len(replaced); index++ {
		if replaced[index] == name {
			replaced[index+1] = value
			return replaced
		}
	}
	panic("flag not found in lifecycle test arguments: " + name)
}

func assertFrozenExitBoundary(
	t *testing.T,
	record protocol.ExitReviewRecord,
) {
	t.Helper()
	if record.DeploymentCount != 1 ||
		len(record.Deployments) != 1 ||
		record.Deployments[0].MemberOrder != 0 ||
		record.Deployments[0].ClaimState !=
			protocol.OperatorClaimStateApproved ||
		record.Deployments[0].EligibilityState !=
			protocol.OperatorEligibilityActive ||
		record.MembershipHash !=
			protocol.ExitReviewMembershipHash(record.Deployments) ||
		record.SettlementBoundaryCount != 1 ||
		len(record.Settlements) != 1 ||
		record.Settlements[0].BoundaryOrder != 0 ||
		record.Settlements[0].CurrencyCode != "EUR" ||
		record.SettlementBoundaryHash !=
			protocol.ExitReviewSettlementBoundaryHash(record.Settlements) ||
		record.ThroughLedgerIndex != 2 ||
		record.ThroughSettlementLedgerIndex != 2 ||
		record.MerkleTreeSize != 2 {
		t.Fatalf("exit review did not pin the exact frozen boundary: %+v", record)
	}
}

func assertExitAllocationConservation(
	t *testing.T,
	record protocol.ExitAllocationRecord,
) {
	t.Helper()
	if record.SettlementSourceCount != 1 ||
		len(record.SettlementSources) != 1 ||
		record.CurrencyAllocationCount != 1 ||
		len(record.CurrencyAllocations) != 1 ||
		record.SettlementSources[0].CurrencyCode != "EUR" ||
		record.CurrencyAllocations[0].CurrencyCode != "EUR" ||
		record.CurrencyAllocations[0].DistributableMinor !=
			record.SettlementSources[0].DistributableMinor ||
		record.CurrencyAllocations[0].AllocatedMinor !=
			record.CurrencyAllocations[0].DistributableMinor ||
		record.CurrencyAllocations[0].BeneficiaryType !=
			record.BeneficiaryType ||
		record.CurrencyAllocations[0].BeneficiaryID != record.BeneficiaryID ||
		record.SettlementSourceHash !=
			protocol.ExitAllocationSettlementSourceHash(
				record.SettlementSources,
			) ||
		record.CurrencyAllocationHash !=
			protocol.ExitAllocationCurrencyHash(
				record.CurrencyAllocations,
			) {
		t.Fatalf(
			"final allocation did not conserve its frozen settlement rows: %+v",
			record,
		)
	}
}

func assertExitLifecycleLists(
	t *testing.T,
	reviewID string,
	transferID string,
	allocationID string,
) {
	t.Helper()
	reviews := runExitLifecycleCLI[protocol.ExitReviewPage](
		t,
		runListExitReviews,
		[]string{"--status", protocol.ExitReviewStatusEligible, "--limit", "10"},
	)
	if len(reviews.Items) != 1 ||
		reviews.Items[0].Record.ReviewID != reviewID {
		t.Fatalf("verified exit review list = %+v", reviews)
	}
	transfers := runExitLifecycleCLI[protocol.OwnershipTransferPage](
		t,
		runListOwnershipTransfers,
		[]string{
			"--status",
			protocol.OwnershipTransferStatusCompleted,
			"--limit",
			"10",
		},
	)
	if len(transfers.Items) != 1 ||
		transfers.Items[0].Record.TransferID != transferID {
		t.Fatalf("completed ownership transfer list = %+v", transfers)
	}
	allocations := runExitLifecycleCLI[protocol.ExitAllocationPage](
		t,
		runListExitAllocations,
		[]string{
			"--status",
			protocol.ExitAllocationStatusVerifiedFinal,
			"--decision-mode",
			protocol.ExitAllocationDecisionCompletedTransfer,
			"--limit",
			"10",
		},
	)
	if len(allocations.Items) != 1 ||
		allocations.Items[0].Record.AllocationID != allocationID {
		t.Fatalf("verified final allocation list = %+v", allocations)
	}
}

func assertExitLifecyclePersistenceAndVerification(
	t *testing.T,
	fixture exitLifecycleFixture,
	frozen protocol.ExitReviewMutationResult,
	verifiedExit protocol.ExitReviewMutationResult,
	prepared protocol.OwnershipTransferMutationResult,
	completed protocol.OwnershipTransferMutationResult,
	createdAllocation protocol.ExitAllocationMutationResult,
	verifiedAllocation protocol.ExitAllocationMutationResult,
) {
	t.Helper()
	ctx := context.Background()
	runtime, err := app.BootstrapExisting(
		ctx,
		fixture.config,
		app.Options{},
	)
	if err != nil {
		t.Fatalf("reopen completed lifecycle state: %v", err)
	}
	defer runtime.Close()

	storedReview, err := runtime.Store.ExitReview(
		ctx,
		frozen.Review.Record.ReviewID,
	)
	if err != nil ||
		storedReview.Status != protocol.ExitReviewStatusEligible ||
		storedReview.Record.RecordHash != frozen.Review.Record.RecordHash ||
		storedReview.LatestEventHash != verifiedExit.Event.EventHash {
		t.Fatalf(
			"persisted exit review = %+v, error=%v",
			storedReview,
			err,
		)
	}
	storedTransfer, err := runtime.Store.OwnershipTransfer(
		ctx,
		prepared.Transfer.Record.TransferID,
	)
	if err != nil ||
		storedTransfer.Status != protocol.OwnershipTransferStatusCompleted ||
		storedTransfer.LatestEventHash != completed.Event.EventHash ||
		storedTransfer.Membership == nil ||
		storedTransfer.Membership.TargetGroupID != fixture.target.groupID {
		t.Fatalf(
			"persisted ownership transfer = %+v, error=%v",
			storedTransfer,
			err,
		)
	}
	storedAllocation, err := runtime.Store.ExitAllocation(
		ctx,
		createdAllocation.Allocation.Record.AllocationID,
	)
	if err != nil ||
		storedAllocation.Status !=
			protocol.ExitAllocationStatusVerifiedFinal ||
		storedAllocation.LatestEventHash != verifiedAllocation.Event.EventHash ||
		storedAllocation.Record.RecordHash !=
			createdAllocation.Allocation.Record.RecordHash {
		t.Fatalf(
			"persisted final allocation = %+v, error=%v",
			storedAllocation,
			err,
		)
	}

	for name, verify := range map[string]func() error{
		"exit reviews": func() error {
			return runtime.Store.VerifyExitReviews(
				ctx,
				runtime.SigningKey.PublicKey(),
				runtime.SigningKey.KeyID(),
				fixture.config.RegistryScope,
			)
		},
		"ownership transfers": func() error {
			return runtime.Store.VerifyOwnershipTransfers(
				ctx,
				runtime.SigningKey.PublicKey(),
				runtime.SigningKey.KeyID(),
				fixture.config.RegistryScope,
			)
		},
		"final allocations": func() error {
			return runtime.Store.VerifyExitAllocations(
				ctx,
				runtime.SigningKey.PublicKey(),
				runtime.SigningKey.KeyID(),
				fixture.config.RegistryScope,
			)
		},
	} {
		if err := verify(); err != nil {
			t.Fatalf("verify persisted %s: %v", name, err)
		}
	}
	assertExitLifecycleSignature(
		t,
		runtime.SigningKey.PublicKey(),
		protocol.ExitReviewEventReceiptMessage(verifiedExit.Event),
		verifiedExit.Event.Signature,
	)
	assertExitLifecycleSignature(
		t,
		runtime.SigningKey.PublicKey(),
		protocol.OwnershipTransferEventReceiptMessage(completed.Event),
		completed.Event.Signature,
	)
	assertExitLifecycleSignature(
		t,
		runtime.SigningKey.PublicKey(),
		protocol.ExitAllocationEventReceiptMessage(verifiedAllocation.Event),
		verifiedAllocation.Event.Signature,
	)
	if err := runtime.Service.VerifyState(ctx); err != nil {
		t.Fatalf("verify complete persisted lifecycle state: %v", err)
	}
}

func assertExitLifecycleSignature(
	t *testing.T,
	publicKey ed25519.PublicKey,
	message []byte,
	encodedSignature string,
) {
	t.Helper()
	signature, err := protocol.ParseSignature(encodedSignature)
	if err != nil || !protocol.Verify(publicKey, message, signature) {
		t.Fatalf(
			"lifecycle event signature verification failed: error=%v",
			err,
		)
	}
}

func assertExitAllocationTamperingFailsClosed(
	t *testing.T,
	databasePath string,
	allocationID string,
) {
	t.Helper()
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatalf("open lifecycle database for corruption test: %v", err)
	}
	if _, err := database.Exec(`
		UPDATE exit_allocation_currency_allocations
		SET distributable_minor = distributable_minor + 1,
		    allocated_minor = allocated_minor + 1
		WHERE allocation_id = ?`,
		allocationID,
	); err == nil {
		database.Close()
		t.Fatal("append-only trigger allowed final allocation currency mutation")
	}
	if _, err := database.Exec(
		"DROP TRIGGER exit_allocation_currency_allocations_no_update",
	); err != nil {
		database.Close()
		t.Fatalf("drop allocation update trigger for corruption test: %v", err)
	}
	result, err := database.Exec(`
		UPDATE exit_allocation_currency_allocations
		SET distributable_minor = distributable_minor + 1,
		    allocated_minor = allocated_minor + 1
		WHERE allocation_id = ?`,
		allocationID,
	)
	if err != nil {
		database.Close()
		t.Fatalf("corrupt final allocation currency row: %v", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		database.Close()
		t.Fatalf(
			"corrupted allocation row count = %d, error=%v, want 1",
			changed,
			err,
		)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close corrupted lifecycle database: %v", err)
	}

	assertExitLifecycleCLIErrorContains(
		t,
		runShowExitAllocation,
		[]string{"--allocation-id", allocationID},
		"final exit allocation",
	)
}
