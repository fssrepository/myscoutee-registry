package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/fssrepository/myscoutee-registry/internal/globalidentity"
	"github.com/fssrepository/myscoutee-registry/internal/identity"
	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

var (
	periodPattern       = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])$`)
	deploymentIDPattern = regexp.MustCompile(`^dep_[0-9a-f]{32}$`)
	batchIDPattern      = regexp.MustCompile(`^batch_[0-9a-f]{32}$`)
)

type Options struct {
	TimestampSkew                  time.Duration
	RegistryScope                  string
	ValuationMultiplierBasisPoints int64
	GlobalIdentityKeys             *globalidentity.KeyRing
	Now                            func() time.Time
	NewID                          func(prefix string) (string, error)
	Logger                         *slog.Logger
}

type Service struct {
	store                          store.Store
	signingKey                     *identity.SigningKey
	timestampSkew                  time.Duration
	registryScope                  string
	valuationMultiplierBasisPoints int64
	globalIdentityKeys             *globalidentity.KeyRing
	now                            func() time.Time
	newID                          func(prefix string) (string, error)
	logger                         *slog.Logger

	integrityMutex             sync.Mutex
	trustedOperationalRevision store.OperationalRevision
	operationalRevisionTrusted bool
	integrityFailure           error
	fullVerificationRuns       atomic.Uint64
}

func New(registryStore store.Store, signingKey *identity.SigningKey, options Options) *Service {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	newID := options.NewID
	if newID == nil {
		newID = randomID
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	registryScope := options.RegistryScope
	valuationMultiplier := options.ValuationMultiplierBasisPoints
	if valuationMultiplier <= 0 {
		valuationMultiplier =
			protocol.SettlementDefaultValuationMultiplierBasisPoints
	}
	return &Service{
		store:                          registryStore,
		signingKey:                     signingKey,
		timestampSkew:                  options.TimestampSkew,
		registryScope:                  registryScope,
		valuationMultiplierBasisPoints: valuationMultiplier,
		globalIdentityKeys:             options.GlobalIdentityKeys,
		now:                            now,
		newID:                          newID,
		logger:                         logger,
	}
}

func (registry *Service) RegisterDeployment(
	ctx context.Context,
	request protocol.RegistrationRequest,
) (protocol.RegistrationResponse, error) {
	if request.ProtocolVersion != protocol.Version {
		return protocol.RegistrationResponse{}, requestError("unsupported_protocol", "protocol_version must be \"1\"")
	}
	if !protocol.IsRegistryScope(request.RegistryScope) {
		return protocol.RegistrationResponse{}, requestError("invalid_request", "registry_scope is malformed")
	}
	if err := validateToken("nonce", request.Nonce); err != nil {
		return protocol.RegistrationResponse{}, err
	}
	if err := validateToken("idempotency_key", request.IdempotencyKey); err != nil {
		return protocol.RegistrationResponse{}, err
	}
	if !protocol.IsDigest(request.PayloadHash) {
		return protocol.RegistrationResponse{}, requestError("invalid_request", "payload_hash must be a lowercase sha256 digest")
	}
	requestTime, err := registry.validateTimestamp(request.Timestamp)
	if err != nil {
		return protocol.RegistrationResponse{}, err
	}
	publicKey, publicKeyDER, err := protocol.ParsePublicKey(request.PublicKey)
	if err != nil {
		return protocol.RegistrationResponse{}, requestError("invalid_request", "public_key must be canonical padded base64 Ed25519 SPKI DER")
	}
	fingerprint := protocol.PublicKeyFingerprint(publicKeyDER)
	signature, err := protocol.ParseSignature(request.Signature)
	if err != nil {
		return protocol.RegistrationResponse{}, requestError("invalid_signature", "signature must be canonical padded base64 Ed25519")
	}
	signingMessage := protocol.CanonicalRequest(
		"POST",
		protocol.RegistrationPath,
		request.ProtocolVersion,
		request.RegistryScope,
		fingerprint,
		request.Timestamp,
		request.Nonce,
		request.IdempotencyKey,
		request.PayloadHash,
	)
	if !protocol.Verify(publicKey, signingMessage, signature) {
		return protocol.RegistrationResponse{}, requestError("invalid_signature", "deployment registration signature verification failed")
	}
	if request.RegistryScope != registry.registryScope {
		return protocol.RegistrationResponse{}, requestError(
			"registry_scope_mismatch",
			"request is addressed to a different sovereign registry scope",
		)
	}

	if request.KeyAlgorithm != protocol.KeyAlgorithmEd25519 {
		return protocol.RegistrationResponse{}, requestError("invalid_request", "key_algorithm must be Ed25519")
	}
	if err := validateCanonicalText("software_version", request.SoftwareVersion, 1, 128); err != nil {
		return protocol.RegistrationResponse{}, err
	}
	expectedPayloadHash := protocol.Digest(protocol.RegistrationPayload(
		request.KeyAlgorithm,
		request.PublicKey,
		request.SoftwareVersion,
	))
	if request.PayloadHash != expectedPayloadHash {
		return protocol.RegistrationResponse{}, requestError("invalid_payload_hash", "registration payload_hash does not match the canonical payload")
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		registry.logger.Error("refusing deployment registration while registry integrity verification fails", "error", err)
		return protocol.RegistrationResponse{}, requestError(
			"registry_integrity_unavailable",
			"registry integrity verification failed; new append-only records are temporarily unavailable",
		)
	}

	deploymentID, err := registry.newID("dep_")
	if err != nil {
		return protocol.RegistrationResponse{}, fmt.Errorf("generate deployment ID: %w", err)
	}
	acceptedAt := registry.canonicalNow().Format(time.RFC3339)
	receiptMessage := protocol.RegistrationReceipt(
		protocol.Version,
		registry.registryScope,
		deploymentID,
		fingerprint,
		acceptedAt,
		registry.signingKey.KeyID(),
	)
	deployment, duplicate, err := registry.store.RegisterDeployment(ctx, store.RegistrationInput{
		SignerFingerprint:         fingerprint,
		Nonce:                     request.Nonce,
		IdempotencyKey:            request.IdempotencyKey,
		PayloadHash:               request.PayloadHash,
		RequestHash:               protocol.Digest(signingMessage),
		RequestTimestamp:          request.Timestamp,
		RequestSignature:          signature,
		PublicKeyDER:              publicKeyDER,
		KeyAlgorithm:              request.KeyAlgorithm,
		SoftwareVersion:           request.SoftwareVersion,
		CandidateDeploymentID:     deploymentID,
		CandidateRegisteredAt:     acceptedAt,
		CandidateReceiptSignature: registry.signingKey.Sign(receiptMessage),
	})
	if err != nil {
		return protocol.RegistrationResponse{}, mapStoreError(err)
	}
	_ = requestTime // Parsed before all idempotency/replay checks by protocol requirement.
	return protocol.RegistrationResponse{
		ProtocolVersion:      protocol.Version,
		RegistryScope:        registry.registryScope,
		DeploymentID:         deployment.DeploymentID,
		RegisteredAt:         deployment.RegisteredAt,
		PublicKeyFingerprint: deployment.PublicKeyFingerprint,
		RegistryKeyID:        registry.signingKey.KeyID(),
		RegistryPublicKey:    registry.signingKey.EncodedPublicKey(),
		ReceiptSignature:     protocol.EncodeSignature(deployment.ReceiptSignature),
		Duplicate:            duplicate,
	}, nil
}

func (registry *Service) SubmitBatch(
	ctx context.Context,
	request protocol.BatchRequest,
) (protocol.BatchResponse, error) {
	if request.ProtocolVersion != protocol.Version {
		return protocol.BatchResponse{}, requestError("unsupported_protocol", "protocol_version must be \"1\"")
	}
	if !protocol.IsRegistryScope(request.RegistryScope) {
		return protocol.BatchResponse{}, requestError("invalid_request", "registry_scope is malformed")
	}
	if !deploymentIDPattern.MatchString(request.DeploymentID) {
		return protocol.BatchResponse{}, requestError("invalid_request", "deployment_id is malformed")
	}
	if err := validateToken("nonce", request.Nonce); err != nil {
		return protocol.BatchResponse{}, err
	}
	if err := validateToken("idempotency_key", request.IdempotencyKey); err != nil {
		return protocol.BatchResponse{}, err
	}
	if !protocol.IsDigest(request.PayloadHash) {
		return protocol.BatchResponse{}, requestError("invalid_request", "payload_hash must be a lowercase sha256 digest")
	}
	if _, err := registry.validateTimestamp(request.Timestamp); err != nil {
		return protocol.BatchResponse{}, err
	}
	deployment, err := registry.store.Deployment(ctx, request.DeploymentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.BatchResponse{}, requestError("deployment_not_found", "deployment is not registered")
		}
		return protocol.BatchResponse{}, err
	}
	deploymentPublicKey, err := parseStoredPublicKey(deployment.PublicKeyDER)
	if err != nil {
		return protocol.BatchResponse{}, fmt.Errorf("%w: %v", store.ErrInconsistentState, err)
	}
	signature, err := protocol.ParseSignature(request.Signature)
	if err != nil {
		return protocol.BatchResponse{}, requestError("invalid_signature", "signature must be canonical padded base64 Ed25519")
	}
	signingMessage := protocol.CanonicalRequest(
		"POST",
		protocol.BatchPath,
		request.ProtocolVersion,
		request.RegistryScope,
		request.DeploymentID,
		request.Timestamp,
		request.Nonce,
		request.IdempotencyKey,
		request.PayloadHash,
	)
	if !protocol.Verify(deploymentPublicKey, signingMessage, signature) {
		return protocol.BatchResponse{}, requestError("invalid_signature", "MAU batch signature verification failed")
	}
	if request.RegistryScope != registry.registryScope {
		return protocol.BatchResponse{}, requestError(
			"registry_scope_mismatch",
			"request is addressed to a different sovereign registry scope",
		)
	}

	if !periodPattern.MatchString(request.Period) {
		return protocol.BatchResponse{}, requestError("invalid_request", "period must use YYYY-MM")
	}
	if !protocol.IsDigest(request.CommitmentHash) {
		return protocol.BatchResponse{}, requestError("invalid_request", "commitment_hash must be a lowercase sha256 digest")
	}
	var expectedPayloadHash string
	switch request.Kind {
	case protocol.InstallationTestKind:
		if request.RulesetVersion != protocol.InstallationTestRuleset ||
			request.QualifiedMAUCount != 0 ||
			request.Revision != 0 ||
			request.SupersedesBatchID != "" {
			return protocol.BatchResponse{}, requestError(
				"invalid_installation_test",
				"installation tests require installation-test-v1, zero count, revision 0, and no superseded batch",
			)
		}
		expectedCommitment := protocol.Digest(protocol.InstallationTestCommitment(
			request.DeploymentID,
			request.IdempotencyKey,
		))
		if request.CommitmentHash != expectedCommitment {
			return protocol.BatchResponse{}, requestError("invalid_commitment", "installation-test commitment_hash is invalid")
		}
		expectedPayloadHash = protocol.Digest(protocol.BatchPayload(
			request.Kind,
			request.Period,
			request.RulesetVersion,
			request.QualifiedMAUCount,
			request.CommitmentHash,
		))
	case protocol.QualifiedMAUKind:
		if request.RulesetVersion != protocol.QualifiedMAURuleset ||
			request.QualifiedMAUCount < 0 ||
			request.Revision < 1 ||
			(request.Revision == 1 && request.SupersedesBatchID != "") ||
			(request.Revision > 1 && !batchIDPattern.MatchString(request.SupersedesBatchID)) {
			return protocol.BatchResponse{}, requestError(
				"invalid_qmau_snapshot",
				"monthly QMAU requires qmau-v1, a non-negative count, and a linear revision/supersedes pair",
			)
		}
		expectedPayloadHash = protocol.Digest(protocol.QualifiedMAUPayload(
			request.Period,
			request.RulesetVersion,
			request.QualifiedMAUCount,
			request.CommitmentHash,
			request.Revision,
			request.SupersedesBatchID,
		))
	default:
		return protocol.BatchResponse{}, requestError(
			"invalid_batch_kind",
			"kind must be installation-test or monthly-qmau",
		)
	}
	if request.PayloadHash != expectedPayloadHash {
		return protocol.BatchResponse{}, requestError("invalid_payload_hash", "MAU batch payload_hash does not match the canonical payload")
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		registry.logger.Error("refusing MAU batch while registry integrity verification fails", "error", err)
		return protocol.BatchResponse{}, requestError(
			"registry_integrity_unavailable",
			"registry integrity verification failed; new ledger writes are temporarily unavailable",
		)
	}

	batchID, err := registry.newID("batch_")
	if err != nil {
		return protocol.BatchResponse{}, fmt.Errorf("generate batch ID: %w", err)
	}
	acceptedAtTime := registry.canonicalNow()
	acceptedAt := acceptedAtTime.Format(time.RFC3339)
	checkpointDate := acceptedAtTime.Format("2006-01-02")
	record, duplicate, err := registry.store.AcceptInstallationBatch(
		ctx,
		store.BatchInput{
			RegistryScope:       registry.registryScope,
			Signer:              request.DeploymentID,
			Nonce:               request.Nonce,
			IdempotencyKey:      request.IdempotencyKey,
			PayloadHash:         request.PayloadHash,
			RequestHash:         protocol.Digest(signingMessage),
			DeploymentID:        request.DeploymentID,
			RequestTimestamp:    request.Timestamp,
			DeploymentSignature: signature,
			CandidateBatchID:    batchID,
			Kind:                request.Kind,
			Period:              request.Period,
			RulesetVersion:      request.RulesetVersion,
			QualifiedMAUCount:   request.QualifiedMAUCount,
			CommitmentHash:      request.CommitmentHash,
			Revision:            request.Revision,
			SupersedesBatchID:   request.SupersedesBatchID,
			AcceptedAt:          acceptedAt,
			CheckpointDate:      checkpointDate,
		},
		func(entry protocol.LedgerEntry, date string) ([]byte, error) {
			if request.Kind == protocol.QualifiedMAUKind {
				return registry.signingKey.Sign(protocol.QualifiedMAUReceiptMessage(
					protocol.Version,
					registry.registryScope,
					entry.BatchID,
					entry.DeploymentID,
					entry.LedgerIndex,
					entry.EntryHash,
					entry.PreviousEntryHash,
					entry.BatchHash,
					entry.Period,
					entry.RulesetVersion,
					entry.QualifiedMAUCount,
					request.CommitmentHash,
					request.Revision,
					request.SupersedesBatchID,
					entry.AcceptedAt,
					date,
					registry.signingKey.KeyID(),
				)), nil
			}
			return registry.signingKey.Sign(protocol.MAUReceiptMessage(
				protocol.Version,
				registry.registryScope,
				entry.BatchID,
				entry.DeploymentID,
				entry.LedgerIndex,
				entry.EntryHash,
				entry.PreviousEntryHash,
				entry.BatchHash,
				entry.Kind,
				entry.Period,
				entry.RulesetVersion,
				entry.QualifiedMAUCount,
				entry.AcceptedAt,
				date,
				registry.signingKey.KeyID(),
			)), nil
		},
	)
	if err != nil {
		return protocol.BatchResponse{}, mapStoreError(err)
	}
	return registry.batchResponse(record, duplicate), nil
}

func (registry *Service) Receipt(ctx context.Context, batchID string) (protocol.BatchResponse, error) {
	if !batchIDPattern.MatchString(batchID) {
		return protocol.BatchResponse{}, requestError("invalid_request", "batch_id is malformed")
	}
	record, err := registry.store.BatchReceipt(ctx, batchID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.BatchResponse{}, requestError("receipt_not_found", "batch receipt was not found")
		}
		return protocol.BatchResponse{}, err
	}
	return registry.batchResponse(record, true), nil
}

func (registry *Service) Identity(ctx context.Context) (protocol.RegistryIdentity, error) {
	if err := registry.verifyOperationalState(ctx); err != nil {
		registry.logger.Error("refusing registry identity preflight while integrity verification fails", "error", err)
		return protocol.RegistryIdentity{}, requestError(
			"registry_integrity_unavailable",
			"registry integrity verification failed; identity preflight is temporarily unavailable",
		)
	}
	response := protocol.RegistryIdentity{
		ProtocolVersion:   protocol.Version,
		RegistryScope:     registry.registryScope,
		RegistryKeyID:     registry.signingKey.KeyID(),
		RegistryPublicKey: registry.signingKey.EncodedPublicKey(),
	}
	response.Signature = protocol.EncodeSignature(registry.signingKey.Sign(
		protocol.RegistryIdentityMessage(
			response.ProtocolVersion,
			response.RegistryScope,
			response.RegistryKeyID,
			response.RegistryPublicKey,
		),
	))
	return response, nil
}

func (registry *Service) Checkpoint(ctx context.Context, date string) (protocol.Checkpoint, error) {
	checkpointDay, err := time.Parse("2006-01-02", date)
	if err != nil || checkpointDay.Format("2006-01-02") != date {
		return protocol.Checkpoint{}, requestError("invalid_request", "checkpoint date must use YYYY-MM-DD")
	}
	if !checkpointDay.Before(dayStart(registry.canonicalNow())) {
		return protocol.Checkpoint{}, requestError("checkpoint_not_finalized", "only completed UTC days have immutable checkpoints")
	}
	if err := registry.FinalizeCompletedCheckpoints(ctx); err != nil {
		return protocol.Checkpoint{}, err
	}
	record, err := registry.store.Checkpoint(ctx, date)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.Checkpoint{}, requestError("checkpoint_not_found", "checkpoint is outside this registry's finalized history")
		}
		return protocol.Checkpoint{}, err
	}
	return registry.checkpointResponse(record), nil
}

func (registry *Service) FinalizeCompletedCheckpoints(ctx context.Context) error {
	if err := registry.VerifyState(ctx); err != nil {
		return fmt.Errorf("refuse to checkpoint invalid registry state: %w", err)
	}
	created, err := registry.store.FinalizeCompletedCheckpoints(
		ctx,
		registry.canonicalNow(),
		registry.registryScope,
		registry.signingKey.KeyID(),
		func(checkpoint protocol.Checkpoint) ([]byte, error) {
			return registry.signingKey.Sign(protocol.CheckpointMessage(checkpoint)), nil
		},
	)
	if err != nil {
		return err
	}
	if len(created) > 0 {
		registry.logger.Info(
			"finalized UTC registry checkpoints",
			"count", len(created),
			"last_date", created[len(created)-1].Checkpoint.CheckpointDate,
		)
	}
	return nil
}

func (registry *Service) VerifyState(ctx context.Context) error {
	registry.integrityMutex.Lock()
	defer registry.integrityMutex.Unlock()
	registry.fullVerificationRuns.Add(1)

	before, err := registry.store.OperationalRevision(ctx)
	if err != nil {
		registry.integrityFailure = err
		return err
	}
	if err := registry.verifyCompleteOperationalState(ctx); err != nil {
		registry.integrityFailure = err
		return err
	}
	if err := registry.store.VerifyMerkleTree(ctx); err != nil {
		registry.integrityFailure = fmt.Errorf("verify ledger Merkle tree: %w", err)
		return registry.integrityFailure
	}
	after, err := registry.store.OperationalRevision(ctx)
	if err != nil {
		registry.integrityFailure = err
		return err
	}
	if before != after {
		registry.integrityFailure = fmt.Errorf(
			"%w: registry data changed through another connection during full verification",
			store.ErrInconsistentState,
		)
		return registry.integrityFailure
	}
	registry.trustedOperationalRevision = after
	registry.operationalRevisionTrusted = true
	registry.integrityFailure = nil
	return nil
}

// verifyOperationalState keeps ordinary HTTP work on a bounded fast path. A
// complete bootstrap audit establishes the immutable prefix. While SQLite's
// connection-local data_version is unchanged, all writes came through this
// process's transactionally checked Store methods. When a second connection
// (normally the local registry CLI) commits, the cryptographic chain heads,
// source/projection boundary rows, newly completed Merkle frontier, and the
// complete low-volume administrator case and exit-review chains are checked
// before the new revision becomes trusted. Those two verification paths
// deliberately remain full replays in v1 because their direct query rows
// otherwise have no safe bounded trust boundary.
func (registry *Service) verifyOperationalState(ctx context.Context) error {
	registry.integrityMutex.Lock()
	defer registry.integrityMutex.Unlock()

	if registry.integrityFailure != nil {
		return fmt.Errorf(
			"registry remains fail-closed after a failed complete integrity audit: %w",
			registry.integrityFailure,
		)
	}
	before, err := registry.store.OperationalRevision(ctx)
	if err != nil {
		return err
	}
	if registry.operationalRevisionTrusted &&
		before == registry.trustedOperationalRevision {
		return nil
	}
	if err := registry.store.VerifyOperationalBoundary(
		ctx,
		registry.signingKey.PublicKey(),
		registry.signingKey.KeyID(),
		registry.registryScope,
	); err != nil {
		return fmt.Errorf("verify operational trust boundary: %w", err)
	}
	if err := registry.store.VerifyRegistryCases(
		ctx,
		registry.signingKey.PublicKey(),
		registry.signingKey.KeyID(),
		registry.registryScope,
	); err != nil {
		return fmt.Errorf("verify registry case boundary: %w", err)
	}
	if err := registry.store.VerifyExitReviews(
		ctx,
		registry.signingKey.PublicKey(),
		registry.signingKey.KeyID(),
		registry.registryScope,
	); err != nil {
		return fmt.Errorf("verify exit review boundary: %w", err)
	}
	if err := registry.store.VerifyOwnershipTransfers(
		ctx,
		registry.signingKey.PublicKey(),
		registry.signingKey.KeyID(),
		registry.registryScope,
	); err != nil {
		return fmt.Errorf("verify ownership transfer boundary: %w", err)
	}
	after, err := registry.store.OperationalRevision(ctx)
	if err != nil {
		return err
	}
	if before != after {
		return fmt.Errorf(
			"%w: registry data changed through another connection during boundary verification",
			store.ErrInconsistentState,
		)
	}
	registry.trustedOperationalRevision = after
	registry.operationalRevisionTrusted = true
	return nil
}

func (registry *Service) verifyCompleteOperationalState(ctx context.Context) error {
	if err := registry.store.VerifyLedger(ctx); err != nil {
		return fmt.Errorf("verify ledger: %w", err)
	}
	if err := registry.store.VerifyLedgerWeightRows(ctx); err != nil {
		return fmt.Errorf("verify ledger weight rows: %w", err)
	}
	if err := registry.store.VerifyRecords(
		ctx,
		registry.signingKey.PublicKey(),
		registry.signingKey.KeyID(),
		registry.registryScope,
	); err != nil {
		return fmt.Errorf("verify registry records: %w", err)
	}
	if err := registry.store.VerifySettlements(
		ctx,
		registry.signingKey.PublicKey(),
		registry.signingKey.KeyID(),
		registry.registryScope,
	); err != nil {
		return fmt.Errorf("verify settlements: %w", err)
	}
	if err := registry.store.VerifyCheckpoints(
		ctx,
		registry.signingKey.PublicKey(),
		registry.signingKey.KeyID(),
		registry.registryScope,
	); err != nil {
		return fmt.Errorf("verify checkpoints: %w", err)
	}
	if err := registry.store.VerifyOperatorNetwork(
		ctx,
		registry.signingKey.PublicKey(),
		registry.signingKey.KeyID(),
		registry.registryScope,
	); err != nil {
		return fmt.Errorf("verify operator audit network: %w", err)
	}
	if err := registry.store.VerifyAnnouncements(
		ctx,
		registry.signingKey.PublicKey(),
		registry.signingKey.KeyID(),
		registry.registryScope,
	); err != nil {
		return fmt.Errorf("verify announcements: %w", err)
	}
	if err := registry.store.VerifyRegistryCases(
		ctx,
		registry.signingKey.PublicKey(),
		registry.signingKey.KeyID(),
		registry.registryScope,
	); err != nil {
		return fmt.Errorf("verify registry cases: %w", err)
	}
	if err := registry.store.VerifyExitReviews(
		ctx,
		registry.signingKey.PublicKey(),
		registry.signingKey.KeyID(),
		registry.registryScope,
	); err != nil {
		return fmt.Errorf("verify exit reviews: %w", err)
	}
	if err := registry.store.VerifyOwnershipTransfers(
		ctx,
		registry.signingKey.PublicKey(),
		registry.signingKey.KeyID(),
		registry.registryScope,
	); err != nil {
		return fmt.Errorf("verify ownership transfers: %w", err)
	}
	if err := registry.store.VerifyGlobalIdentities(
		ctx,
		registry.signingKey.PublicKey(),
		registry.signingKey.KeyID(),
		registry.registryScope,
	); err != nil {
		return fmt.Errorf("verify global identity dedup state: %w", err)
	}
	return nil
}

// FullVerificationRuns exposes an integrity diagnostic used by qualification
// tests and operators. Ordinary request handling must not increase it; startup,
// health/readiness, checkpoint finalization, and explicit verification do.
func (registry *Service) FullVerificationRuns() uint64 {
	return registry.fullVerificationRuns.Load()
}

func (registry *Service) Health(ctx context.Context) (store.LedgerHead, error) {
	if err := registry.store.Ping(ctx); err != nil {
		return store.LedgerHead{}, err
	}
	if err := registry.VerifyState(ctx); err != nil {
		return store.LedgerHead{}, err
	}
	return registry.store.LedgerHead(ctx)
}

func (registry *Service) RunCheckpointWorker(ctx context.Context, interval time.Duration) {
	if err := registry.FinalizeCompletedCheckpoints(ctx); err != nil {
		registry.logger.Error("checkpoint finalization failed", "error", err)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := registry.FinalizeCompletedCheckpoints(ctx); err != nil {
				registry.logger.Error("checkpoint finalization failed", "error", err)
			}
		}
	}
}

func (registry *Service) RegistryKeyID() string {
	return registry.signingKey.KeyID()
}

func (registry *Service) RegistryScope() string {
	return registry.registryScope
}

func (registry *Service) batchResponse(record store.BatchRecord, duplicate bool) protocol.BatchResponse {
	entry := record.LedgerEntry
	response := protocol.BatchResponse{
		ProtocolVersion: protocol.Version,
		RegistryScope:   registry.registryScope,
		BatchID:         record.BatchID,
		DeploymentID:    record.DeploymentID,
		IdempotencyKey:  record.IdempotencyKey,
		Duplicate:       duplicate,
		Receipt: protocol.MAUReceipt{
			LedgerIndex:       entry.LedgerIndex,
			EntryHash:         entry.EntryHash,
			PreviousEntryHash: entry.PreviousEntryHash,
			BatchHash:         entry.BatchHash,
			Kind:              record.Kind,
			Period:            record.Period,
			RulesetVersion:    record.RulesetVersion,
			QualifiedMAUCount: record.QualifiedMAUCount,
			AcceptedAt:        record.AcceptedAt,
			CheckpointDate:    record.AcceptedAt[:len("2006-01-02")],
			RegistryScope:     registry.registryScope,
			RegistryKeyID:     registry.signingKey.KeyID(),
			RegistryPublicKey: registry.signingKey.EncodedPublicKey(),
			Signature:         protocol.EncodeSignature(record.ReceiptSignature),
		},
	}
	if record.Kind == protocol.QualifiedMAUKind {
		response.Receipt.CommitmentHash = record.CommitmentHash
		response.Receipt.Revision = record.Revision
		response.Receipt.SupersedesBatchID = record.SupersedesBatchID
	}
	return response
}

func (registry *Service) checkpointResponse(record store.CheckpointRecord) protocol.Checkpoint {
	checkpoint := record.Checkpoint
	checkpoint.RegistryPublicKey = registry.signingKey.EncodedPublicKey()
	checkpoint.Signature = protocol.EncodeSignature(record.Signature)
	return checkpoint
}

func (registry *Service) validateTimestamp(value string) (time.Time, error) {
	if protocol.HasCanonicalLineBreak(value) {
		return time.Time{}, requestError("invalid_timestamp", "timestamp must not contain a line break")
	}
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, requestError("invalid_timestamp", "timestamp must be an RFC 3339 UTC timestamp ending in Z")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, requestError("invalid_timestamp", "timestamp must be an RFC 3339 UTC timestamp")
	}
	now := registry.now().UTC()
	if parsed.Before(now.Add(-registry.timestampSkew)) || parsed.After(now.Add(registry.timestampSkew)) {
		return time.Time{}, requestError("timestamp_out_of_range", "timestamp is outside the accepted clock-skew window")
	}
	return parsed, nil
}

func (registry *Service) canonicalNow() time.Time {
	return registry.now().UTC().Truncate(time.Second)
}

func validateToken(name, value string) error {
	if len(value) < 8 || len(value) > 128 {
		return requestError("invalid_request", name+" must be between 8 and 128 printable ASCII characters")
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return requestError("invalid_request", name+" must be a printable ASCII token without spaces")
		}
	}
	return nil
}

func validateCanonicalText(name, value string, minimum, maximum int) error {
	if !utf8.ValidString(value) || len(value) < minimum || len(value) > maximum || protocol.HasCanonicalLineBreak(value) {
		return requestError("invalid_request", name+" is not a valid canonical value")
	}
	return nil
}

func parseStoredPublicKey(der []byte) (ed25519.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("stored deployment key is not Ed25519")
	}
	return publicKey, nil
}

func mapStoreError(err error) error {
	switch {
	case errors.Is(err, store.ErrIdempotencyConflict):
		return requestError("idempotency_conflict", "idempotency_key was already accepted with a different payload_hash")
	case errors.Is(err, store.ErrReplayConflict):
		return requestError("replay_conflict", "nonce was already accepted for a different request")
	case errors.Is(err, store.ErrAcceptedAtFinalized):
		return requestError(
			"registry_clock_before_checkpoint",
			"registry clock is before the latest immutable checkpoint cutoff",
		)
	case errors.Is(err, store.ErrAcceptedAtBeforeHead):
		return requestError(
			"registry_clock_before_ledger_head",
			"registry clock is before the current immutable ledger head",
		)
	case errors.Is(err, store.ErrAcceptedAtBeforeIdentity):
		return requestError(
			"registry_clock_before_identity",
			"registry clock is before this registry identity's creation time",
		)
	case errors.Is(err, store.ErrQualifiedMAURevisionConflict):
		return requestError(
			"qmau_revision_conflict",
			"revision must increment and supersede the current active QMAU snapshot for this deployment and period",
		)
	case errors.Is(err, store.ErrDeploymentInactive):
		return requestError(
			"deployment_inactive",
			"deployment is not active",
		)
	case errors.Is(err, store.ErrGlobalIdentityRateLimited):
		return requestError(
			"global_identity_rate_limited",
			"global identity evaluation rate limit was exceeded",
		)
	case errors.Is(err, store.ErrGlobalIdentityKeyMismatch):
		return requestError(
			"global_identity_key_unavailable",
			"global identity VOPRF key metadata does not match",
		)
	case errors.Is(err, store.ErrGlobalIdentityLinkConflict):
		return requestError(
			"global_identity_link_conflict",
			"global identity link action conflicts with current state",
		)
	case errors.Is(err, store.ErrGlobalIdentityPresenceConflict):
		return requestError(
			"global_identity_presence_conflict",
			"global identity presence revision or counts conflict with current state",
		)
	default:
		return err
	}
}

func randomID(prefix string) (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(randomBytes), nil
}

func dayStart(value time.Time) time.Time {
	year, month, day := value.UTC().Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

func IsRequestError(err error) (*RequestError, bool) {
	var requestErr *RequestError
	ok := errors.As(err, &requestErr)
	return requestErr, ok
}

func ValidatePublicID(value string) bool {
	return deploymentIDPattern.MatchString(value) || batchIDPattern.MatchString(value)
}

func CleanPathValue(value string) string {
	return strings.TrimSpace(value)
}
