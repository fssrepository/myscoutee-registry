package sqlite

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

// OperationalRevision returns SQLite's connection-local data_version. It is
// deliberately not a business sequence: it is a cheap invalidation token that
// changes when another connection (for example the registry CLI) commits.
func (sqliteStore *Store) OperationalRevision(
	ctx context.Context,
) (store.OperationalRevision, error) {
	var revision int64
	if err := sqliteStore.db.QueryRowContext(ctx, "PRAGMA data_version").Scan(
		&revision,
	); err != nil {
		return 0, fmt.Errorf("read SQLite operational revision: %w", err)
	}
	return store.OperationalRevision(revision), nil
}

// VerifyOperationalBoundary verifies only the cryptographic heads and their
// immediately preceding links. A complete audit has already established the
// immutable prefix at bootstrap. SQLite append-only triggers plus transactional
// source/projection writes protect that prefix; this bounded check admits
// legitimate commits made by a second CLI connection without rescanning the
// complete registry history on the next HTTP request.
func (sqliteStore *Store) VerifyOperationalBoundary(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	if len(registryPublicKey) != ed25519.PublicKeySize {
		return inconsistentMessage("operational boundary has an invalid registry public key")
	}
	if err := sqliteStore.verifyIdentityBoundary(
		ctx,
		registryPublicKey,
		registryKeyID,
		registryScope,
	); err != nil {
		return err
	}
	if err := sqliteStore.verifyAppendOnlyTriggerBoundary(ctx); err != nil {
		return err
	}
	if err := sqliteStore.verifyLedgerBoundary(
		ctx,
		registryPublicKey,
		registryKeyID,
		registryScope,
	); err != nil {
		return err
	}
	if err := sqliteStore.verifyCheckpointBoundary(
		ctx,
		registryPublicKey,
		registryKeyID,
		registryScope,
	); err != nil {
		return err
	}
	if err := sqliteStore.verifyOperatorBoundary(
		ctx,
		registryPublicKey,
		registryKeyID,
		registryScope,
	); err != nil {
		return err
	}
	if err := sqliteStore.verifyClaimReviewBoundary(
		ctx,
		registryPublicKey,
		registryKeyID,
		registryScope,
	); err != nil {
		return err
	}
	if err := sqliteStore.verifyClaimEligibilityBoundary(
		ctx,
		registryPublicKey,
		registryKeyID,
		registryScope,
	); err != nil {
		return err
	}
	if err := sqliteStore.verifyAnnouncementBoundary(
		ctx,
		registryPublicKey,
		registryKeyID,
		registryScope,
	); err != nil {
		return err
	}
	if err := sqliteStore.verifyGlobalIdentityBoundary(
		ctx,
		registryPublicKey,
		registryKeyID,
		registryScope,
	); err != nil {
		return err
	}
	return nil
}

func (sqliteStore *Store) verifyAppendOnlyTriggerBoundary(
	ctx context.Context,
) error {
	const expectedTriggers = 104
	var triggerCount int
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM sqlite_master
		WHERE type = 'trigger'
		  AND name IN (
			'registry_identity_no_update',
			'registry_identity_no_delete',
			'deployments_no_update',
			'deployments_no_delete',
			'used_nonces_no_update',
			'used_nonces_no_delete',
			'idempotency_records_no_update',
			'idempotency_records_no_delete',
			'ledger_entries_no_update',
			'ledger_entries_no_delete',
			'mau_batches_no_update',
			'mau_batches_no_delete',
			'checkpoints_no_update',
			'checkpoints_no_delete',
			'ledger_weight_rows_no_update',
			'ledger_weight_rows_no_delete',
			'operator_audit_events_no_update',
			'operator_audit_events_no_delete',
			'operator_action_nonces_no_update',
			'operator_action_nonces_no_delete',
			'announcements_no_update',
			'announcements_no_delete',
			'operator_claim_verification_no_update',
			'operator_claim_verification_no_delete',
			'operator_claim_reviews_no_update',
			'operator_claim_reviews_no_delete',
			'operator_claim_eligibility_events_no_update',
			'operator_claim_eligibility_events_no_delete',
			'operator_network_state_rows_no_update',
			'operator_network_state_rows_no_delete',
			'revenue_batches_no_update',
			'revenue_batches_no_delete',
			'revenue_query_rows_no_update',
			'revenue_query_rows_no_delete',
			'settlements_no_update',
			'settlements_no_delete',
			'settlement_revenue_sources_no_update',
			'settlement_revenue_sources_no_delete',
			'settlement_ttm_months_no_update',
			'settlement_ttm_months_no_delete',
			'settlement_weight_sources_no_update',
			'settlement_weight_sources_no_delete',
			'settlement_beneficiary_deployments_no_update',
			'settlement_beneficiary_deployments_no_delete',
			'settlement_allocations_no_update',
			'settlement_allocations_no_delete',
			'ledger_merkle_nodes_no_update',
			'ledger_merkle_nodes_no_delete',
			'registry_case_events_no_update',
			'registry_case_events_no_delete',
			'exit_reviews_no_update',
			'exit_reviews_no_delete',
			'exit_review_deployments_no_update',
			'exit_review_deployments_no_delete',
			'exit_review_settlement_boundaries_no_update',
			'exit_review_settlement_boundaries_no_delete',
			'exit_review_events_no_update',
			'exit_review_events_no_delete',
			'exit_review_state_rows_no_update',
			'exit_review_state_rows_no_delete',
			'ownership_transfers_no_update',
			'ownership_transfers_no_delete',
			'ownership_transfer_events_no_update',
			'ownership_transfer_events_no_delete',
			'ownership_transfer_state_rows_no_update',
			'ownership_transfer_state_rows_no_delete',
			'ownership_transfer_memberships_no_update',
			'ownership_transfer_memberships_no_delete',
			'exit_allocations_no_update',
			'exit_allocations_no_delete',
			'exit_allocation_settlement_sources_no_update',
			'exit_allocation_settlement_sources_no_delete',
			'exit_allocation_currency_allocations_no_update',
			'exit_allocation_currency_allocations_no_delete',
			'exit_allocation_events_no_update',
			'exit_allocation_events_no_delete',
			'exit_allocation_state_rows_no_update',
			'exit_allocation_state_rows_no_delete',
			'global_identity_voprf_keys_no_update',
			'global_identity_voprf_keys_no_delete',
			'global_identity_evaluations_no_update',
			'global_identity_evaluations_no_delete',
			'global_identities_no_update',
			'global_identities_no_delete',
			'global_identity_events_no_update',
			'global_identity_events_no_delete',
			'global_identity_link_history_no_update',
			'global_identity_link_history_no_delete',
			'global_identity_presence_batches_no_update',
			'global_identity_presence_batches_no_delete',
			'global_identity_presence_items_no_update',
			'global_identity_presence_items_no_delete',
			'global_identity_presence_submissions_no_update',
			'global_identity_presence_submissions_no_delete',
			'global_identity_presence_chunks_no_update',
			'global_identity_presence_chunks_no_delete',
			'global_identity_presence_chunk_items_no_update',
			'global_identity_presence_chunk_items_no_delete',
			'global_identity_presence_completions_no_update',
			'global_identity_presence_completions_no_delete',
			'global_identity_dedup_snapshots_no_update',
			'global_identity_dedup_snapshots_no_delete',
			'demo_seed_metadata_guard_update',
			'demo_seed_metadata_no_delete'
		  )`).Scan(&triggerCount); err != nil {
		return inconsistent("inspect append-only trigger boundary", err)
	}
	if triggerCount != expectedTriggers {
		return inconsistentMessage(
			"append-only trigger boundary is incomplete: got %d of %d required triggers",
			triggerCount,
			expectedTriggers,
		)
	}
	return nil
}

func (sqliteStore *Store) verifyIdentityBoundary(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	identity, err := sqliteStore.RegistryIdentity(ctx)
	if err != nil {
		return inconsistent("read operational registry identity", err)
	}
	if identity == nil ||
		identity.ProtocolVersion != protocol.Version ||
		identity.RegistryScope != registryScope ||
		identity.RegistryKeyID != registryKeyID ||
		!bytes.Equal(identity.PublicKeyDER, registryPublicKeyDER(registryPublicKey)) ||
		!validPersistedTimestamp(identity.CreatedAt) {
		return inconsistentMessage("operational registry identity does not match the configured trust anchor")
	}
	return nil
}

func registryPublicKeyDER(publicKey ed25519.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil
	}
	return der
}

func (sqliteStore *Store) verifyLedgerBoundary(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			protocol_version,
			registry_scope,
			ledger_index,
			entry_type,
			deployment_id,
			batch_id,
			kind,
			period,
			ruleset_version,
			qualified_mau_count,
			batch_hash,
			previous_entry_hash,
			entry_hash,
			accepted_at
		FROM ledger_entries
		ORDER BY ledger_index DESC
		LIMIT 2`)
	if err != nil {
		return inconsistent("read operational ledger boundary", err)
	}
	defer rows.Close()
	entries := make([]protocol.LedgerEntry, 0, 2)
	for rows.Next() {
		entry, err := scanOperationalLedgerEntry(rows)
		if err != nil {
			return inconsistent("scan operational ledger boundary", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate operational ledger boundary", err)
	}
	if len(entries) == 0 {
		return nil
	}
	head := entries[0]
	if head.LedgerIndex < 1 ||
		head.ProtocolVersion != protocol.Version ||
		head.RegistryScope != registryScope ||
		!protocol.IsDigest(head.BatchHash) ||
		!protocol.IsDigest(head.PreviousEntryHash) ||
		!protocol.IsDigest(head.EntryHash) ||
		!validPersistedTimestamp(head.AcceptedAt) ||
		head.EntryHash != protocol.Digest(protocol.LedgerEntryMessage(head)) {
		return inconsistentMessage("operational ledger head is invalid")
	}
	if head.LedgerIndex == 1 {
		if len(entries) != 1 || head.PreviousEntryHash != protocol.ZeroHash {
			return inconsistentMessage("operational ledger genesis boundary is invalid")
		}
	} else {
		if len(entries) != 2 {
			return inconsistentMessage("operational ledger predecessor is missing")
		}
		previous := entries[1]
		if previous.LedgerIndex != head.LedgerIndex-1 ||
			previous.EntryHash != head.PreviousEntryHash ||
			previous.EntryHash != protocol.Digest(protocol.LedgerEntryMessage(previous)) {
			return inconsistentMessage("operational ledger head does not extend its trusted predecessor")
		}
		headTime, headErr := time.Parse(time.RFC3339Nano, head.AcceptedAt)
		previousTime, previousErr := time.Parse(time.RFC3339Nano, previous.AcceptedAt)
		if headErr != nil || previousErr != nil || headTime.Before(previousTime) {
			return inconsistentMessage("operational ledger boundary has invalid timestamp ordering")
		}
	}
	if err := sqliteStore.verifyLedgerSourceBoundary(
		ctx,
		head,
		registryPublicKey,
		registryKeyID,
	); err != nil {
		return err
	}
	if err := sqliteStore.verifyMerkleAppendBoundary(ctx, head); err != nil {
		return err
	}
	return nil
}

func scanOperationalLedgerEntry(scanner rowScanner) (protocol.LedgerEntry, error) {
	var entry protocol.LedgerEntry
	err := scanner.Scan(
		&entry.ProtocolVersion,
		&entry.RegistryScope,
		&entry.LedgerIndex,
		&entry.EntryType,
		&entry.DeploymentID,
		&entry.BatchID,
		&entry.Kind,
		&entry.Period,
		&entry.RulesetVersion,
		&entry.QualifiedMAUCount,
		&entry.BatchHash,
		&entry.PreviousEntryHash,
		&entry.EntryHash,
		&entry.AcceptedAt,
	)
	return entry, err
}

func (sqliteStore *Store) verifyLedgerSourceBoundary(
	ctx context.Context,
	entry protocol.LedgerEntry,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
) error {
	switch entry.EntryType {
	case protocol.InstallationEntryType, protocol.QualifiedMAUEntryType:
		var batchKind, period, ruleset, payloadHash, acceptedAt string
		var deploymentID string
		var qualifiedMAU, ledgerIndex int64
		if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT
				deployment_id,
				kind,
				period,
				ruleset_version,
				qualified_mau_count,
				payload_hash,
				accepted_at,
				ledger_index
			FROM mau_batches
			WHERE batch_id = ?`,
			entry.BatchID,
		).Scan(
			&deploymentID,
			&batchKind,
			&period,
			&ruleset,
			&qualifiedMAU,
			&payloadHash,
			&acceptedAt,
			&ledgerIndex,
		); err != nil {
			return inconsistent("read operational MAU source boundary", err)
		}
		if deploymentID != entry.DeploymentID ||
			batchKind != entry.Kind ||
			period != entry.Period ||
			ruleset != entry.RulesetVersion ||
			qualifiedMAU != entry.QualifiedMAUCount ||
			payloadHash != entry.BatchHash ||
			acceptedAt != entry.AcceptedAt ||
			ledgerIndex != entry.LedgerIndex {
			return inconsistentMessage("operational MAU source does not match the ledger head")
		}
		var weightEntryHash string
		if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT source_entry_hash
			FROM ledger_weight_rows
			WHERE ledger_index = ?`,
			entry.LedgerIndex,
		).Scan(&weightEntryHash); err != nil || weightEntryHash != entry.EntryHash {
			return inconsistentMessage("operational ledger head has no matching weight row")
		}
	case protocol.RevenueEntryType:
		var deploymentID, kind, period, ruleset, payloadHash, acceptedAt string
		var ledgerIndex int64
		if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT
				deployment_id,
				kind,
				period,
				ruleset_version,
				payload_hash,
				accepted_at,
				ledger_index
			FROM revenue_batches
			WHERE batch_id = ?`,
			entry.BatchID,
		).Scan(
			&deploymentID,
			&kind,
			&period,
			&ruleset,
			&payloadHash,
			&acceptedAt,
			&ledgerIndex,
		); err != nil {
			return inconsistent("read operational revenue source boundary", err)
		}
		if deploymentID != entry.DeploymentID ||
			kind != entry.Kind ||
			period != entry.Period ||
			ruleset != entry.RulesetVersion ||
			payloadHash != entry.BatchHash ||
			acceptedAt != entry.AcceptedAt ||
			ledgerIndex != entry.LedgerIndex ||
			entry.QualifiedMAUCount != 0 {
			return inconsistentMessage("operational revenue source does not match the ledger head")
		}
	case protocol.SettlementEntryType:
		record, err := settlementByIDQuery(ctx, sqliteStore.db, entry.BatchID)
		if err != nil {
			return inconsistent("read operational settlement source boundary", err)
		}
		receipt := settlementReceipt(
			record,
			entry.RegistryScope,
		)
		if record.LedgerEntry != entry ||
			record.RegistryKeyID != registryKeyID ||
			record.SourceFingerprint != settlementSourceFingerprint(record) ||
			record.AllocationHash != protocol.SettlementAllocationHash(
				record.Allocations,
			) ||
			record.SettlementHash != protocol.Digest(
				protocol.SettlementHashMessage(receipt),
			) ||
			!ed25519.Verify(
				registryPublicKey,
				protocol.SettlementReceiptMessage(receipt),
				record.ReceiptSignature,
			) {
			return inconsistentMessage(
				"operational settlement source does not match the ledger head",
			)
		}
		return nil
	default:
		return inconsistentMessage(
			"operational ledger head has unsupported entry type %q",
			entry.EntryType,
		)
	}
	var deploymentExists int
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM deployments WHERE deployment_id = ?
		)`,
		entry.DeploymentID,
	).Scan(&deploymentExists); err != nil || deploymentExists != 1 {
		return inconsistentMessage("operational ledger head references an unknown deployment")
	}
	return nil
}

// Only the parent nodes completed by the newest append are new. Recomputing
// that frontier is O(log n) worst-case and amortized O(1).
func (sqliteStore *Store) verifyMerkleAppendBoundary(
	ctx context.Context,
	entry protocol.LedgerEntry,
) error {
	nodeIndex := entry.LedgerIndex - 1
	for level := int64(1); nodeIndex&1 == 1; level++ {
		parentIndex := nodeIndex >> 1
		var persisted []byte
		if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT node_hash
			FROM ledger_merkle_nodes
			WHERE tree_level = ? AND node_index = ?`,
			level,
			parentIndex,
		).Scan(&persisted); err != nil {
			return inconsistent("read operational Merkle frontier", err)
		}
		left, err := sqliteStore.completeMerkleSubtree(ctx, level-1, parentIndex*2)
		if err != nil {
			return err
		}
		right, err := sqliteStore.completeMerkleSubtree(ctx, level-1, parentIndex*2+1)
		if err != nil {
			return err
		}
		if !equalHash(persisted, merkleNodeBytes(left, right)) {
			return inconsistentMessage(
				"operational Merkle frontier node %d/%d is invalid",
				level,
				parentIndex,
			)
		}
		nodeIndex >>= 1
	}
	return nil
}

func (sqliteStore *Store) verifyCheckpointBoundary(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			registry_scope,
			checkpoint_date,
			through_ledger_index,
			entry_count,
			ledger_head_hash,
			previous_checkpoint_hash,
			checkpoint_hash,
			generated_at,
			registry_key_id,
			signature
		FROM checkpoints
		ORDER BY checkpoint_date DESC
		LIMIT 2`)
	if err != nil {
		return inconsistent("read operational checkpoint boundary", err)
	}
	defer rows.Close()
	records := make([]store.CheckpointRecord, 0, 2)
	for rows.Next() {
		record, err := scanCheckpoint(rows)
		if err != nil {
			return err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate operational checkpoint boundary", err)
	}
	if len(records) == 0 {
		return nil
	}
	head := records[0]
	checkpoint := head.Checkpoint
	checkpointDate, err := time.Parse("2006-01-02", checkpoint.CheckpointDate)
	if err != nil ||
		checkpoint.RegistryScope != registryScope ||
		checkpoint.RegistryKeyID != registryKeyID ||
		checkpoint.EntryCount != checkpoint.ThroughLedgerIndex ||
		checkpoint.CheckpointHash != protocol.Digest(protocol.CheckpointMessage(checkpoint)) ||
		!ed25519.Verify(
			registryPublicKey,
			protocol.CheckpointMessage(checkpoint),
			head.Signature,
		) {
		return inconsistentMessage("operational checkpoint head is invalid")
	}
	if len(records) == 1 {
		if checkpoint.PreviousCheckpointHash != protocol.ZeroHash {
			return inconsistentMessage("operational checkpoint genesis link is invalid")
		}
	} else {
		previous := records[1].Checkpoint
		previousDate, parseErr := time.Parse("2006-01-02", previous.CheckpointDate)
		if parseErr != nil ||
			!checkpointDate.Equal(previousDate.AddDate(0, 0, 1)) ||
			checkpoint.PreviousCheckpointHash != previous.CheckpointHash {
			return inconsistentMessage("operational checkpoint head does not extend its predecessor")
		}
	}
	expectedLedgerHash := protocol.ZeroHash
	if checkpoint.ThroughLedgerIndex > 0 {
		if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT entry_hash
			FROM ledger_entries
			WHERE ledger_index = ? AND accepted_at < ?`,
			checkpoint.ThroughLedgerIndex,
			checkpointDate.AddDate(0, 0, 1).UTC().Format(time.RFC3339),
		).Scan(&expectedLedgerHash); err != nil {
			return inconsistent("read checkpoint ledger boundary", err)
		}
	}
	if expectedLedgerHash != checkpoint.LedgerHeadHash {
		return inconsistentMessage("operational checkpoint head does not match its ledger boundary")
	}
	return nil
}

func (sqliteStore *Store) verifyOperatorBoundary(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		operatorAuditSelect+" ORDER BY audit_index DESC LIMIT 2",
	)
	if err != nil {
		return inconsistent("read operational operator boundary", err)
	}
	defer rows.Close()
	events := make([]store.OperatorAuditEvent, 0, 2)
	for rows.Next() {
		event, err := scanOperatorAuditEvent(rows)
		if err != nil {
			return err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate operational operator boundary", err)
	}
	if len(events) == 0 {
		return nil
	}
	head := events[0]
	if head.AuditIndex < 1 ||
		!validHexID(head.ActionID, "opa_", 32) ||
		head.RegistryKeyID != registryKeyID ||
		!validPersistedTimestamp(head.AcceptedAt) {
		return inconsistentMessage("operational operator audit head has invalid metadata")
	}
	if len(events) == 1 {
		if head.PreviousAuditHash != protocol.OperatorAuditZeroHash {
			return inconsistentMessage("operational operator audit genesis link is invalid")
		}
	} else if events[1].AuditIndex != head.AuditIndex-1 ||
		events[1].AuditHash != head.PreviousAuditHash {
		return inconsistentMessage("operational operator audit head does not extend its predecessor")
	}
	var publicKeyDER []byte
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT public_key_der
		FROM deployments
		WHERE deployment_id = ?`,
		head.DeploymentID,
	).Scan(&publicKeyDER); err != nil {
		return inconsistent("read operator boundary deployment key", err)
	}
	parsedKey, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return inconsistent("parse operator boundary deployment key", err)
	}
	deploymentPublicKey, ok := parsedKey.(ed25519.PublicKey)
	if !ok || len(deploymentPublicKey) != ed25519.PublicKeySize {
		return inconsistentMessage("operator boundary deployment key is not Ed25519")
	}
	submission, err := sqliteStore.operatorClaimSubmissionByAction(
		ctx,
		head.ActionID,
	)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if errors.Is(err, store.ErrNotFound) {
		submission = store.OperatorClaimSubmission{}
	}
	expectedPayloadHash, _, err := operatorEventPayloadHash(head, submission)
	if err != nil || expectedPayloadHash != head.PayloadHash {
		return inconsistentMessage("operational operator audit payload hash is invalid")
	}
	requestMessage := protocol.CanonicalRequest(
		"POST",
		protocol.OperatorActionPath,
		protocol.Version,
		registryScope,
		head.DeploymentID,
		head.RequestTimestamp,
		head.Nonce,
		head.IdempotencyKey,
		head.PayloadHash,
	)
	if head.RequestHash != protocol.Digest(requestMessage) ||
		!ed25519.Verify(
			deploymentPublicKey,
			requestMessage,
			head.DeploymentSignature,
		) {
		return inconsistentMessage("operational operator audit deployment proof is invalid")
	}
	expectedAuditHash := protocol.Digest(protocol.OperatorAuditMessage(
		head.AuditIndex,
		head.ActionID,
		head.DeploymentID,
		head.SubjectDeploymentID,
		head.RelatedDeploymentID,
		head.Action,
		head.PayloadHash,
		head.AcceptedAt,
		head.ClaimState,
		head.GroupID,
		head.LinkID,
		head.TokenID,
		head.ClientTokenHash,
		head.SourceClaimActionID,
		head.SourcePrivateRecordHash,
		head.TokenExpiresAt,
		head.PreviousAuditHash,
	))
	if expectedAuditHash != head.AuditHash ||
		!ed25519.Verify(
			registryPublicKey,
			protocol.OperatorActionReceiptMessage(
				operatorReceipt(head, registryScope),
			),
			head.ReceiptSignature,
		) {
		return inconsistentMessage("operational operator audit registry proof is invalid")
	}
	var nonceActionID string
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT action_id
		FROM operator_action_nonces
		WHERE deployment_id = ? AND request_nonce = ?`,
		head.DeploymentID,
		head.Nonce,
	).Scan(&nonceActionID); err != nil || nonceActionID != head.ActionID {
		return inconsistentMessage("operational operator audit nonce boundary is invalid")
	}
	var stateActionID string
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT action_id
		FROM operator_network_state_rows
		WHERE audit_index = ?`,
		head.AuditIndex,
	).Scan(&stateActionID); err != nil || stateActionID != head.ActionID {
		return inconsistentMessage("operational operator audit state boundary is invalid")
	}
	return nil
}

func (sqliteStore *Store) operatorClaimSubmissionByAction(
	ctx context.Context,
	actionID string,
) (store.OperatorClaimSubmission, error) {
	return scanOperatorClaimSubmission(sqliteStore.db.QueryRowContext(ctx, `
		SELECT
			claim_action_id,
			deployment_id,
			group_id,
			legal_name,
			registration_number,
			jurisdiction,
			registered_address,
			website,
			verification_contact_name,
			verification_contact_role,
			verification_contact_email,
			authority_attested,
			operator_avatar_url,
			payload_hash,
			submitted_at,
			private_record_hash
		FROM operator_claim_verification_submissions
		WHERE claim_action_id = ?`,
		actionID,
	))
}

func (sqliteStore *Store) verifyClaimReviewBoundary(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			review_index,
			review_id,
			deployment_id,
			claim_action_id,
			group_id,
			legal_name,
			decision,
			reviewer_id,
			review_reference,
			reason_code,
			idempotency_key,
			reviewed_at,
			previous_review_hash,
			review_hash,
			registry_key_id,
			signature
		FROM operator_claim_reviews
		ORDER BY review_index DESC
		LIMIT 2`)
	if err != nil {
		return inconsistent("read operational claim-review boundary", err)
	}
	defer rows.Close()
	reviews := make([]store.OperatorClaimReview, 0, 2)
	for rows.Next() {
		review, err := scanOperatorClaimReview(rows)
		if err != nil {
			return err
		}
		reviews = append(reviews, review)
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate operational claim-review boundary", err)
	}
	if len(reviews) == 0 {
		return nil
	}
	head := reviews[0]
	validDecision := (head.Decision == protocol.OperatorClaimReviewApproved &&
		head.ReasonCode == "") ||
		(head.Decision == protocol.OperatorClaimReviewRejected &&
			protocol.IsOperatorClaimReviewReasonCode(head.ReasonCode))
	if head.ReviewIndex < 1 ||
		!validHexID(head.ReviewID, "opr_", 32) ||
		head.RegistryKeyID != registryKeyID ||
		!validDecision ||
		!validPersistedTimestamp(head.ReviewedAt) {
		return inconsistentMessage("operational claim-review head has invalid metadata")
	}
	if len(reviews) == 1 {
		if head.PreviousReviewHash != protocol.OperatorClaimReviewZeroHash {
			return inconsistentMessage("operational claim-review genesis link is invalid")
		}
	} else if reviews[1].ReviewIndex != head.ReviewIndex-1 ||
		reviews[1].ReviewHash != head.PreviousReviewHash {
		return inconsistentMessage("operational claim-review head does not extend its predecessor")
	}
	receipt := operatorClaimReviewReceipt(head, registryScope)
	if head.ReviewHash != protocol.Digest(
		protocol.OperatorClaimReviewHashMessage(receipt),
	) || !ed25519.Verify(
		registryPublicKey,
		protocol.OperatorClaimReviewReceiptMessage(receipt),
		head.Signature,
	) {
		return inconsistentMessage("operational claim-review registry proof is invalid")
	}
	var statusReviewIndex int64
	var statusReviewHash string
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT review_index, review_hash
		FROM operator_claim_status
		WHERE deployment_id = ? AND claim_action_id = ?`,
		head.DeploymentID,
		head.ClaimActionID,
	).Scan(&statusReviewIndex, &statusReviewHash); err != nil ||
		statusReviewIndex != head.ReviewIndex ||
		statusReviewHash != head.ReviewHash {
		return inconsistentMessage("operational claim-review status boundary is invalid")
	}
	return nil
}

func (sqliteStore *Store) verifyClaimEligibilityBoundary(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		operatorClaimEligibilitySelect+`
		ORDER BY eligibility_index DESC
		LIMIT 2`,
	)
	if err != nil {
		return inconsistent(
			"read operational claim-eligibility boundary",
			err,
		)
	}
	defer rows.Close()
	decisions := make([]store.OperatorClaimEligibility, 0, 2)
	for rows.Next() {
		decision, err := scanOperatorClaimEligibility(rows)
		if err != nil {
			return err
		}
		decisions = append(decisions, decision)
	}
	if err := rows.Err(); err != nil {
		return inconsistent(
			"iterate operational claim-eligibility boundary",
			err,
		)
	}
	if len(decisions) == 0 {
		return nil
	}
	head := decisions[0]
	validDecision := (head.Decision ==
		protocol.OperatorClaimEligibilitySuspend &&
		protocol.IsOperatorClaimEligibilityReasonCode(
			head.ReasonCode,
		)) ||
		(head.Decision ==
			protocol.OperatorClaimEligibilityReinstate &&
			head.ReasonCode == "")
	if head.EligibilityIndex < 1 ||
		!validHexID(head.EligibilityID, "ope_", 32) ||
		head.RegistryKeyID != registryKeyID ||
		!validDecision ||
		!validPersistedTimestamp(head.DecidedAt) {
		return inconsistentMessage(
			"operational claim-eligibility head has invalid metadata",
		)
	}
	if len(decisions) == 1 {
		if head.PreviousEligibilityHash !=
			protocol.OperatorClaimEligibilityZeroHash {
			return inconsistentMessage(
				"operational claim-eligibility genesis link is invalid",
			)
		}
	} else if decisions[1].EligibilityIndex != head.EligibilityIndex-1 ||
		decisions[1].EligibilityHash != head.PreviousEligibilityHash {
		return inconsistentMessage(
			"operational claim-eligibility head does not extend its predecessor",
		)
	}
	receipt := operatorClaimEligibilityReceipt(head, registryScope)
	if head.EligibilityHash != protocol.Digest(
		protocol.OperatorClaimEligibilityHashMessage(receipt),
	) || !ed25519.Verify(
		registryPublicKey,
		protocol.OperatorClaimEligibilityReceiptMessage(receipt),
		head.Signature,
	) {
		return inconsistentMessage(
			"operational claim-eligibility registry proof is invalid",
		)
	}

	var currentClaimActionID string
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT claim_action_id
		FROM operator_claim_status
		WHERE deployment_id = ?`,
		head.DeploymentID,
	).Scan(&currentClaimActionID); err != nil {
		return inconsistent(
			"read operational claim-eligibility status boundary",
			err,
		)
	}
	if currentClaimActionID != head.ClaimActionID {
		return nil
	}
	var eligibilityID, eligibilityHash string
	var eligibilityIndex int64
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT eligibility_id, eligibility_index, eligibility_hash
		FROM operator_claim_eligibility_current
		WHERE deployment_id = ? AND claim_action_id = ?`,
		head.DeploymentID,
		head.ClaimActionID,
	).Scan(
		&eligibilityID,
		&eligibilityIndex,
		&eligibilityHash,
	); err != nil ||
		eligibilityID != head.EligibilityID ||
		eligibilityIndex != head.EligibilityIndex ||
		eligibilityHash != head.EligibilityHash {
		return inconsistentMessage(
			"operational claim-eligibility current-state boundary is invalid",
		)
	}
	return nil
}

func (sqliteStore *Store) verifyAnnouncementBoundary(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		announcementSelect+" ORDER BY sequence DESC LIMIT 2",
	)
	if err != nil {
		return inconsistent("read operational announcement boundary", err)
	}
	defer rows.Close()
	records := make([]persistedAnnouncement, 0, 2)
	for rows.Next() {
		record, err := scanPersistedAnnouncement(rows)
		if err != nil {
			return err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate operational announcement boundary", err)
	}
	if len(records) == 0 {
		return nil
	}
	head := records[0]
	entry := head.entry
	if entry.Sequence < 1 ||
		!validHexID(entry.AnnouncementID, "ann_", 32) ||
		entry.ProtocolVersion != protocol.Version ||
		entry.RegistryScope != registryScope ||
		entry.RegistryKeyID != registryKeyID ||
		!validPersistedTimestamp(entry.AcceptedAt) ||
		!validPersistedTimestamp(entry.PublishedAt) ||
		(entry.ExpiresAt != "" && !validPersistedTimestamp(entry.ExpiresAt)) {
		return inconsistentMessage("operational announcement head has invalid metadata")
	}
	if len(records) == 1 {
		if entry.PreviousAnnouncementHash != protocol.AnnouncementZeroHash {
			return inconsistentMessage("operational announcement genesis link is invalid")
		}
	} else if records[1].entry.Sequence != entry.Sequence-1 ||
		records[1].entry.AnnouncementHash != entry.PreviousAnnouncementHash {
		return inconsistentMessage("operational announcement head does not extend its predecessor")
	}
	contentHash := protocol.Digest(protocol.AnnouncementContentMessage(
		entry.TitleKey,
		entry.BodyKey,
		entry.Localizations,
	))
	linksHash := protocol.Digest(protocol.AnnouncementLinksMessage(entry.Links))
	manifestHash := protocol.AnnouncementZeroHash
	updateChannel := ""
	if entry.UpdateManifest != nil {
		manifestHash = protocol.Digest(
			protocol.UpdateManifestMessage(*entry.UpdateManifest),
		)
		updateChannel = entry.UpdateManifest.Channel
	}
	expectedDraftHash := protocol.Digest(protocol.AnnouncementDraftMessage(
		entry.PublicationID,
		entry.Kind,
		entry.Severity,
		entry.PublishedAt,
		entry.ExpiresAt,
		entry.ContentHash,
		entry.LinksHash,
		entry.UpdateManifestHash,
	))
	if entry.ContentHash != contentHash ||
		entry.LinksHash != linksHash ||
		entry.UpdateManifestHash != manifestHash ||
		head.updateChannel != updateChannel ||
		head.draftHash != expectedDraftHash ||
		entry.AnnouncementHash != protocol.Digest(
			protocol.AnnouncementEntryMessage(entry),
		) ||
		!ed25519.Verify(
			registryPublicKey,
			protocol.AnnouncementReceiptMessage(entry),
			head.signature,
		) ||
		!knownAnnouncementKind(entry.Kind) ||
		!knownAnnouncementSeverity(entry.Severity) ||
		(entry.Kind == protocol.AnnouncementKindUpdate) !=
			(entry.UpdateManifest != nil) {
		return inconsistentMessage("operational announcement head proof is invalid")
	}
	return nil
}
