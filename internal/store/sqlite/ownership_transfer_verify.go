package sqlite

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func (sqliteStore *Store) VerifyOwnershipTransfers(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	records, err := sqliteStore.verifiedOwnershipTransferRecords(
		ctx,
		registryKeyID,
		registryScope,
	)
	if err != nil {
		return err
	}
	events, latest, states, err := sqliteStore.verifiedOwnershipTransferEvents(
		ctx,
		records,
		registryPublicKey,
		registryKeyID,
		registryScope,
	)
	if err != nil {
		return err
	}
	if err := sqliteStore.verifyOwnershipTransferStateRows(
		ctx,
		states,
	); err != nil {
		return err
	}
	if err := sqliteStore.verifyOwnershipTransferMemberships(
		ctx,
		records,
		events,
		latest,
	); err != nil {
		return err
	}
	return verifyNoConflictingActiveOwnershipTransfers(records, latest)
}

func (sqliteStore *Store) verifiedOwnershipTransferRecords(
	ctx context.Context,
	registryKeyID string,
	registryScope string,
) (map[string]store.OwnershipTransferRecord, error) {
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		ownershipTransferRecordSelect+" ORDER BY transfer_id",
	)
	if err != nil {
		return nil, inconsistent("read ownership transfer records", err)
	}
	baseRecords := make([]store.OwnershipTransferRecord, 0)
	for rows.Next() {
		record, err := scanOwnershipTransferRecord(rows)
		if err != nil {
			rows.Close()
			return nil, inconsistent("scan ownership transfer record", err)
		}
		baseRecords = append(baseRecords, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, inconsistent("iterate ownership transfer records", err)
	}
	if err := rows.Close(); err != nil {
		return nil, inconsistent("close ownership transfer records", err)
	}
	records := make(map[string]store.OwnershipTransferRecord)
	for _, record := range baseRecords {
		if !validHexID(record.TransferID, "otf_", 32) ||
			record.RulesetVersion !=
				protocol.OwnershipTransferRulesetVersion ||
			!validHexID(record.ExitReviewID, "exr_", 32) ||
			!validHexID(record.TargetDeploymentID, "dep_", 32) ||
			!validHexID(record.ClaimActionID, "opa_", 32) ||
			!validHexID(record.SourceGroupID, "opg_", 32) ||
			!validHexID(record.TargetGroupID, "opg_", 32) ||
			record.SourceGroupID == record.TargetGroupID ||
			record.LegalName == "" ||
			record.RegistryScope != registryScope ||
			record.RegistryKeyID != registryKeyID ||
			!protocol.IsDigest(record.ExitRecordHash) ||
			!protocol.IsDigest(record.ExitVerificationEventHash) ||
			!protocol.IsDigest(record.ExitEvidenceHash) ||
			!protocol.IsDigest(record.RecordHash) ||
			!validPersistedTimestamp(record.PreparedAt) {
			return nil, inconsistentMessage(
				"ownership transfer %s has invalid immutable metadata",
				record.TransferID,
			)
		}
		expectedRecordHash := protocol.Digest(
			protocol.OwnershipTransferRecordHashMessage(
				ownershipTransferProtocolRecord(record),
			),
		)
		if record.RecordHash != expectedRecordHash {
			return nil, inconsistentMessage(
				"ownership transfer %s record hash verification failed",
				record.TransferID,
			)
		}
		var (
			exitDeploymentID      string
			exitClaimActionID     string
			exitGroupID           string
			exitRecordHash        string
			exitEventReviewID     string
			exitEventAction       string
			exitEventStatus       string
			exitEventEvidenceHash string
			exitEventRecordHash   string
			exitEventAcceptedAt   string
			submissionLegalName   string
		)
		err = sqliteStore.db.QueryRowContext(ctx, `
			SELECT
				review.target_deployment_id,
				review.claim_action_id,
				review.group_id,
				review.record_hash,
				event.review_id,
				event.action,
				event.resulting_status,
				event.evidence_hash,
				event.record_hash,
				event.accepted_at,
				submission.legal_name
			FROM exit_reviews review
			JOIN exit_review_events event
			  ON event.event_index = ?
			 AND event.event_hash = ?
			JOIN operator_claim_verification_submissions submission
			  ON submission.claim_action_id = review.claim_action_id
			WHERE review.review_id = ?`,
			record.ExitVerificationEventIndex,
			record.ExitVerificationEventHash,
			record.ExitReviewID,
		).Scan(
			&exitDeploymentID,
			&exitClaimActionID,
			&exitGroupID,
			&exitRecordHash,
			&exitEventReviewID,
			&exitEventAction,
			&exitEventStatus,
			&exitEventEvidenceHash,
			&exitEventRecordHash,
			&exitEventAcceptedAt,
			&submissionLegalName,
		)
		if err != nil ||
			exitDeploymentID != record.TargetDeploymentID ||
			exitClaimActionID != record.ClaimActionID ||
			exitGroupID != record.SourceGroupID ||
			exitRecordHash != record.ExitRecordHash ||
			exitEventReviewID != record.ExitReviewID ||
			exitEventAction != protocol.ExitReviewActionVerify ||
			exitEventStatus != protocol.ExitReviewStatusEligible ||
			exitEventEvidenceHash != record.ExitEvidenceHash ||
			exitEventRecordHash != record.ExitRecordHash ||
			submissionLegalName != record.LegalName ||
			record.PreparedAt < exitEventAcceptedAt {
			return nil, inconsistentMessage(
				"ownership transfer %s does not match its claim/exit boundary",
				record.TransferID,
			)
		}
		targetEligible, err := ownershipTransferTargetEligibleAt(
			ctx,
			sqliteStore.db,
			record.TargetGroupID,
			record.PreparedAt,
		)
		if err != nil {
			return nil, err
		}
		if !targetEligible {
			return nil, inconsistentMessage(
				"ownership transfer %s target group was not eligible at prepare",
				record.TransferID,
			)
		}
		if _, duplicate := records[record.TransferID]; duplicate {
			return nil, inconsistentMessage(
				"ownership transfer ID %s is duplicated",
				record.TransferID,
			)
		}
		records[record.TransferID] = record
	}
	return records, nil
}

func ownershipTransferTargetEligibleAt(
	ctx context.Context,
	queryer ownershipTransferQueryer,
	groupID string,
	acceptedAt string,
) (bool, error) {
	var (
		auditIndex       int64
		reviewIndex      int64
		eligibilityIndex int64
		transferIndex    int64
	)
	if err := queryer.QueryRowContext(ctx, `
		SELECT
			COALESCE((
				SELECT MAX(audit_index)
				FROM operator_audit_events
				WHERE accepted_at <= ?
			), 0),
			COALESCE((
				SELECT MAX(review_index)
				FROM operator_claim_reviews
				WHERE reviewed_at <= ?
			), 0),
			COALESCE((
				SELECT MAX(eligibility_index)
				FROM operator_claim_eligibility_events
				WHERE decided_at <= ?
			), 0),
			COALESCE((
				SELECT MAX(event_index)
				FROM ownership_transfer_events
				WHERE accepted_at <= ?
			), 0)`,
		acceptedAt,
		acceptedAt,
		acceptedAt,
		acceptedAt,
	).Scan(
		&auditIndex,
		&reviewIndex,
		&eligibilityIndex,
		&transferIndex,
	); err != nil {
		return false, inconsistent(
			"read ownership transfer target eligibility boundary",
			err,
		)
	}
	var found int
	err := queryer.QueryRowContext(
		ctx,
		leaderboardStateCTE+`
		SELECT 1
		FROM memberships membership
		JOIN operator_claim_verification_submissions submission
		  ON submission.claim_action_id = membership.claim_action_id
		 AND submission.deployment_id = membership.deployment_id
		WHERE membership.group_id = ?
		  AND submission.group_id = ?
		  AND membership.active = 1
		  AND membership.claimed = 1
		  AND membership.claim_state = 'approved'
		  AND membership.eligible = 1
		LIMIT 1`,
		auditIndex,
		int64(0),
		reviewIndex,
		eligibilityIndex,
		transferIndex,
		acceptedAt[:len("2006-01-02")],
		"",
		"",
		groupID,
		groupID,
	).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, inconsistent(
			"verify ownership transfer target eligibility boundary",
			err,
		)
	}
	return found == 1, nil
}

func (sqliteStore *Store) verifiedOwnershipTransferEvents(
	ctx context.Context,
	records map[string]store.OwnershipTransferRecord,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) (
	map[int64]store.OwnershipTransferEvent,
	map[string]store.OwnershipTransferEvent,
	map[int64]ownershipTransferState,
	error,
) {
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		ownershipTransferEventSelect+" ORDER BY event_index",
	)
	if err != nil {
		return nil, nil, nil,
			inconsistent("read ownership transfer event chain", err)
	}
	defer rows.Close()
	events := make(map[int64]store.OwnershipTransferEvent)
	latest := make(map[string]store.OwnershipTransferEvent)
	states := make(map[int64]ownershipTransferState)
	seenPrepare := make(map[string]bool)
	seenIdempotency := make(map[string]bool)
	expectedIndex := int64(1)
	previousHash := protocol.OwnershipTransferZeroHash
	var previousAcceptedAt time.Time
	for rows.Next() {
		event, err := scanOwnershipTransferEvent(rows)
		if err != nil {
			return nil, nil, nil,
				inconsistent("scan ownership transfer event", err)
		}
		record, exists := records[event.TransferID]
		acceptedAt, acceptedErr := time.Parse(
			time.RFC3339Nano,
			event.AcceptedAt,
		)
		effectiveDate, effectiveErr := time.Parse(
			"2006-01-02",
			event.EffectiveDate,
		)
		if event.EventIndex != expectedIndex ||
			!validHexID(event.EventID, "ote_", 32) ||
			!exists ||
			event.RecordHash != record.RecordHash ||
			event.RegistryScope != registryScope ||
			event.RegistryKeyID != registryKeyID ||
			event.PreviousEventHash != previousHash ||
			!protocol.IsDigest(event.EvidenceHash) ||
			!protocol.IsDigest(event.PayloadHash) ||
			!protocol.IsDigest(event.EventHash) ||
			acceptedErr != nil ||
			effectiveErr != nil ||
			event.EffectiveDate != effectiveDate.Format("2006-01-02") ||
			event.EffectiveDate <
				record.PreparedAt[:len("2006-01-02")] ||
			(expectedIndex > 1 &&
				acceptedAt.Before(previousAcceptedAt)) ||
			seenIdempotency[event.IdempotencyKey] {
			return nil, nil, nil, inconsistentMessage(
				"ownership transfer event %d has invalid metadata or ordering",
				event.EventIndex,
			)
		}
		prior, hasPrior := latest[event.TransferID]
		if event.Action == protocol.OwnershipTransferActionPrepare {
			if hasPrior ||
				seenPrepare[event.TransferID] ||
				event.EventIndex == 0 ||
				event.ResultingStatus !=
					protocol.OwnershipTransferStatusPrepared ||
				event.ActorRole !=
					protocol.OwnershipTransferActorRequester ||
				event.ReasonCode != "" ||
				event.PreviousTransferEventHash !=
					protocol.OwnershipTransferZeroHash ||
				event.AcceptedAt != record.PreparedAt {
				return nil, nil, nil, inconsistentMessage(
					"ownership transfer %s has an invalid prepare event",
					event.TransferID,
				)
			}
			seenPrepare[event.TransferID] = true
		} else {
			if !hasPrior ||
				event.ActorRole != protocol.OwnershipTransferActorManager ||
				event.PreviousTransferEventHash != prior.EventHash ||
				!validOwnershipTransferTransition(
					prior.ResultingStatus,
					event.Action,
					event.ResultingStatus,
				) ||
				event.EffectiveDate < prior.EffectiveDate {
				return nil, nil, nil, inconsistentMessage(
					"ownership transfer event %d has an invalid transition",
					event.EventIndex,
				)
			}
		}
		validReason := (event.Action ==
			protocol.OwnershipTransferActionReject ||
			event.Action == protocol.OwnershipTransferActionCancel) ==
			protocol.IsOperatorClaimReviewReasonCode(event.ReasonCode)
		if !validReason ||
			event.ActorID == "" ||
			len(event.ActorID) > 120 ||
			event.Reference == "" ||
			len(event.Reference) > 240 ||
			protocol.HasCanonicalLineBreak(event.ActorID) ||
			protocol.HasCanonicalLineBreak(event.Reference) ||
			event.IdempotencyKey == "" {
			return nil, nil, nil, inconsistentMessage(
				"ownership transfer event %d has invalid audit fields",
				event.EventIndex,
			)
		}
		if event.Action == protocol.OwnershipTransferActionComplete &&
			event.EffectiveDate !=
				event.AcceptedAt[:len("2006-01-02")] {
			return nil, nil, nil, inconsistentMessage(
				"ownership transfer completion %d is backdated",
				event.EventIndex,
			)
		}
		expectedPayloadHash := protocol.Digest(
			protocol.OwnershipTransferEventPayloadMessage(
				ownershipTransferProtocolEvent(event),
			),
		)
		expectedEventHash := protocol.Digest(
			protocol.OwnershipTransferEventHashMessage(
				ownershipTransferProtocolEvent(event),
			),
		)
		if event.PayloadHash != expectedPayloadHash ||
			event.EventHash != expectedEventHash ||
			!ed25519.Verify(
				registryPublicKey,
				protocol.OwnershipTransferEventReceiptMessage(
					ownershipTransferProtocolEvent(event),
				),
				event.Signature,
			) {
			return nil, nil, nil, inconsistentMessage(
				"ownership transfer event %d hash/signature verification failed",
				event.EventIndex,
			)
		}
		events[event.EventIndex] = event
		latest[event.TransferID] = event
		states[event.EventIndex] =
			ownershipTransferStateFromEvent(record, event)
		seenIdempotency[event.IdempotencyKey] = true
		expectedIndex++
		previousHash = event.EventHash
		previousAcceptedAt = acceptedAt
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil,
			inconsistent("iterate ownership transfer event chain", err)
	}
	if len(seenPrepare) != len(records) {
		return nil, nil, nil, inconsistentMessage(
			"ownership transfer record count is %d, prepare count is %d",
			len(records),
			len(seenPrepare),
		)
	}
	return events, latest, states, nil
}

func (sqliteStore *Store) verifyOwnershipTransferStateRows(
	ctx context.Context,
	expected map[int64]ownershipTransferState,
) error {
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		ownershipTransferStateSelect+" ORDER BY event_index",
	)
	if err != nil {
		return inconsistent("read ownership transfer query rows", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		actual, err := scanOwnershipTransferState(rows)
		if err != nil {
			return inconsistent("scan ownership transfer query row", err)
		}
		want, exists := expected[actual.EventIndex]
		if !exists || !reflect.DeepEqual(actual, want) {
			return inconsistentMessage(
				"ownership transfer query row %d does not match its event",
				actual.EventIndex,
			)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate ownership transfer query rows", err)
	}
	if count != len(expected) {
		return inconsistentMessage(
			"ownership transfer query row count is %d, expected %d",
			count,
			len(expected),
		)
	}
	return nil
}

func (sqliteStore *Store) verifyOwnershipTransferMemberships(
	ctx context.Context,
	records map[string]store.OwnershipTransferRecord,
	events map[int64]store.OwnershipTransferEvent,
	latest map[string]store.OwnershipTransferEvent,
) error {
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		ownershipTransferMembershipSelect+" ORDER BY completion_event_index",
	)
	if err != nil {
		return inconsistent("read ownership transfer memberships", err)
	}
	memberships := make([]store.OwnershipTransferMembership, 0)
	for rows.Next() {
		membership, err := scanOwnershipTransferMembership(rows)
		if err != nil {
			rows.Close()
			return inconsistent("scan ownership transfer membership", err)
		}
		memberships = append(memberships, membership)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return inconsistent("iterate ownership transfer memberships", err)
	}
	if err := rows.Close(); err != nil {
		return inconsistent("close ownership transfer memberships", err)
	}
	seen := make(map[string]bool)
	for _, membership := range memberships {
		record, recordExists := records[membership.TransferID]
		event, eventExists := events[membership.CompletionEventIndex]
		head, headExists := latest[membership.TransferID]
		if !recordExists ||
			!eventExists ||
			!headExists ||
			event.EventHash != membership.CompletionEventHash ||
			event.TransferID != membership.TransferID ||
			event.Action != protocol.OwnershipTransferActionComplete ||
			event.ResultingStatus !=
				protocol.OwnershipTransferStatusCompleted ||
			head.EventIndex != event.EventIndex ||
			membership.TargetDeploymentID !=
				record.TargetDeploymentID ||
			membership.ClaimActionID != record.ClaimActionID ||
			membership.SourceGroupID != record.SourceGroupID ||
			membership.TargetGroupID != record.TargetGroupID ||
			membership.EffectiveDate != event.EffectiveDate ||
			membership.CompletedAt != event.AcceptedAt ||
			!protocol.IsDigest(membership.AuditHeadHash) ||
			!protocol.IsDigest(membership.MembershipHash) ||
			seen[membership.TransferID] {
			return inconsistentMessage(
				"ownership transfer membership %s has inconsistent sources",
				membership.TransferID,
			)
		}
		var auditHash string
		var expectedAuditIndex int64
		if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT COALESCE(MAX(audit_index), 0)
			FROM operator_audit_events
			WHERE accepted_at < ?`,
			membership.CompletedAt,
		).Scan(&expectedAuditIndex); err != nil {
			return inconsistent(
				"read ownership transfer membership audit head",
				err,
			)
		}
		if membership.ThroughAuditIndex != expectedAuditIndex {
			return inconsistentMessage(
				"ownership transfer membership %s is not pinned to the completion audit head",
				membership.TransferID,
			)
		}
		if membership.ThroughAuditIndex == 0 {
			auditHash = protocol.OperatorAuditZeroHash
		} else if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT audit_hash
			FROM operator_audit_events
			WHERE audit_index = ?`,
			membership.ThroughAuditIndex,
		).Scan(&auditHash); err != nil {
			return inconsistent(
				"read ownership transfer membership audit boundary",
				err,
			)
		}
		if membership.AuditHeadHash != auditHash {
			return inconsistentMessage(
				"ownership transfer membership %s has an invalid audit boundary",
				membership.TransferID,
			)
		}
		expectedHash := protocol.Digest(
			protocol.OwnershipTransferMembershipHashMessage(
				ownershipTransferProtocolMembership(membership),
			),
		)
		if membership.MembershipHash != expectedHash {
			return inconsistentMessage(
				"ownership transfer membership %s hash verification failed",
				membership.TransferID,
			)
		}
		seen[membership.TransferID] = true
	}
	completed := 0
	for transferID, event := range latest {
		if event.ResultingStatus ==
			protocol.OwnershipTransferStatusCompleted {
			completed++
			if !seen[transferID] {
				return inconsistentMessage(
					"completed ownership transfer %s has no membership boundary",
					transferID,
				)
			}
		} else if seen[transferID] {
			return inconsistentMessage(
				"non-completed ownership transfer %s has a membership boundary",
				transferID,
			)
		}
	}
	if len(seen) != completed {
		return inconsistentMessage(
			"ownership transfer membership count is %d, expected %d",
			len(seen),
			completed,
		)
	}
	return nil
}

func verifyNoConflictingActiveOwnershipTransfers(
	records map[string]store.OwnershipTransferRecord,
	latest map[string]store.OwnershipTransferEvent,
) error {
	type claimKey struct {
		deploymentID  string
		claimActionID string
	}
	active := make(map[claimKey][]string)
	for transferID, event := range latest {
		if event.ResultingStatus !=
			protocol.OwnershipTransferStatusPrepared &&
			event.ResultingStatus !=
				protocol.OwnershipTransferStatusApproved {
			continue
		}
		record := records[transferID]
		key := claimKey{
			deploymentID:  record.TargetDeploymentID,
			claimActionID: record.ClaimActionID,
		}
		active[key] = append(active[key], transferID)
	}
	keys := make([]claimKey, 0, len(active))
	for key := range active {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		if keys[left].deploymentID != keys[right].deploymentID {
			return keys[left].deploymentID < keys[right].deploymentID
		}
		return keys[left].claimActionID < keys[right].claimActionID
	})
	for _, key := range keys {
		if len(active[key]) > 1 {
			return inconsistentMessage(
				"claim %s/%s has multiple active ownership transfers",
				key.deploymentID,
				key.claimActionID,
			)
		}
	}
	return nil
}
