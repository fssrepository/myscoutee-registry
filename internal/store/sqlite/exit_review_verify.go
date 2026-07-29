package sqlite

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"reflect"
	"regexp"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

var exitReviewVerifierReasonPattern = regexp.MustCompile(
	`^[a-z][a-z0-9-]{2,63}$`,
)

func (sqliteStore *Store) VerifyExitReviews(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	if len(registryPublicKey) != ed25519.PublicKeySize {
		return inconsistentMessage(
			"exit review verification has an invalid registry public key",
		)
	}
	var identityCreatedAtValue string
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT created_at
		FROM registry_identity
		WHERE singleton = 1`).Scan(&identityCreatedAtValue); err != nil {
		return inconsistent("read identity for exit review verification", err)
	}
	identityCreatedAt, err := time.Parse(time.RFC3339Nano, identityCreatedAtValue)
	if err != nil || !validPersistedTimestamp(identityCreatedAtValue) {
		return inconsistentMessage(
			"registry identity timestamp is invalid for exit review verification",
		)
	}

	records, err := sqliteStore.verifyExitReviewRecords(
		ctx,
		registryKeyID,
		registryScope,
	)
	if err != nil {
		return err
	}
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		exitReviewEventSelect+" ORDER BY event_index",
	)
	if err != nil {
		return inconsistent("read exit review event chain", err)
	}
	events := make([]store.ExitReviewEvent, 0)
	for rows.Next() {
		event, scanErr := scanExitReviewEvent(rows)
		if scanErr != nil {
			rows.Close()
			return inconsistent("scan exit review event chain", scanErr)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return inconsistent("iterate exit review event chain", err)
	}
	if err := rows.Close(); err != nil {
		return inconsistent("close exit review event chain", err)
	}

	expectedIndex := int64(1)
	previousHash := protocol.ExitReviewZeroHash
	var previousAcceptedAt time.Time
	perReviewHash := make(map[string]string)
	perReviewStatus := make(map[string]string)
	perReviewEffectiveDate := make(map[string]string)
	freezeSeen := make(map[string]bool)
	eventCount := int64(0)
	for _, event := range events {
		record, exists := records[event.ReviewID]
		if !exists {
			return inconsistentMessage(
				"exit review event %d references a missing frozen record",
				event.EventIndex,
			)
		}
		acceptedAt, parseErr := time.Parse(time.RFC3339Nano, event.AcceptedAt)
		if parseErr != nil ||
			!validPersistedTimestamp(event.AcceptedAt) ||
			acceptedAt.Before(identityCreatedAt) ||
			(!previousAcceptedAt.IsZero() &&
				acceptedAt.Before(previousAcceptedAt)) {
			return inconsistentMessage(
				"exit review event timestamps are invalid or non-monotonic",
			)
		}
		if event.EventIndex != expectedIndex ||
			event.PreviousEventHash != previousHash ||
			event.RegistryScope != registryScope ||
			event.RegistryKeyID != registryKeyID ||
			event.RecordHash != record.RecordHash ||
			!validHexID(event.EventID, "exe_", 32) ||
			!validHexID(event.ReviewID, "exr_", 32) ||
			!protocol.IsDigest(event.EvidenceHash) ||
			!protocol.IsDigest(event.PayloadHash) ||
			!protocol.IsDigest(event.EventHash) ||
			!validExitReviewVerifierActor(event.ActorRole, event.ActorID) ||
			!validRegistryCaseText(event.Reference, 240) ||
			!validRegistryCaseToken(event.IdempotencyKey) {
			return inconsistentMessage(
				"exit review event %d has invalid immutable fields",
				event.EventIndex,
			)
		}
		effectiveDate, dateErr := time.Parse("2006-01-02", event.EffectiveDate)
		if dateErr != nil ||
			effectiveDate.Format("2006-01-02") != event.EffectiveDate ||
			event.EffectiveDate < record.RecordDate ||
			(perReviewEffectiveDate[event.ReviewID] != "" &&
				event.EffectiveDate < perReviewEffectiveDate[event.ReviewID]) {
			return inconsistentMessage(
				"exit review event %d has an invalid effective date",
				event.EventIndex,
			)
		}
		expectedPreviousReviewHash := perReviewHash[event.ReviewID]
		if expectedPreviousReviewHash == "" {
			expectedPreviousReviewHash = protocol.ExitReviewZeroHash
		}
		if event.PreviousReviewEventHash != expectedPreviousReviewHash {
			return inconsistentMessage(
				"exit review event %d breaks its per-review chain",
				event.EventIndex,
			)
		}
		if !validExitReviewVerifierSemantics(
			event,
			perReviewStatus[event.ReviewID],
			freezeSeen[event.ReviewID],
			record.RecordDate,
		) {
			return inconsistentMessage(
				"exit review event %d has invalid transition semantics",
				event.EventIndex,
			)
		}
		expectedPayloadHash := protocol.Digest(
			protocol.ExitReviewEventPayloadMessage(
				exitReviewProtocolEvent(event),
			),
		)
		expectedEventHash := protocol.Digest(
			protocol.ExitReviewEventHashMessage(
				exitReviewProtocolEvent(event),
			),
		)
		if event.PayloadHash != expectedPayloadHash ||
			event.EventHash != expectedEventHash ||
			!ed25519.Verify(
				registryPublicKey,
				protocol.ExitReviewEventReceiptMessage(
					exitReviewProtocolEvent(event),
				),
				event.Signature,
			) {
			return inconsistentMessage(
				"exit review event %d hash or signature differs",
				event.EventIndex,
			)
		}
		state, stateErr := scanExitReviewState(
			sqliteStore.db.QueryRowContext(
				ctx,
				exitReviewStateSelect+" WHERE event_index = ?",
				event.EventIndex,
			),
		)
		if stateErr != nil {
			return inconsistent(
				"read exit review event query row",
				stateErr,
			)
		}
		expectedState := exitReviewStateFromEvent(record, event)
		if !reflect.DeepEqual(state, expectedState) {
			return inconsistentMessage(
				"exit review query row %d differs from its immutable event",
				event.EventIndex,
			)
		}
		perReviewHash[event.ReviewID] = event.EventHash
		perReviewStatus[event.ReviewID] = event.ResultingStatus
		perReviewEffectiveDate[event.ReviewID] = event.EffectiveDate
		if event.Action == protocol.ExitReviewActionFreeze {
			freezeSeen[event.ReviewID] = true
		}
		previousHash = event.EventHash
		previousAcceptedAt = acceptedAt
		expectedIndex++
		eventCount++
	}
	for reviewID := range records {
		if !freezeSeen[reviewID] {
			return inconsistentMessage(
				"exit review %q has no freeze event",
				reviewID,
			)
		}
	}
	var stateCount int64
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM exit_review_state_rows`).Scan(&stateCount); err != nil {
		return inconsistent("count exit review query rows", err)
	}
	if stateCount != eventCount {
		return inconsistentMessage(
			"exit review event/query cardinality differs",
		)
	}
	return nil
}

func (sqliteStore *Store) verifyExitReviewRecords(
	ctx context.Context,
	registryKeyID string,
	registryScope string,
) (map[string]store.ExitReviewRecord, error) {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT review_id
		FROM exit_reviews
		ORDER BY review_id`)
	if err != nil {
		return nil, inconsistent("list frozen exit review records", err)
	}
	ids := make([]string, 0)
	for rows.Next() {
		var reviewID string
		if err := rows.Scan(&reviewID); err != nil {
			rows.Close()
			return nil, inconsistent("scan frozen exit review ID", err)
		}
		ids = append(ids, reviewID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, inconsistent("iterate frozen exit review IDs", err)
	}
	if err := rows.Close(); err != nil {
		return nil, inconsistent("close frozen exit review ID rows", err)
	}

	tx, err := sqliteStore.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin exit review record verification: %w", err)
	}
	defer tx.Rollback()
	records := make(map[string]store.ExitReviewRecord, len(ids))
	for _, reviewID := range ids {
		record, readErr := exitReviewRecordByID(ctx, tx, reviewID)
		if readErr != nil {
			return nil, inconsistent("read frozen exit review record", readErr)
		}
		if record.RulesetVersion != protocol.ExitReviewRulesetVersion ||
			record.RegistryScope != registryScope ||
			record.RegistryKeyID != registryKeyID ||
			!validHexID(record.ReviewID, "exr_", 32) ||
			!validHexID(record.TargetDeploymentID, "dep_", 32) ||
			!validHexID(record.ClaimActionID, "opa_", 32) ||
			!validHexID(record.GroupID, "opg_", 32) ||
			!protocol.IsDigest(record.RecordHash) ||
			!protocol.IsDigest(record.CheckpointHash) ||
			!protocol.IsDigest(record.LedgerHeadHash) ||
			!protocol.IsDigest(record.MerkleRootHash) ||
			!protocol.IsDigest(record.AuditHeadHash) ||
			!protocol.IsDigest(record.ClaimReviewHeadHash) ||
			!protocol.IsDigest(record.EligibilityHeadHash) ||
			!protocol.IsDigest(record.SettlementBoundaryHash) ||
			!protocol.IsDigest(record.MembershipHash) ||
			record.DeploymentCount != int64(len(record.Deployments)) ||
			record.SettlementBoundaryCount != int64(len(record.Settlements)) ||
			!validPersistedTimestamp(record.FrozenAt) {
			return nil, inconsistentMessage(
				"frozen exit review %q has invalid immutable fields",
				reviewID,
			)
		}
		recomputed, recomputeErr := freezeExitReviewRecordTx(
			ctx,
			tx,
			store.ExitReviewFreezeInput{
				RecordDate:         record.RecordDate,
				TargetDeploymentID: record.TargetDeploymentID,
				ClaimActionID:      record.ClaimActionID,
				GroupID:            record.GroupID,
				CandidateReviewID:  record.ReviewID,
				AcceptedAt:         record.FrozenAt,
				RegistryScope:      record.RegistryScope,
				RegistryKeyID:      record.RegistryKeyID,
			},
		)
		if recomputeErr != nil {
			return nil, inconsistent(
				"recompute frozen exit review boundaries",
				recomputeErr,
			)
		}
		if !reflect.DeepEqual(record, recomputed) {
			return nil, inconsistentMessage(
				"frozen exit review %q differs from its pinned source boundaries",
				reviewID,
			)
		}
		records[reviewID] = record
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("finish exit review record verification: %w", err)
	}
	return records, nil
}

func validExitReviewVerifierActor(role, actorID string) bool {
	if role != protocol.ExitReviewActorBuyer &&
		role != protocol.ExitReviewActorAuditor {
		return false
	}
	if len(actorID) < 1 || len(actorID) > 120 {
		return false
	}
	for index, character := range []byte(actorID) {
		valid := (character >= 'A' && character <= 'Z') ||
			(character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' ||
				character == '_' ||
				character == ':' ||
				character == '/' ||
				character == '-'))
		if !valid {
			return false
		}
	}
	return true
}

func validExitReviewVerifierSemantics(
	event store.ExitReviewEvent,
	currentStatus string,
	freezeSeen bool,
	recordDate string,
) bool {
	switch event.Action {
	case protocol.ExitReviewActionFreeze:
		return !freezeSeen &&
			currentStatus == "" &&
			event.ResultingStatus == protocol.ExitReviewStatusPending &&
			event.EffectiveDate == recordDate &&
			event.ReasonCode == ""
	case protocol.ExitReviewActionVerify:
		return freezeSeen &&
			(currentStatus == protocol.ExitReviewStatusPending ||
				currentStatus == protocol.ExitReviewStatusDisputed) &&
			event.ResultingStatus == protocol.ExitReviewStatusEligible &&
			event.ReasonCode == ""
	case protocol.ExitReviewActionReject:
		return freezeSeen &&
			(currentStatus == protocol.ExitReviewStatusPending ||
				currentStatus == protocol.ExitReviewStatusDisputed) &&
			event.ResultingStatus == protocol.ExitReviewStatusRejected &&
			exitReviewVerifierReasonPattern.MatchString(event.ReasonCode)
	case protocol.ExitReviewActionDispute:
		return freezeSeen &&
			(currentStatus == protocol.ExitReviewStatusEligible ||
				currentStatus == protocol.ExitReviewStatusRejected) &&
			event.ResultingStatus == protocol.ExitReviewStatusDisputed &&
			exitReviewVerifierReasonPattern.MatchString(event.ReasonCode)
	case protocol.ExitReviewActionWithdraw:
		return freezeSeen &&
			currentStatus != "" &&
			currentStatus != protocol.ExitReviewStatusWithdrawn &&
			event.ResultingStatus == protocol.ExitReviewStatusWithdrawn &&
			exitReviewVerifierReasonPattern.MatchString(event.ReasonCode)
	default:
		return false
	}
}
