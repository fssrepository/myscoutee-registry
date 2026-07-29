package sqlite

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"reflect"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func (sqliteStore *Store) VerifyExitAllocations(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return inconsistent("begin final exit allocation verification", err)
	}
	defer tx.Rollback()
	records, err := verifiedExitAllocationRecords(
		ctx,
		tx,
		registryKeyID,
		registryScope,
	)
	if err != nil {
		return err
	}
	states, err := verifiedExitAllocationEvents(
		ctx,
		tx,
		records,
		registryPublicKey,
		registryKeyID,
		registryScope,
	)
	if err != nil {
		return err
	}
	if err := verifyExitAllocationStateRows(ctx, tx, states); err != nil {
		return err
	}
	return nil
}

func verifiedExitAllocationRecords(
	ctx context.Context,
	tx *sql.Tx,
	registryKeyID string,
	registryScope string,
) (map[string]store.ExitAllocationRecord, error) {
	rows, err := tx.QueryContext(
		ctx,
		exitAllocationRecordSelect+" ORDER BY allocation_id",
	)
	if err != nil {
		return nil, inconsistent("read final exit allocation records", err)
	}
	baseRecords := make([]store.ExitAllocationRecord, 0)
	for rows.Next() {
		record, scanErr := scanExitAllocationRecord(rows)
		if scanErr != nil {
			rows.Close()
			return nil, inconsistent(
				"scan final exit allocation record",
				scanErr,
			)
		}
		baseRecords = append(baseRecords, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, inconsistent("iterate final exit allocation records", err)
	}
	if err := rows.Close(); err != nil {
		return nil, inconsistent("close final exit allocation records", err)
	}
	records := make(map[string]store.ExitAllocationRecord)
	for _, baseRecord := range baseRecords {
		record := baseRecord
		record.SettlementSources, err = exitAllocationSourcesByAllocation(
			ctx,
			tx,
			record.AllocationID,
		)
		if err != nil {
			return nil, inconsistent("read final exit allocation sources", err)
		}
		record.CurrencyAllocations, err =
			exitAllocationCurrenciesByAllocation(
				ctx,
				tx,
				record.AllocationID,
			)
		if err != nil {
			return nil,
				inconsistent("read final exit allocation currencies", err)
		}
		if !validExitAllocationRecordMetadata(
			record,
			registryKeyID,
			registryScope,
		) {
			return nil, inconsistentMessage(
				"final exit allocation %s has invalid immutable metadata",
				record.AllocationID,
			)
		}
		if record.SettlementSourceCount !=
			int64(len(record.SettlementSources)) ||
			record.CurrencyAllocationCount !=
				int64(len(record.CurrencyAllocations)) ||
			record.SettlementSourceHash !=
				protocol.ExitAllocationSettlementSourceHash(
					exitAllocationProtocolSources(
						record.SettlementSources,
					),
				) ||
			record.CurrencyAllocationHash !=
				protocol.ExitAllocationCurrencyHash(
					exitAllocationProtocolCurrencies(
						record.CurrencyAllocations,
					),
				) ||
			record.RecordHash != protocol.Digest(
				protocol.ExitAllocationRecordHashMessage(
					exitAllocationProtocolRecord(record),
				),
			) {
			return nil, inconsistentMessage(
				"final exit allocation %s record hash or row commitment failed",
				record.AllocationID,
			)
		}
		exitRecord, err := exitReviewRecordByID(
			ctx,
			tx,
			record.ExitReviewID,
		)
		if err != nil ||
			exitRecord.TargetDeploymentID != record.TargetDeploymentID ||
			exitRecord.ClaimActionID != record.ClaimActionID ||
			exitRecord.GroupID != record.SourceGroupID ||
			exitRecord.RecordHash != record.ExitRecordHash {
			return nil, inconsistentMessage(
				"final exit allocation %s has an invalid exit record pin",
				record.AllocationID,
			)
		}
		exitEvent, err := scanExitReviewEvent(tx.QueryRowContext(
			ctx,
			exitReviewEventSelect+`
			WHERE event_index = ?
			  AND event_hash = ?
			  AND review_id = ?`,
			record.ExitVerificationEventIndex,
			record.ExitVerificationEventHash,
			record.ExitReviewID,
		))
		if err != nil ||
			exitEvent.Action != protocol.ExitReviewActionVerify ||
			exitEvent.ResultingStatus != protocol.ExitReviewStatusEligible ||
			exitEvent.RecordHash != record.ExitRecordHash ||
			exitEvent.EvidenceHash != record.ExitEvidenceHash ||
			record.CreatedAt < exitEvent.AcceptedAt {
			return nil, inconsistentMessage(
				"final exit allocation %s has an invalid verified-exit event pin",
				record.AllocationID,
			)
		}
		expectedSources, expectedCurrencies, err :=
			deriveExitAllocationRowsTx(
				ctx,
				tx,
				store.ExitReview{Record: exitRecord},
				record.BeneficiaryType,
				record.BeneficiaryID,
			)
		if err != nil ||
			!equalExitAllocationSources(
				record.SettlementSources,
				expectedSources,
			) ||
			!equalExitAllocationCurrencies(
				record.CurrencyAllocations,
				expectedCurrencies,
			) ||
			!validExitAllocationConservation(record) {
			return nil, inconsistentMessage(
				"final exit allocation %s does not reproduce its frozen settlement sources",
				record.AllocationID,
			)
		}
		if err := verifyExitAllocationDecisionBoundary(
			ctx,
			tx,
			record,
		); err != nil {
			return nil, err
		}
		if _, duplicate := records[record.AllocationID]; duplicate {
			return nil, inconsistentMessage(
				"final exit allocation ID %s is duplicated",
				record.AllocationID,
			)
		}
		records[record.AllocationID] = record
	}
	return records, nil
}

func validExitAllocationRecordMetadata(
	record store.ExitAllocationRecord,
	registryKeyID string,
	registryScope string,
) bool {
	if !validHexID(record.AllocationID, "xal_", 32) ||
		record.RulesetVersion != protocol.ExitAllocationRulesetVersion ||
		!validHexID(record.ExitReviewID, "exr_", 32) ||
		!validHexID(record.TargetDeploymentID, "dep_", 32) ||
		!validHexID(record.ClaimActionID, "opa_", 32) ||
		!validHexID(record.SourceGroupID, "opg_", 32) ||
		!protocol.IsDigest(record.ExitRecordHash) ||
		!protocol.IsDigest(record.ExitVerificationEventHash) ||
		!protocol.IsDigest(record.ExitEvidenceHash) ||
		!protocol.IsDigest(record.OwnershipTransferCompletionEventHash) ||
		!protocol.IsDigest(record.OwnershipTransferHeadHash) ||
		!protocol.IsDigest(record.ContractTermsHash) ||
		!protocol.IsDigest(record.EvidenceHash) ||
		!protocol.IsDigest(record.SettlementSourceHash) ||
		!protocol.IsDigest(record.CurrencyAllocationHash) ||
		!protocol.IsDigest(record.RecordHash) ||
		record.ExitVerificationEventIndex < 1 ||
		record.ThroughOwnershipTransferEventIndex < 0 ||
		record.SettlementSourceCount < 0 ||
		record.CurrencyAllocationCount < 0 ||
		record.RegistryKeyID != registryKeyID ||
		record.RegistryScope != registryScope ||
		!validPersistedTimestamp(record.CreatedAt) ||
		record.ContractReference == "" ||
		len(record.ContractReference) > 240 ||
		protocol.HasCanonicalLineBreak(record.ContractReference) ||
		!validExitAllocationBeneficiaryID(record.BeneficiaryID) {
		return false
	}
	switch record.DecisionMode {
	case protocol.ExitAllocationDecisionCompletedTransfer:
		return validHexID(record.OwnershipTransferID, "otf_", 32) &&
			record.OwnershipTransferCompletionEventIndex > 0 &&
			record.BeneficiaryType ==
				protocol.ExitAllocationBeneficiaryOperatorGroup &&
			validHexID(record.BeneficiaryID, "opg_", 32)
	case protocol.ExitAllocationDecisionNoTransfer:
		return record.OwnershipTransferID == "" &&
			record.OwnershipTransferCompletionEventIndex == 0 &&
			record.OwnershipTransferCompletionEventHash ==
				protocol.ExitAllocationZeroHash &&
			record.BeneficiaryType ==
				protocol.ExitAllocationBeneficiaryContract
	default:
		return false
	}
}

func validExitAllocationBeneficiaryID(value string) bool {
	if len(value) < 1 || len(value) > 120 ||
		protocol.HasCanonicalLineBreak(value) {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' ||
			character == '_' ||
			character == ':' ||
			character == '/' ||
			character == '-' {
			continue
		}
		return false
	}
	return true
}

func validExitAllocationConservation(
	record store.ExitAllocationRecord,
) bool {
	totals := make(map[string]int64)
	fractions := make(map[string]int64)
	for index, source := range record.SettlementSources {
		if source.BoundaryOrder != int64(index) ||
			!validHexID(source.SettlementID, "stl_", 32) ||
			!validExitAllocationCurrencyCode(source.CurrencyCode) ||
			source.FractionDigits < 0 ||
			source.FractionDigits > 9 ||
			source.Revision < 1 ||
			source.LedgerIndex < 1 ||
			!protocol.IsDigest(source.SettlementHash) ||
			!protocol.IsDigest(source.SourceFingerprint) ||
			!protocol.IsDigest(source.SettlementAllocationHash) ||
			!protocol.SettlementMinorAmountIsSafe(
				source.DistributableMinor,
			) {
			return false
		}
		fraction, exists := fractions[source.CurrencyCode]
		if exists && fraction != source.FractionDigits {
			return false
		}
		fractions[source.CurrencyCode] = source.FractionDigits
		current := totals[source.CurrencyCode]
		if current >
			protocol.SettlementMaximumSafeMinor-source.DistributableMinor {
			return false
		}
		totals[source.CurrencyCode] =
			current + source.DistributableMinor
	}
	if len(totals) != len(record.CurrencyAllocations) {
		return false
	}
	previousCode := ""
	for index, allocation := range record.CurrencyAllocations {
		total, exists := totals[allocation.CurrencyCode]
		if allocation.AllocationOrder != int64(index) ||
			!exists ||
			(index > 0 && allocation.CurrencyCode <= previousCode) ||
			allocation.FractionDigits !=
				fractions[allocation.CurrencyCode] ||
			allocation.DistributableMinor != total ||
			allocation.AllocatedMinor != total ||
			allocation.BeneficiaryType != record.BeneficiaryType ||
			allocation.BeneficiaryID != record.BeneficiaryID ||
			!protocol.SettlementMinorAmountIsSafe(
				allocation.AllocatedMinor,
			) {
			return false
		}
		previousCode = allocation.CurrencyCode
	}
	return true
}

func validExitAllocationCurrencyCode(value string) bool {
	if len(value) != 3 {
		return false
	}
	for _, character := range value {
		if character < 'A' || character > 'Z' {
			return false
		}
	}
	return true
}

func verifyExitAllocationDecisionBoundary(
	ctx context.Context,
	tx *sql.Tx,
	record store.ExitAllocationRecord,
) error {
	if record.ThroughOwnershipTransferEventIndex == 0 {
		if record.OwnershipTransferHeadHash !=
			protocol.OwnershipTransferZeroHash {
			return inconsistentMessage(
				"final exit allocation %s has an invalid empty ownership head",
				record.AllocationID,
			)
		}
	} else {
		head, err := scanOwnershipTransferEvent(tx.QueryRowContext(
			ctx,
			ownershipTransferEventSelect+`
			WHERE event_index = ?
			  AND event_hash = ?`,
			record.ThroughOwnershipTransferEventIndex,
			record.OwnershipTransferHeadHash,
		))
		if err != nil || head.AcceptedAt > record.CreatedAt {
			return inconsistentMessage(
				"final exit allocation %s has an invalid ownership head",
				record.AllocationID,
			)
		}
	}
	var conflictCount int
	selected := record.OwnershipTransferID
	if err := tx.QueryRowContext(ctx, `
		WITH ranked AS (
			SELECT
				event.transfer_id,
				event.resulting_status,
				ROW_NUMBER() OVER (
					PARTITION BY event.transfer_id
					ORDER BY event.event_index DESC
				) AS rank
			FROM ownership_transfer_events event
			WHERE event.event_index <= ?
		)
		SELECT COUNT(*)
		FROM ranked state
		JOIN ownership_transfers transfer
		  ON transfer.transfer_id = state.transfer_id
		WHERE state.rank = 1
		  AND transfer.target_deployment_id = ?
		  AND transfer.claim_action_id = ?
		  AND state.resulting_status IN ('prepared', 'approved', 'completed')
		  AND (? = '' OR transfer.transfer_id <> ?)`,
		record.ThroughOwnershipTransferEventIndex,
		record.TargetDeploymentID,
		record.ClaimActionID,
		selected,
		selected,
	).Scan(&conflictCount); err != nil {
		return inconsistent(
			"replay final exit allocation ownership decision",
			err,
		)
	}
	if conflictCount != 0 {
		return inconsistentMessage(
			"final exit allocation %s has conflicting ownership decisions at its boundary",
			record.AllocationID,
		)
	}
	var laterTransferCount int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM ownership_transfers transfer
		JOIN ownership_transfer_events event
		  ON event.transfer_id = transfer.transfer_id
		 AND event.action = 'prepare'
		WHERE transfer.exit_review_id = ?
		  AND event.event_index > ?`,
		record.ExitReviewID,
		record.ThroughOwnershipTransferEventIndex,
	).Scan(&laterTransferCount); err != nil {
		return inconsistent(
			"check transfers after final exit allocation",
			err,
		)
	}
	if laterTransferCount != 0 {
		return inconsistentMessage(
			"final exit allocation %s is followed by a forbidden ownership transfer",
			record.AllocationID,
		)
	}
	if record.DecisionMode ==
		protocol.ExitAllocationDecisionNoTransfer {
		return nil
	}
	transferRecord, err := ownershipTransferRecordByID(
		ctx,
		tx,
		record.OwnershipTransferID,
	)
	if err != nil {
		return inconsistent(
			"read final exit allocation ownership transfer",
			err,
		)
	}
	membership, found, err := ownershipTransferMembershipByTransfer(
		ctx,
		tx,
		record.OwnershipTransferID,
	)
	if err != nil || !found {
		return inconsistentMessage(
			"final exit allocation %s has no completed transfer membership",
			record.AllocationID,
		)
	}
	event, err := scanOwnershipTransferEvent(tx.QueryRowContext(
		ctx,
		ownershipTransferEventSelect+`
		WHERE event_index = ?
		  AND event_hash = ?`,
		record.OwnershipTransferCompletionEventIndex,
		record.OwnershipTransferCompletionEventHash,
	))
	if err != nil ||
		event.TransferID != record.OwnershipTransferID ||
		event.Action != protocol.OwnershipTransferActionComplete ||
		event.ResultingStatus != protocol.OwnershipTransferStatusCompleted ||
		event.EventIndex > record.ThroughOwnershipTransferEventIndex ||
		transferRecord.ExitReviewID != record.ExitReviewID ||
		transferRecord.TargetDeploymentID != record.TargetDeploymentID ||
		transferRecord.ClaimActionID != record.ClaimActionID ||
		transferRecord.SourceGroupID != record.SourceGroupID ||
		transferRecord.TargetGroupID != record.BeneficiaryID ||
		membership.CompletionEventIndex != event.EventIndex ||
		membership.CompletionEventHash != event.EventHash ||
		record.CreatedAt < event.AcceptedAt {
		return inconsistentMessage(
			"final exit allocation %s has an invalid completed transfer pin",
			record.AllocationID,
		)
	}
	return nil
}

func verifiedExitAllocationEvents(
	ctx context.Context,
	tx *sql.Tx,
	records map[string]store.ExitAllocationRecord,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) (map[int64]exitAllocationState, error) {
	rows, err := tx.QueryContext(
		ctx,
		exitAllocationEventSelect+" ORDER BY event_index",
	)
	if err != nil {
		return nil, inconsistent("read final exit allocation event chain", err)
	}
	defer rows.Close()
	states := make(map[int64]exitAllocationState)
	latest := make(map[string]store.ExitAllocationEvent)
	eventCounts := make(map[string]int)
	seenIdempotency := make(map[string]bool)
	expectedIndex := int64(1)
	previousHash := protocol.ExitAllocationZeroHash
	var previousAcceptedAt time.Time
	for rows.Next() {
		event, err := scanExitAllocationEvent(rows)
		if err != nil {
			return nil, inconsistent("scan final exit allocation event", err)
		}
		record, exists := records[event.AllocationID]
		acceptedAt, acceptedErr := time.Parse(
			time.RFC3339Nano,
			event.AcceptedAt,
		)
		if event.EventIndex != expectedIndex ||
			!validHexID(event.EventID, "xae_", 32) ||
			!exists ||
			event.RecordHash != record.RecordHash ||
			event.RegistryScope != registryScope ||
			event.RegistryKeyID != registryKeyID ||
			event.PreviousEventHash != previousHash ||
			!protocol.IsDigest(event.EvidenceHash) ||
			!protocol.IsDigest(event.PayloadHash) ||
			!protocol.IsDigest(event.EventHash) ||
			acceptedErr != nil ||
			(expectedIndex > 1 &&
				acceptedAt.Before(previousAcceptedAt)) ||
			seenIdempotency[event.IdempotencyKey] ||
			!validExitAllocationBeneficiaryID(event.ActorID) ||
			!validExitAllocationAuditText(event.Reference, 240) ||
			!validExitAllocationIdempotency(event.IdempotencyKey) {
			return nil, inconsistentMessage(
				"final exit allocation event %d has invalid metadata or ordering",
				event.EventIndex,
			)
		}
		prior, hasPrior := latest[event.AllocationID]
		if event.Action == protocol.ExitAllocationActionCreate {
			if hasPrior ||
				event.ResultingStatus !=
					protocol.ExitAllocationStatusRecorded ||
				event.ActorRole != protocol.ExitAllocationActorAllocator ||
				event.PreviousAllocationEventHash !=
					protocol.ExitAllocationZeroHash ||
				event.AcceptedAt != record.CreatedAt ||
				event.Reference != record.ContractReference ||
				event.EvidenceHash != record.EvidenceHash {
				return nil, inconsistentMessage(
					"final exit allocation %s has an invalid create event",
					event.AllocationID,
				)
			}
		} else if event.Action ==
			protocol.ExitAllocationActionVerify {
			if !hasPrior ||
				prior.ResultingStatus !=
					protocol.ExitAllocationStatusRecorded ||
				event.ResultingStatus !=
					protocol.ExitAllocationStatusVerifiedFinal ||
				event.ActorRole != protocol.ExitAllocationActorVerifier ||
				event.PreviousAllocationEventHash != prior.EventHash {
				return nil, inconsistentMessage(
					"final exit allocation %s has an invalid verify event",
					event.AllocationID,
				)
			}
		} else {
			return nil, inconsistentMessage(
				"final exit allocation event %d has an invalid action",
				event.EventIndex,
			)
		}
		expectedPayloadHash := protocol.Digest(
			protocol.ExitAllocationEventPayloadMessage(
				exitAllocationProtocolEvent(event),
			),
		)
		expectedEventHash := protocol.Digest(
			protocol.ExitAllocationEventHashMessage(
				exitAllocationProtocolEvent(event),
			),
		)
		if event.PayloadHash != expectedPayloadHash ||
			event.EventHash != expectedEventHash ||
			!ed25519.Verify(
				registryPublicKey,
				protocol.ExitAllocationEventReceiptMessage(
					exitAllocationProtocolEvent(event),
				),
				event.Signature,
			) {
			return nil, inconsistentMessage(
				"final exit allocation event %d hash/signature verification failed",
				event.EventIndex,
			)
		}
		eventCounts[event.AllocationID]++
		if eventCounts[event.AllocationID] > 2 {
			return nil, inconsistentMessage(
				"final exit allocation %s has too many events",
				event.AllocationID,
			)
		}
		states[event.EventIndex] =
			exitAllocationStateFromEvent(record, event)
		latest[event.AllocationID] = event
		seenIdempotency[event.IdempotencyKey] = true
		expectedIndex++
		previousHash = event.EventHash
		previousAcceptedAt = acceptedAt
	}
	if err := rows.Err(); err != nil {
		return nil, inconsistent("iterate final exit allocation event chain", err)
	}
	for allocationID := range records {
		if eventCounts[allocationID] < 1 {
			return nil, inconsistentMessage(
				"final exit allocation %s has no create event",
				allocationID,
			)
		}
	}
	return states, nil
}

func validExitAllocationAuditText(value string, maximum int) bool {
	return value != "" &&
		len(value) <= maximum &&
		!protocol.HasCanonicalLineBreak(value)
}

func validExitAllocationIdempotency(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func verifyExitAllocationStateRows(
	ctx context.Context,
	tx *sql.Tx,
	expected map[int64]exitAllocationState,
) error {
	rows, err := tx.QueryContext(
		ctx,
		exitAllocationStateSelect+" ORDER BY event_index",
	)
	if err != nil {
		return inconsistent("read final exit allocation query rows", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		actual, err := scanExitAllocationState(rows)
		if err != nil {
			return inconsistent("scan final exit allocation query row", err)
		}
		want, exists := expected[actual.EventIndex]
		if !exists || !reflect.DeepEqual(actual, want) {
			return inconsistentMessage(
				"final exit allocation query row %d does not match its event",
				actual.EventIndex,
			)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate final exit allocation query rows", err)
	}
	if count != len(expected) {
		return inconsistentMessage(
			"final exit allocation query row count is %d, expected %d",
			count,
			len(expected),
		)
	}
	return nil
}
