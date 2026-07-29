package sqlite

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func (sqliteStore *Store) VerifyRegistryCases(
	ctx context.Context,
	registryPublicKey []byte,
	registryKeyID string,
	registryScope string,
) error {
	if len(registryPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"%w: invalid registry public key for case verification",
			store.ErrInconsistentState,
		)
	}
	var identityCreatedAtValue string
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT created_at
		FROM registry_identity
		WHERE singleton = 1`).Scan(&identityCreatedAtValue); err != nil {
		return inconsistent("read registry identity for case verification", err)
	}
	identityCreatedAt, err := time.Parse(
		time.RFC3339Nano,
		identityCreatedAtValue,
	)
	if err != nil || !validPersistedTimestamp(identityCreatedAtValue) {
		return fmt.Errorf(
			"%w: registry identity timestamp is invalid for case verification",
			store.ErrInconsistentState,
		)
	}
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		registryCaseEventSelect+" ORDER BY event_index",
	)
	if err != nil {
		return inconsistent("read registry case event chain", err)
	}
	defer rows.Close()

	expectedCases := make(map[string]store.RegistryCase)
	expectedIndex := int64(1)
	previousHash := protocol.RegistryCaseZeroHash
	var previousAcceptedAt time.Time
	for rows.Next() {
		event, scanErr := scanRegistryCaseEvent(rows)
		if scanErr != nil {
			return inconsistent("scan registry case event chain", scanErr)
		}
		acceptedAt, parseErr := time.Parse(
			time.RFC3339Nano,
			event.AcceptedAt,
		)
		if parseErr != nil ||
			!validPersistedTimestamp(event.AcceptedAt) ||
			acceptedAt.Before(identityCreatedAt) ||
			(!previousAcceptedAt.IsZero() && acceptedAt.Before(previousAcceptedAt)) {
			return fmt.Errorf(
				"%w: registry case event timestamps are not canonical and monotonic",
				store.ErrInconsistentState,
			)
		}
		if event.EventIndex != expectedIndex ||
			event.PreviousEventHash != previousHash ||
			event.RegistryScope != registryScope ||
			event.RegistryKeyID != registryKeyID ||
			!protocol.IsDigest(event.EvidenceHash) ||
			!protocol.IsDigest(event.PayloadHash) ||
			!validHexID(event.EventID, "cse_", 32) ||
			!validHexID(event.CaseID, "case_", 32) ||
			!validRegistryCaseSubjectID(
				event.SubjectType,
				event.SubjectID,
			) ||
			!validRegistryCaseCategory(event.Category) ||
			!validRegistryCaseText(event.Reference, 240) ||
			!validRegistryCaseText(event.ActorID, 120) ||
			!validRegistryCaseToken(event.IdempotencyKey) {
			return fmt.Errorf(
				"%w: registry case event %d has invalid immutable fields",
				store.ErrInconsistentState,
				event.EventIndex,
			)
		}
		expectedPayloadHash := protocol.Digest(
			protocol.RegistryCasePayloadMessage(
				event.Action,
				event.CaseID,
				event.SubjectType,
				event.SubjectID,
				event.Category,
				event.Severity,
				event.EvidenceHash,
				event.Reference,
				event.ActorID,
			),
		)
		if event.PayloadHash != expectedPayloadHash {
			return fmt.Errorf(
				"%w: registry case event %d payload hash differs",
				store.ErrInconsistentState,
				event.EventIndex,
			)
		}
		protocolEvent := registryCaseProtocolEvent(event)
		expectedEventHash := protocol.Digest(
			protocol.RegistryCaseEventHashMessage(protocolEvent),
		)
		if event.EventHash != expectedEventHash ||
			!ed25519.Verify(
				ed25519.PublicKey(registryPublicKey),
				protocol.RegistryCaseEventReceiptMessage(protocolEvent),
				event.Signature,
			) {
			return fmt.Errorf(
				"%w: registry case event %d hash or signature differs",
				store.ErrInconsistentState,
				event.EventIndex,
			)
		}

		current, exists := expectedCases[event.CaseID]
		switch event.Action {
		case protocol.RegistryCaseActionFlag:
			if exists || !validRegistryCaseSubject(event.SubjectType) ||
				!validRegistryCaseSeverity(event.Severity) {
				return fmt.Errorf(
					"%w: registry case flag event %d has invalid semantics",
					store.ErrInconsistentState,
					event.EventIndex,
				)
			}
			expectedCases[event.CaseID] = store.RegistryCase{
				CaseID:           event.CaseID,
				Status:           protocol.RegistryCaseStatusOpen,
				SubjectType:      event.SubjectType,
				SubjectID:        event.SubjectID,
				Category:         event.Category,
				Severity:         event.Severity,
				FlagEvidenceHash: event.EvidenceHash,
				FlagReference:    event.Reference,
				FlagActorID:      event.ActorID,
				FlaggedAt:        event.AcceptedAt,
				FlagEventIndex:   event.EventIndex,
				FlagEventHash:    event.EventHash,
				LatestEventIndex: event.EventIndex,
				LatestEventHash:  event.EventHash,
			}
		case protocol.RegistryCaseActionClear:
			if !exists ||
				current.Status != protocol.RegistryCaseStatusOpen ||
				current.SubjectType != event.SubjectType ||
				current.SubjectID != event.SubjectID ||
				current.Category != event.Category ||
				current.Severity != event.Severity {
				return fmt.Errorf(
					"%w: registry case clear event %d has invalid semantics",
					store.ErrInconsistentState,
					event.EventIndex,
				)
			}
			current.Status = protocol.RegistryCaseStatusCleared
			current.ClearEvidenceHash = event.EvidenceHash
			current.ClearReference = event.Reference
			current.ClearActorID = event.ActorID
			current.ClearedAt = event.AcceptedAt
			current.ClearEventIndex = event.EventIndex
			current.ClearEventHash = event.EventHash
			current.LatestEventIndex = event.EventIndex
			current.LatestEventHash = event.EventHash
			expectedCases[event.CaseID] = current
		default:
			return fmt.Errorf(
				"%w: registry case event %d action is invalid",
				store.ErrInconsistentState,
				event.EventIndex,
			)
		}
		expectedIndex++
		previousHash = event.EventHash
		previousAcceptedAt = acceptedAt
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return inconsistent("iterate registry case event chain", err)
	}
	if err := rows.Close(); err != nil {
		return inconsistent("close registry case event chain", err)
	}
	for _, item := range expectedCases {
		exists, lookupErr := registryCaseSubjectExists(
			ctx,
			sqliteStore.db,
			item.SubjectType,
			item.SubjectID,
		)
		if lookupErr != nil || !exists {
			return fmt.Errorf(
				"%w: registry case %q references a missing subject",
				store.ErrInconsistentState,
				item.CaseID,
			)
		}
	}
	return sqliteStore.verifyRegistryCaseQueryRows(ctx, expectedCases)
}

func (sqliteStore *Store) verifyRegistryCaseQueryRows(
	ctx context.Context,
	expected map[string]store.RegistryCase,
) error {
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		registryCaseSelect+" ORDER BY case_id",
	)
	if err != nil {
		return inconsistent("read registry case query rows", err)
	}
	defer rows.Close()
	seen := make(map[string]bool, len(expected))
	for rows.Next() {
		actual, scanErr := scanRegistryCase(rows)
		if scanErr != nil {
			return inconsistent("scan registry case query row", scanErr)
		}
		expectedRow, exists := expected[actual.CaseID]
		if !exists || !sameRegistryCase(actual, expectedRow) {
			return fmt.Errorf(
				"%w: registry case query row %q differs from its audit events",
				store.ErrInconsistentState,
				actual.CaseID,
			)
		}
		seen[actual.CaseID] = true
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate registry case query rows", err)
	}
	if len(seen) != len(expected) {
		return fmt.Errorf(
			"%w: registry case query rows are incomplete",
			store.ErrInconsistentState,
		)
	}
	return nil
}

func sameRegistryCase(left, right store.RegistryCase) bool {
	return left.CaseID == right.CaseID &&
		left.Status == right.Status &&
		left.SubjectType == right.SubjectType &&
		left.SubjectID == right.SubjectID &&
		left.Category == right.Category &&
		left.Severity == right.Severity &&
		left.FlagEvidenceHash == right.FlagEvidenceHash &&
		left.FlagReference == right.FlagReference &&
		left.FlagActorID == right.FlagActorID &&
		left.FlaggedAt == right.FlaggedAt &&
		left.FlagEventIndex == right.FlagEventIndex &&
		left.FlagEventHash == right.FlagEventHash &&
		left.ClearEvidenceHash == right.ClearEvidenceHash &&
		left.ClearReference == right.ClearReference &&
		left.ClearActorID == right.ClearActorID &&
		left.ClearedAt == right.ClearedAt &&
		left.ClearEventIndex == right.ClearEventIndex &&
		left.ClearEventHash == right.ClearEventHash &&
		left.LatestEventIndex == right.LatestEventIndex &&
		left.LatestEventHash == right.LatestEventHash
}

func validRegistryCaseSubject(subjectType string) bool {
	switch subjectType {
	case protocol.RegistryCaseSubjectDeployment,
		protocol.RegistryCaseSubjectClaim,
		protocol.RegistryCaseSubjectGroup,
		protocol.RegistryCaseSubjectQMAU,
		protocol.RegistryCaseSubjectRevenue,
		protocol.RegistryCaseSubjectLedger:
		return true
	default:
		return false
	}
}

func validRegistryCaseSeverity(severity string) bool {
	switch severity {
	case protocol.RegistryCaseSeverityInfo,
		protocol.RegistryCaseSeverityWarning,
		protocol.RegistryCaseSeverityCritical:
		return true
	default:
		return false
	}
}

func validRegistryCaseSubjectID(subjectType, subjectID string) bool {
	switch subjectType {
	case protocol.RegistryCaseSubjectDeployment:
		return validHexID(subjectID, "dep_", 32)
	case protocol.RegistryCaseSubjectClaim:
		return validHexID(subjectID, "opa_", 32)
	case protocol.RegistryCaseSubjectGroup:
		return validHexID(subjectID, "opg_", 32)
	case protocol.RegistryCaseSubjectQMAU:
		return validHexID(subjectID, "batch_", 32)
	case protocol.RegistryCaseSubjectRevenue:
		return validHexID(subjectID, "revbatch_", 32)
	case protocol.RegistryCaseSubjectLedger:
		index, err := strconv.ParseInt(subjectID, 10, 64)
		return err == nil &&
			index > 0 &&
			strconv.FormatInt(index, 10) == subjectID
	default:
		return false
	}
}

func validRegistryCaseCategory(category string) bool {
	if len(category) < 3 || len(category) > 64 ||
		category[0] < 'a' || category[0] > 'z' {
		return false
	}
	for _, character := range category[1:] {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '-' {
			return false
		}
	}
	return true
}

func validRegistryCaseText(value string, maximum int) bool {
	return utf8.ValidString(value) &&
		len(value) >= 1 &&
		len(value) <= maximum &&
		strings.TrimSpace(value) == value &&
		!protocol.HasCanonicalLineBreak(value)
}

func validRegistryCaseToken(value string) bool {
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
