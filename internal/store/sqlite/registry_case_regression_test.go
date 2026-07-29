package sqlite

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const (
	registryCaseRegressionScope      = "example:registry-case-regression"
	registryCaseRegressionDeployment = "dep_00000000000000000000000000000001"
)

type registryCaseRegressionFixture struct {
	store          *Store
	privateKey     ed25519.PrivateKey
	publicKey      ed25519.PublicKey
	registryKeyID  string
	nextCaseID     int
	nextEventID    int
	nextAcceptedAt int
}

func TestRegistryCaseSubjectsAcceptClaimsAndGroupsOnlyAtClaimBoundaries(
	t *testing.T,
) {
	fixture := newRegistryCaseRegressionFixture(t)
	const (
		directClaimAction  = "opa_11111111111111111111111111111111"
		derivedClaimAction = "opa_22222222222222222222222222222222"
		unrelatedRedeem    = "opa_33333333333333333333333333333333"
		claimGroupID       = "opg_11111111111111111111111111111111"
		effectiveGroupID   = "opg_22222222222222222222222222222222"
	)

	insertRegistryCaseOperatorEvent(
		t,
		fixture.store,
		1,
		directClaimAction,
		protocol.OperatorActionClaim,
		protocol.OperatorClaimStatePendingReview,
		"Direct Cooperative",
		claimGroupID,
		"",
		"",
		"",
	)
	insertRegistryCaseOperatorState(
		t,
		fixture.store,
		1,
		directClaimAction,
		claimGroupID,
		effectiveGroupID,
		"sha256:operator-case-audit-1",
	)
	insertRegistryCaseOperatorEvent(
		t,
		fixture.store,
		2,
		derivedClaimAction,
		protocol.OperatorActionRedeemClientToken,
		protocol.OperatorClaimStatePendingReview,
		"Derived Cooperative",
		claimGroupID,
		"",
		directClaimAction,
		protocol.Digest([]byte("private-claim-record")),
	)
	insertRegistryCaseOperatorEvent(
		t,
		fixture.store,
		3,
		unrelatedRedeem,
		protocol.OperatorActionRedeemClientToken,
		protocol.OperatorClaimStateClaimed,
		"",
		claimGroupID,
		"opl_33333333333333333333333333333333",
		"",
		"",
	)

	for _, subject := range []struct {
		name        string
		subjectType string
		subjectID   string
	}{
		{
			name:        "direct claim action",
			subjectType: protocol.RegistryCaseSubjectClaim,
			subjectID:   directClaimAction,
		},
		{
			name:        "token-derived pending claim action",
			subjectType: protocol.RegistryCaseSubjectClaim,
			subjectID:   derivedClaimAction,
		},
		{
			name:        "profile claim group",
			subjectType: protocol.RegistryCaseSubjectGroup,
			subjectID:   claimGroupID,
		},
		{
			name:        "effective linked group",
			subjectType: protocol.RegistryCaseSubjectGroup,
			subjectID:   effectiveGroupID,
		},
	} {
		t.Run(subject.name, func(t *testing.T) {
			exists, err := registryCaseSubjectExists(
				context.Background(),
				fixture.store.db,
				subject.subjectType,
				subject.subjectID,
			)
			if err != nil {
				t.Fatalf("check registry case subject: %v", err)
			}
			if !exists {
				t.Fatalf(
					"subject %s %q was not recognized",
					subject.subjectType,
					subject.subjectID,
				)
			}
		})
	}

	exists, err := registryCaseSubjectExists(
		context.Background(),
		fixture.store.db,
		protocol.RegistryCaseSubjectClaim,
		unrelatedRedeem,
	)
	if err != nil {
		t.Fatalf("check unrelated redemption: %v", err)
	}
	if exists {
		t.Fatal("ordinary linked-token redemption was accepted as a claim subject")
	}
}

func TestRegistryCaseFlagRetryAfterClearReturnsOriginalEventAndCurrentState(
	t *testing.T,
) {
	fixture := newRegistryCaseRegressionFixture(t)
	flagInput := fixture.registryCaseFlagInput(
		registryCaseRegressionDeployment,
		"case-idempotency",
	)
	flagEvent, flaggedCase, duplicate, err := fixture.store.AppendRegistryCaseEvent(
		context.Background(),
		flagInput,
		fixture.signRegistryCaseEvent,
	)
	if err != nil || duplicate {
		t.Fatalf(
			"append initial registry case flag: duplicate=%t, error=%v",
			duplicate,
			err,
		)
	}

	clearInput := fixture.registryCaseClearInput(
		flaggedCase,
		"clear-idempotency",
	)
	_, clearedCase, duplicate, err := fixture.store.AppendRegistryCaseEvent(
		context.Background(),
		clearInput,
		fixture.signRegistryCaseEvent,
	)
	if err != nil || duplicate ||
		clearedCase.Status != protocol.RegistryCaseStatusCleared {
		t.Fatalf(
			"clear registry case: duplicate=%t, case=%+v, error=%v",
			duplicate,
			clearedCase,
			err,
		)
	}

	retryEvent, retryCase, duplicate, err := fixture.store.AppendRegistryCaseEvent(
		context.Background(),
		flagInput,
		fixture.signRegistryCaseEvent,
	)
	if err != nil || !duplicate {
		t.Fatalf(
			"retry cleared registry case flag: duplicate=%t, error=%v",
			duplicate,
			err,
		)
	}
	if retryEvent.EventIndex != flagEvent.EventIndex ||
		retryEvent.EventID != flagEvent.EventID ||
		retryEvent.EventHash != flagEvent.EventHash ||
		!equalBytes(retryEvent.Signature, flagEvent.Signature) {
		t.Fatalf(
			"idempotent retry did not return the original signed event: got=%+v want=%+v",
			retryEvent,
			flagEvent,
		)
	}
	if retryCase.Status != protocol.RegistryCaseStatusCleared ||
		retryCase.ClearEventIndex != clearedCase.ClearEventIndex ||
		retryCase.LatestEventHash != clearedCase.LatestEventHash {
		t.Fatalf(
			"idempotent retry returned stale case state: got=%+v want=%+v",
			retryCase,
			clearedCase,
		)
	}

	conflicting := flagInput
	conflicting.Reference = "review:changed-payload"
	conflicting.PayloadHash = registryCasePayloadHash(conflicting)
	_, _, _, err = fixture.store.AppendRegistryCaseEvent(
		context.Background(),
		conflicting,
		fixture.signRegistryCaseEvent,
	)
	if !errors.Is(err, store.ErrIdempotencyConflict) {
		t.Fatalf("changed idempotent payload error = %v, want conflict", err)
	}
}

func TestRegistryCasePaginationRemainsStableWhenUnseenCaseIsCleared(
	t *testing.T,
) {
	fixture := newRegistryCaseRegressionFixture(t)
	flagged := make([]store.RegistryCase, 0, 3)
	for index := 1; index <= 3; index++ {
		input := fixture.registryCaseFlagInput(
			registryCaseRegressionDeployment,
			fmt.Sprintf("case-pagination-%d", index),
		)
		_, item, duplicate, err := fixture.store.AppendRegistryCaseEvent(
			context.Background(),
			input,
			fixture.signRegistryCaseEvent,
		)
		if err != nil || duplicate {
			t.Fatalf(
				"append pagination flag %d: duplicate=%t, error=%v",
				index,
				duplicate,
				err,
			)
		}
		flagged = append(flagged, item)
	}

	firstPage, err := fixture.store.RegistryCases(
		context.Background(),
		store.RegistryCaseQuery{Limit: 2},
	)
	if err != nil {
		t.Fatalf("read first registry-case page: %v", err)
	}
	if len(firstPage.Items) != 2 ||
		firstPage.Items[0].CaseID != flagged[2].CaseID ||
		firstPage.Items[1].CaseID != flagged[1].CaseID ||
		firstPage.NextEventIndex != flagged[1].FlagEventIndex {
		t.Fatalf("unexpected first registry-case page: %+v", firstPage)
	}

	clearInput := fixture.registryCaseClearInput(
		flagged[0],
		"clear-between-pages",
	)
	if _, _, _, err := fixture.store.AppendRegistryCaseEvent(
		context.Background(),
		clearInput,
		fixture.signRegistryCaseEvent,
	); err != nil {
		t.Fatalf("clear case between pages: %v", err)
	}

	secondPage, err := fixture.store.RegistryCases(
		context.Background(),
		store.RegistryCaseQuery{
			Limit:            2,
			BeforeEventIndex: firstPage.NextEventIndex,
		},
	)
	if err != nil {
		t.Fatalf("read second registry-case page: %v", err)
	}
	if len(secondPage.Items) != 1 ||
		secondPage.Items[0].CaseID != flagged[0].CaseID ||
		secondPage.Items[0].Status != protocol.RegistryCaseStatusCleared ||
		secondPage.NextEventIndex != 0 {
		t.Fatalf(
			"clear between pages skipped or duplicated a case: %+v",
			secondPage,
		)
	}
}

func TestVerifyRegistryCasesRejectsEventAndQueryTamperingWithoutLeakingConnection(
	t *testing.T,
) {
	t.Run("immutable event", func(t *testing.T) {
		fixture := newRegistryCaseRegressionFixture(t)
		fixture.appendDeploymentCase(t, "case-event-tamper")
		fixture.verifyRegistryCases(t)

		if _, err := fixture.store.db.Exec(
			"DROP TRIGGER registry_case_events_no_update",
		); err != nil {
			t.Fatalf("drop event update trigger for corruption test: %v", err)
		}
		if _, err := fixture.store.db.Exec(`
			UPDATE registry_case_events
			SET reference = 'review:tampered'
			WHERE event_index = 1`); err != nil {
			t.Fatalf("tamper registry case event: %v", err)
		}
		if err := fixture.store.VerifyRegistryCases(
			context.Background(),
			fixture.publicKey,
			fixture.registryKeyID,
			registryCaseRegressionScope,
		); !errors.Is(err, store.ErrInconsistentState) {
			t.Fatalf("event tamper verification error = %v", err)
		}
		assertRegistryCaseConnectionAvailable(t, fixture.store)
	})

	t.Run("current query row", func(t *testing.T) {
		fixture := newRegistryCaseRegressionFixture(t)
		item := fixture.appendDeploymentCase(t, "case-query-tamper")
		fixture.verifyRegistryCases(t)

		if _, err := fixture.store.db.Exec(`
			UPDATE registry_cases
			SET flag_reference = 'review:tampered'
			WHERE case_id = ?`,
			item.CaseID,
		); err != nil {
			t.Fatalf("tamper registry case query row: %v", err)
		}
		if err := fixture.store.VerifyRegistryCases(
			context.Background(),
			fixture.publicKey,
			fixture.registryKeyID,
			registryCaseRegressionScope,
		); !errors.Is(err, store.ErrInconsistentState) {
			t.Fatalf("query-row tamper verification error = %v", err)
		}
		assertRegistryCaseConnectionAvailable(t, fixture.store)
	})
}

func TestRegistryCaseMigrationAppliesToVersionElevenDatabase(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "registry.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatalf("open version-eleven database: %v", err)
	}
	if _, err := database.Exec("PRAGMA foreign_keys = ON"); err != nil {
		database.Close()
		t.Fatalf("enable version-eleven foreign keys: %v", err)
	}
	if _, err := database.Exec(`
		CREATE TABLE schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TEXT NOT NULL DEFAULT (
				strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
			)
		)`); err != nil {
		database.Close()
		t.Fatalf("create version-eleven migration table: %v", err)
	}
	for version := 1; version <= 11; version++ {
		name := fmt.Sprintf("%04d_", version)
		entries, readErr := migrationFiles.ReadDir("migrations")
		if readErr != nil {
			database.Close()
			t.Fatalf("list migrations: %v", readErr)
		}
		migrationName := ""
		for _, entry := range entries {
			if len(entry.Name()) >= len(name) &&
				entry.Name()[:len(name)] == name {
				migrationName = entry.Name()
				break
			}
		}
		if migrationName == "" {
			database.Close()
			t.Fatalf("migration version %d was not found", version)
		}
		contents, readErr := migrationFiles.ReadFile(
			"migrations/" + migrationName,
		)
		if readErr != nil {
			database.Close()
			t.Fatalf("read migration %s: %v", migrationName, readErr)
		}
		transaction, beginErr := database.Begin()
		if beginErr != nil {
			database.Close()
			t.Fatalf("begin migration %s: %v", migrationName, beginErr)
		}
		if _, execErr := transaction.Exec(string(contents)); execErr != nil {
			transaction.Rollback()
			database.Close()
			t.Fatalf("apply migration %s: %v", migrationName, execErr)
		}
		if _, execErr := transaction.Exec(
			"INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
			version,
			migrationName,
		); execErr != nil {
			transaction.Rollback()
			database.Close()
			t.Fatalf("record migration %s: %v", migrationName, execErr)
		}
		if commitErr := transaction.Commit(); commitErr != nil {
			database.Close()
			t.Fatalf("commit migration %s: %v", migrationName, commitErr)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close version-eleven database: %v", err)
	}

	registryStore, err := Open(databasePath)
	if err != nil {
		t.Fatalf("migrate version-eleven registry database: %v", err)
	}
	defer registryStore.Close()

	for _, table := range []string{"registry_case_events", "registry_cases"} {
		var count int
		if err := registryStore.db.QueryRow(`
			SELECT COUNT(*)
			FROM sqlite_master
			WHERE type = 'table' AND name = ?`,
			table,
		).Scan(&count); err != nil {
			t.Fatalf("find migrated table %s: %v", table, err)
		}
		if count != 1 {
			t.Fatalf("migrated table %s count = %d, want 1", table, count)
		}
	}
	var recorded int
	if err := registryStore.db.QueryRow(`
		SELECT COUNT(*)
		FROM schema_migrations
		WHERE version = 12 AND name = '0012_registry_cases.sql'`,
	).Scan(&recorded); err != nil {
		t.Fatalf("read registry-case migration record: %v", err)
	}
	if recorded != 1 {
		t.Fatalf("registry-case migration record count = %d, want 1", recorded)
	}
}

func newRegistryCaseRegressionFixture(
	t *testing.T,
) *registryCaseRegressionFixture {
	t.Helper()
	registryStore, err := Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatalf("open registry-case SQLite store: %v", err)
	}
	t.Cleanup(func() {
		if err := registryStore.Close(); err != nil {
			t.Errorf("close registry-case SQLite store: %v", err)
		}
	})

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate registry-case signing key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("encode registry-case public key: %v", err)
	}
	registryKeyID := protocol.RegistryKeyID(publicKeyDER)
	if err := registryStore.EnsureRegistryIdentity(
		context.Background(),
		store.RegistryIdentity{
			ProtocolVersion: protocol.Version,
			RegistryScope:   registryCaseRegressionScope,
			RegistryKeyID:   registryKeyID,
			PublicKeyDER:    publicKeyDER,
			CreatedAt:       "2026-07-28T00:00:00Z",
		},
	); err != nil {
		t.Fatalf("seed registry-case identity: %v", err)
	}
	insertRegistryCaseDeployment(
		t,
		registryStore,
		registryCaseRegressionDeployment,
	)
	return &registryCaseRegressionFixture{
		store:          registryStore,
		privateKey:     privateKey,
		publicKey:      publicKey,
		registryKeyID:  registryKeyID,
		nextCaseID:     1,
		nextEventID:    1,
		nextAcceptedAt: 1,
	}
}

func (fixture *registryCaseRegressionFixture) registryCaseFlagInput(
	subjectID string,
	suffix string,
) store.RegistryCaseEventInput {
	input := store.RegistryCaseEventInput{
		Action:           protocol.RegistryCaseActionFlag,
		CaseID:           fmt.Sprintf("case_%032x", fixture.nextCaseID),
		SubjectType:      protocol.RegistryCaseSubjectDeployment,
		SubjectID:        subjectID,
		Category:         "qmau-anomaly",
		Severity:         protocol.RegistryCaseSeverityWarning,
		EvidenceHash:     protocol.RegistryCaseZeroHash,
		Reference:        "review:" + suffix,
		ActorID:          "registry-case-regression",
		IdempotencyKey:   "flag-" + suffix,
		CandidateEventID: fmt.Sprintf("cse_%032x", fixture.nextEventID),
		AcceptedAt: time.Date(
			2026,
			time.July,
			28,
			0,
			0,
			fixture.nextAcceptedAt,
			0,
			time.UTC,
		).Format(time.RFC3339),
		RegistryScope: registryCaseRegressionScope,
		RegistryKeyID: fixture.registryKeyID,
	}
	input.PayloadHash = registryCasePayloadHash(input)
	fixture.nextCaseID++
	fixture.nextEventID++
	fixture.nextAcceptedAt++
	return input
}

func (fixture *registryCaseRegressionFixture) registryCaseClearInput(
	item store.RegistryCase,
	suffix string,
) store.RegistryCaseEventInput {
	input := store.RegistryCaseEventInput{
		Action:           protocol.RegistryCaseActionClear,
		CaseID:           item.CaseID,
		SubjectType:      item.SubjectType,
		SubjectID:        item.SubjectID,
		Category:         item.Category,
		Severity:         item.Severity,
		EvidenceHash:     protocol.RegistryCaseZeroHash,
		Reference:        "resolution:" + suffix,
		ActorID:          "registry-case-regression",
		IdempotencyKey:   "clear-" + suffix,
		CandidateEventID: fmt.Sprintf("cse_%032x", fixture.nextEventID),
		AcceptedAt: time.Date(
			2026,
			time.July,
			28,
			0,
			0,
			fixture.nextAcceptedAt,
			0,
			time.UTC,
		).Format(time.RFC3339),
		RegistryScope: registryCaseRegressionScope,
		RegistryKeyID: fixture.registryKeyID,
	}
	input.PayloadHash = registryCasePayloadHash(input)
	fixture.nextEventID++
	fixture.nextAcceptedAt++
	return input
}

func (fixture *registryCaseRegressionFixture) signRegistryCaseEvent(
	event store.RegistryCaseEvent,
) ([]byte, error) {
	return ed25519.Sign(
		fixture.privateKey,
		protocol.RegistryCaseEventReceiptMessage(
			registryCaseProtocolEvent(event),
		),
	), nil
}

func (fixture *registryCaseRegressionFixture) appendDeploymentCase(
	t *testing.T,
	suffix string,
) store.RegistryCase {
	t.Helper()
	input := fixture.registryCaseFlagInput(
		registryCaseRegressionDeployment,
		suffix,
	)
	_, item, duplicate, err := fixture.store.AppendRegistryCaseEvent(
		context.Background(),
		input,
		fixture.signRegistryCaseEvent,
	)
	if err != nil || duplicate {
		t.Fatalf(
			"append registry case: duplicate=%t, error=%v",
			duplicate,
			err,
		)
	}
	return item
}

func (fixture *registryCaseRegressionFixture) verifyRegistryCases(t *testing.T) {
	t.Helper()
	if err := fixture.store.VerifyRegistryCases(
		context.Background(),
		fixture.publicKey,
		fixture.registryKeyID,
		registryCaseRegressionScope,
	); err != nil {
		t.Fatalf("verify registry cases: %v", err)
	}
}

func registryCasePayloadHash(input store.RegistryCaseEventInput) string {
	return protocol.Digest(protocol.RegistryCasePayloadMessage(
		input.Action,
		input.CaseID,
		input.SubjectType,
		input.SubjectID,
		input.Category,
		input.Severity,
		input.EvidenceHash,
		input.Reference,
		input.ActorID,
	))
}

func insertRegistryCaseDeployment(
	t *testing.T,
	registryStore *Store,
	deploymentID string,
) {
	t.Helper()
	signature := make([]byte, ed25519.SignatureSize)
	_, _, err := registryStore.RegisterDeployment(
		context.Background(),
		store.RegistrationInput{
			SignerFingerprint: "sha256:" +
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Nonce:          "nonce-registry-case-" + deploymentID,
			IdempotencyKey: "register-registry-case-" + deploymentID,
			PayloadHash: "sha256:" +
				"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			RequestHash: "sha256:" +
				"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			RequestTimestamp:          "2026-07-28T00:00:00Z",
			RequestSignature:          signature,
			PublicKeyDER:              []byte("deployment-public-key"),
			KeyAlgorithm:              protocol.KeyAlgorithmEd25519,
			SoftwareVersion:           "registry-case-regression",
			CandidateDeploymentID:     deploymentID,
			CandidateRegisteredAt:     "2026-07-28T00:00:01Z",
			CandidateReceiptSignature: signature,
		},
	)
	if err != nil {
		t.Fatalf("seed registry-case deployment: %v", err)
	}
}

func insertRegistryCaseOperatorEvent(
	t *testing.T,
	registryStore *Store,
	auditIndex int64,
	actionID string,
	actionType string,
	claimState string,
	operatorName string,
	groupID string,
	linkID string,
	sourceClaimActionID string,
	sourcePrivateRecordHash string,
) {
	t.Helper()
	signature := make([]byte, ed25519.SignatureSize)
	auditHash := fmt.Sprintf("sha256:operator-case-audit-%d", auditIndex)
	_, err := registryStore.db.Exec(`
		INSERT INTO operator_audit_events (
			audit_index,
			action_id,
			deployment_id,
			subject_deployment_id,
			related_deployment_id,
			action_type,
			request_timestamp,
			request_nonce,
			idempotency_key,
			payload_hash,
			request_hash,
			deployment_signature,
			operator_name,
			operator_avatar_url,
			claim_state,
			group_id,
			link_id,
			token_id,
			client_token_hash,
			token_ttl_seconds,
			token_expires_at,
			accepted_at,
			previous_audit_hash,
			audit_hash,
			registry_key_id,
			receipt_signature,
			source_claim_action_id,
			source_private_record_hash
		) VALUES (
			?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?,
			?, ?, 0, '', ?, ?, ?, ?, ?, ?, ?
		)`,
		auditIndex,
		actionID,
		registryCaseRegressionDeployment,
		registryCaseRegressionDeployment,
		actionType,
		fmt.Sprintf("2026-07-28T00:01:%02dZ", auditIndex),
		fmt.Sprintf("nonce-operator-case-%d", auditIndex),
		fmt.Sprintf("idempotency-operator-case-%d", auditIndex),
		protocol.Digest([]byte(fmt.Sprintf("operator-case-payload-%d", auditIndex))),
		protocol.Digest([]byte(fmt.Sprintf("operator-case-request-%d", auditIndex))),
		signature,
		operatorName,
		claimState,
		groupID,
		linkID,
		fmt.Sprintf("opt_%032x", auditIndex),
		protocol.Digest([]byte(fmt.Sprintf("operator-case-token-%d", auditIndex))),
		fmt.Sprintf("2026-07-28T00:02:%02dZ", auditIndex),
		protocol.ZeroHash,
		auditHash,
		"registry-case-regression-key",
		signature,
		sourceClaimActionID,
		sourcePrivateRecordHash,
	)
	if err != nil {
		t.Fatalf("insert operator case event %s: %v", actionID, err)
	}
}

func insertRegistryCaseOperatorState(
	t *testing.T,
	registryStore *Store,
	auditIndex int64,
	actionID string,
	claimGroupID string,
	effectiveGroupID string,
	sourceAuditHash string,
) {
	t.Helper()
	if _, err := registryStore.db.Exec(`
		INSERT INTO operator_network_state_rows (
			audit_index,
			action_id,
			deployment_id,
			claimed,
			active,
			claim_state,
			claim_state_audit_index,
			profile_claim_audit_index,
			claim_group_id,
			effective_group_id,
			operator_name,
			operator_avatar_url,
			profile_claim_state,
			link_id,
			related_deployment_id,
			source_audit_hash,
			accepted_at
		) VALUES (
			?, ?, ?, 1, 1, 'pending-review', ?, ?, ?, ?,
			'Direct Cooperative', '', 'pending-review', '', '', ?, ?
		)`,
		auditIndex,
		actionID,
		registryCaseRegressionDeployment,
		auditIndex,
		auditIndex,
		claimGroupID,
		effectiveGroupID,
		sourceAuditHash,
		fmt.Sprintf("2026-07-28T00:01:%02dZ", auditIndex),
	); err != nil {
		t.Fatalf("insert operator case state %s: %v", actionID, err)
	}
}

func assertRegistryCaseConnectionAvailable(t *testing.T, registryStore *Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := registryStore.db.PingContext(ctx); err != nil {
		t.Fatalf("registry case verifier leaked its SQLite connection: %v", err)
	}
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
