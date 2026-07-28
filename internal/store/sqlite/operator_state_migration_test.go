package sqlite

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestOperatorNetworkStateMigrationBackfillsHistoricalBoundaries(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "registry.db")
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatalf("open pre-state-model database: %v", err)
	}
	if _, err := database.Exec("PRAGMA foreign_keys = ON"); err != nil {
		database.Close()
		t.Fatalf("enable pre-state-model foreign keys: %v", err)
	}
	if _, err := database.Exec(`
		CREATE TABLE schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
		)`); err != nil {
		database.Close()
		t.Fatalf("create pre-state-model migration table: %v", err)
	}
	for _, migration := range []struct {
		version int
		name    string
	}{
		{version: 1, name: "0001_initial.sql"},
		{version: 2, name: "0002_operator_network.sql"},
		{version: 3, name: "0003_announcements.sql"},
		{version: 4, name: "0004_operator_claim_verification.sql"},
	} {
		contents, err := migrationFiles.ReadFile("migrations/" + migration.name)
		if err != nil {
			database.Close()
			t.Fatalf("read migration %s: %v", migration.name, err)
		}
		transaction, err := database.Begin()
		if err != nil {
			database.Close()
			t.Fatalf("begin migration %s: %v", migration.name, err)
		}
		if _, err := transaction.Exec(string(contents)); err != nil {
			transaction.Rollback()
			database.Close()
			t.Fatalf("apply migration %s: %v", migration.name, err)
		}
		if _, err := transaction.Exec(
			"INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
			migration.version,
			migration.name,
		); err != nil {
			transaction.Rollback()
			database.Close()
			t.Fatalf("record migration %s: %v", migration.name, err)
		}
		if err := transaction.Commit(); err != nil {
			database.Close()
			t.Fatalf("commit migration %s: %v", migration.name, err)
		}
	}

	insertPreStateDeployment(t, database, "dep_state_alpha", "alpha")
	insertPreStateDeployment(t, database, "dep_state_beta", "beta")
	insertPreStateOperatorEvent(
		t,
		database,
		1,
		"opa_state_alpha_claim",
		"dep_state_alpha",
		"dep_state_alpha",
		"",
		"claim",
		"Alpha Cooperative",
		"claimed",
		"opg_state_alpha",
		"",
		"sha256:state-audit-1",
	)
	insertPreStateOperatorEvent(
		t,
		database,
		2,
		"opa_state_beta_claim",
		"dep_state_beta",
		"dep_state_beta",
		"",
		"claim",
		"Beta Cooperative",
		"claimed",
		"opg_state_beta",
		"",
		"sha256:state-audit-2",
	)
	insertPreStateOperatorEvent(
		t,
		database,
		3,
		"opa_state_alpha_token",
		"dep_state_alpha",
		"dep_state_alpha",
		"",
		"issue-client-token",
		"",
		"claimed",
		"opg_state_alpha",
		"",
		"sha256:state-audit-3",
	)
	insertPreStateOperatorEvent(
		t,
		database,
		4,
		"opa_state_beta_redeem",
		"dep_state_beta",
		"dep_state_beta",
		"dep_state_alpha",
		"redeem-client-token",
		"",
		"claimed",
		"opg_state_alpha",
		"opl_state_beta_alpha",
		"sha256:state-audit-4",
	)
	if err := database.Close(); err != nil {
		t.Fatalf("close pre-state-model database: %v", err)
	}

	registryStore, err := Open(databasePath)
	if err != nil {
		t.Fatalf("migrate existing operator audit database: %v", err)
	}
	defer registryStore.Close()

	rows, err := registryStore.db.Query(
		operatorNetworkStateSelect + " ORDER BY audit_index",
	)
	if err != nil {
		t.Fatalf("read backfilled operator state rows: %v", err)
	}
	defer rows.Close()
	states := make([]operatorNetworkStateRow, 0, 4)
	for rows.Next() {
		state, err := scanOperatorNetworkState(rows)
		if err != nil {
			t.Fatalf("scan backfilled operator state row: %v", err)
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate backfilled operator state rows: %v", err)
	}
	if len(states) != 4 {
		t.Fatalf("backfilled state row count = %d, want 4", len(states))
	}
	if states[0].DeploymentID != "dep_state_alpha" ||
		states[0].EffectiveGroupID != "opg_state_alpha" ||
		states[0].ProfileClaimAuditIndex != 1 ||
		!states[0].Claimed {
		t.Fatalf("backfilled first claim state = %+v", states[0])
	}
	if states[2].DeploymentID != "dep_state_alpha" ||
		states[2].EffectiveGroupID != "opg_state_alpha" ||
		states[2].ActionID != "opa_state_alpha_token" {
		t.Fatalf("backfilled no-op token boundary = %+v", states[2])
	}
	if states[3].DeploymentID != "dep_state_beta" ||
		states[3].ClaimGroupID != "opg_state_beta" ||
		states[3].EffectiveGroupID != "opg_state_alpha" ||
		states[3].LinkID != "opl_state_beta_alpha" ||
		states[3].RelatedDeploymentID != "dep_state_alpha" {
		t.Fatalf("backfilled linked membership state = %+v", states[3])
	}
}

func insertPreStateDeployment(
	t *testing.T,
	database *sql.DB,
	deploymentID string,
	suffix string,
) {
	t.Helper()
	if _, err := database.Exec(`
		INSERT INTO deployments (
			deployment_id,
			public_key_der,
			public_key_fingerprint,
			key_algorithm,
			software_version,
			registration_timestamp,
			registration_nonce,
			registration_idempotency_key,
			registration_signature,
			registered_at,
			registration_payload_hash,
			registration_receipt_signature
		) VALUES (?, ?, ?, 'Ed25519', 'migration-test', ?, ?, ?, zeroblob(64), ?, ?, zeroblob(64))`,
		deploymentID,
		[]byte("public-key-"+suffix),
		"fingerprint-"+suffix,
		"2026-07-28T00:00:00Z",
		"registration-nonce-"+suffix,
		"registration-idempotency-"+suffix,
		"2026-07-28T00:00:01Z",
		"registration-payload-"+suffix,
	); err != nil {
		t.Fatalf("insert pre-state deployment %s: %v", deploymentID, err)
	}
}

func insertPreStateOperatorEvent(
	t *testing.T,
	database *sql.DB,
	auditIndex int64,
	actionID string,
	deploymentID string,
	subjectDeploymentID string,
	relatedDeploymentID string,
	action string,
	operatorName string,
	claimState string,
	groupID string,
	linkID string,
	auditHash string,
) {
	t.Helper()
	if _, err := database.Exec(`
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
			receipt_signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, zeroblob(64), ?, '', ?, ?, ?, '', '', 0, '', ?, ?, ?, 'registry-key', zeroblob(64))`,
		auditIndex,
		actionID,
		deploymentID,
		subjectDeploymentID,
		relatedDeploymentID,
		action,
		"2026-07-28T00:00:00Z",
		"operator-nonce-"+actionID,
		"operator-idempotency-"+actionID,
		"payload-"+actionID,
		"request-"+actionID,
		operatorName,
		claimState,
		groupID,
		linkID,
		"2026-07-28T00:00:01Z",
		"previous-"+actionID,
		auditHash,
	); err != nil {
		t.Fatalf("insert pre-state operator event %s: %v", actionID, err)
	}
}
