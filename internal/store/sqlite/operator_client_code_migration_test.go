package sqlite

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestOperatorClientCodeMigrationAddsAnchorsAndSingleUseIndex(t *testing.T) {
	registryStore, err := Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatalf("open registry store with client-code migration: %v", err)
	}
	defer registryStore.Close()

	columns := make(map[string]bool)
	rows, err := registryStore.db.Query("PRAGMA table_info(operator_audit_events)")
	if err != nil {
		t.Fatalf("read operator audit columns: %v", err)
	}
	for rows.Next() {
		var columnIndex int
		var name, columnType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(
			&columnIndex,
			&name,
			&columnType,
			&notNull,
			&defaultValue,
			&primaryKey,
		); err != nil {
			rows.Close()
			t.Fatalf("scan operator audit column: %v", err)
		}
		columns[name] = true
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close operator audit columns: %v", err)
	}
	if !columns["source_claim_action_id"] ||
		!columns["source_private_record_hash"] {
		t.Fatalf("operator source anchor columns = %+v", columns)
	}

	var indexSQL string
	if err := registryStore.db.QueryRow(`
		SELECT sql
		FROM sqlite_master
		WHERE type = 'index'
		  AND name = 'operator_audit_events_redeem_token_once_idx'`,
	).Scan(&indexSQL); err != nil {
		t.Fatalf("read redemption uniqueness index: %v", err)
	}
	if !strings.Contains(indexSQL, "WHERE action_type = 'redeem-client-token'") {
		t.Fatalf("redemption uniqueness index SQL = %q", indexSQL)
	}

	insertPreStateDeployment(
		t,
		registryStore.db,
		"dep_client_code_constraint",
		"client-code-constraint",
	)
	insertPreStateOperatorEvent(
		t,
		registryStore.db,
		1,
		"opa_client_code_redeem_one",
		"dep_client_code_constraint",
		"dep_client_code_constraint",
		"dep_client_code_constraint",
		"redeem-client-token",
		"",
		"claimed",
		"opg_client_code_constraint",
		"opl_client_code_redeem_one",
		"sha256:client-code-redeem-one",
	)
	if _, err := registryStore.db.Exec(
		"DROP TRIGGER operator_audit_events_no_update",
	); err != nil {
		t.Fatalf("drop append-only trigger for source-anchor constraint test: %v", err)
	}
	if _, err := registryStore.db.Exec(`
		UPDATE operator_audit_events
		SET claim_state = 'pending-review',
		    operator_name = 'Derived Cooperative',
		    link_id = ''
		WHERE audit_index = 1`); err != nil {
		t.Fatalf("legacy unanchored v1 redemption no longer migrates: %v", err)
	}
	if _, err := registryStore.db.Exec(`
		UPDATE operator_audit_events
		SET source_claim_action_id = 'opa_00000000000000000000000000000001'
		WHERE audit_index = 1`); err == nil {
		t.Fatalf("source-anchor check accepted only one source anchor")
	}
	if _, err := registryStore.db.Exec(`
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
			source_claim_action_id,
			source_private_record_hash,
			token_ttl_seconds,
			token_expires_at,
			accepted_at,
			previous_audit_hash,
			audit_hash,
			registry_key_id,
			receipt_signature
		)
		SELECT
			2,
			'opa_client_code_redeem_two',
			deployment_id,
			subject_deployment_id,
			related_deployment_id,
			action_type,
			request_timestamp,
			'nonce_client_code_redeem_two',
			'idempotency_client_code_redeem_two',
			payload_hash,
			'request_client_code_redeem_two',
			deployment_signature,
			operator_name,
			operator_avatar_url,
			claim_state,
			group_id,
			'opl_client_code_redeem_two',
			token_id,
			client_token_hash,
			source_claim_action_id,
			source_private_record_hash,
			token_ttl_seconds,
			token_expires_at,
			accepted_at,
			audit_hash,
			'sha256:client-code-redeem-two',
			registry_key_id,
			receipt_signature
		FROM operator_audit_events
		WHERE audit_index = 1`); err == nil {
		t.Fatalf("partial unique index accepted a second redemption for one token")
	}
}
