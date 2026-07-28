package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

func TestSchemaEnablesWALAndAppendOnlyTriggers(t *testing.T) {
	t.Parallel()

	registryStore, err := Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatalf("open registry SQLite store: %v", err)
	}
	defer registryStore.Close()

	var journalMode string
	if err := registryStore.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("read journal mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal mode = %q, want wal", journalMode)
	}

	expectedTriggers := []string{
		"registry_identity_no_update", "registry_identity_no_delete",
		"deployments_no_update", "deployments_no_delete",
		"used_nonces_no_update", "used_nonces_no_delete",
		"idempotency_records_no_update", "idempotency_records_no_delete",
		"ledger_entries_no_update", "ledger_entries_no_delete",
		"ledger_weight_rows_no_update", "ledger_weight_rows_no_delete",
		"mau_batches_no_update", "mau_batches_no_delete",
		"checkpoints_no_update", "checkpoints_no_delete",
		"operator_audit_events_no_update", "operator_audit_events_no_delete",
		"operator_action_nonces_no_update", "operator_action_nonces_no_delete",
		"operator_network_state_rows_no_update", "operator_network_state_rows_no_delete",
		"operator_claim_verification_no_update", "operator_claim_verification_no_delete",
		"operator_claim_reviews_no_update", "operator_claim_reviews_no_delete",
		"announcements_no_update", "announcements_no_delete",
	}

	rows, err := registryStore.db.Query("PRAGMA table_info(operator_audit_events)")
	if err != nil {
		t.Fatalf("read public operator audit columns: %v", err)
	}
	defer rows.Close()
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
			t.Fatalf("scan public operator audit column: %v", err)
		}
		switch name {
		case "registered_address",
			"verification_contact_name",
			"verification_contact_email":
			t.Fatalf("private verification field %q must not be a public audit column", name)
		}
	}
	for _, name := range expectedTriggers {
		var count int
		if err := registryStore.db.QueryRow(`
			SELECT COUNT(*)
			FROM sqlite_master
			WHERE type = 'trigger' AND name = ?`,
			name,
		).Scan(&count); err != nil {
			t.Fatalf("find trigger %s: %v", name, err)
		}
		if count != 1 {
			t.Fatalf("trigger %s count = %d, want 1", name, count)
		}
	}

	signature := make([]byte, 64)
	if _, err := registryStore.db.Exec(`
		INSERT INTO deployments (
			deployment_id, public_key_der, public_key_fingerprint,
			key_algorithm, software_version, registration_timestamp,
			registration_nonce, registration_idempotency_key, registration_signature,
			registered_at,
			registration_payload_hash, registration_receipt_signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"dep_00000000000000000000000000000001",
		[]byte("deployment-public-key"),
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"Ed25519",
		"test",
		"2026-07-28T00:00:00Z",
		"nonce_registration_seed",
		"registration_seed",
		signature,
		"2026-07-28T00:00:00Z",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		signature,
	); err != nil {
		t.Fatalf("seed deployment: %v", err)
	}
	if _, err := registryStore.db.Exec(`
		INSERT INTO ledger_entries (
			ledger_index, protocol_version, registry_scope, entry_type, deployment_id,
			batch_id, kind, period, ruleset_version, qualified_mau_count,
			batch_hash, previous_entry_hash, entry_hash, accepted_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		1,
		"1",
		"example:test-primary",
		protocol.InstallationEntryType,
		"dep_00000000000000000000000000000001",
		"batch_000000000000000000000000000001",
		protocol.InstallationTestKind,
		"2026-07",
		protocol.InstallationTestRuleset,
		0,
		"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		protocol.ZeroHash,
		"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		"2026-07-28T00:00:02Z",
	); err != nil {
		t.Fatalf("seed ledger entry: %v", err)
	}
	if _, err := registryStore.db.Exec(
		"UPDATE ledger_entries SET accepted_at = ? WHERE ledger_index = 1",
		"2026-07-29T00:00:00Z",
	); err == nil {
		t.Fatalf("ledger update must be rejected by append-only trigger")
	}
	if _, err := registryStore.db.Exec(
		"DELETE FROM ledger_entries WHERE ledger_index = 1",
	); err == nil {
		t.Fatalf("ledger delete must be rejected by append-only trigger")
	}
	if err := registryStore.VerifyLedger(context.Background()); err != nil {
		// The hand-written hash is intentionally not valid; verifying it should
		// demonstrate that startup verification catches tampering as well.
		return
	}
	t.Fatalf("hand-written invalid ledger hash unexpectedly verified")
}
