package sqlite

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

const presenceCapacityMigrationName = "0021_global_identity_presence_chunk_capacity.sql"

func TestGlobalIdentityPresenceChunkCapacityMigrationUpgradesVersionTwentyDatabase(
	t *testing.T,
) {
	databasePath := filepath.Join(t.TempDir(), "registry.db")
	database := createVersionTwentyPresenceDatabase(t, databasePath)
	seedPresenceCapacityParents(t, database)
	if err := database.Close(); err != nil {
		t.Fatalf("close version-twenty database: %v", err)
	}

	registryStore, err := Open(databasePath)
	if err != nil {
		t.Fatalf("apply presence-capacity migration: %v", err)
	}
	defer registryStore.Close()

	var migrationCount int
	if err := registryStore.db.QueryRow(`
		SELECT COUNT(*)
		FROM schema_migrations
		WHERE version = 21 AND name = ?`,
		presenceCapacityMigrationName,
	).Scan(&migrationCount); err != nil {
		t.Fatalf("read presence-capacity migration record: %v", err)
	}
	if migrationCount != 1 {
		t.Fatalf(
			"presence-capacity migration record count = %d, want 1",
			migrationCount,
		)
	}

	insertPresenceSubmission(
		t,
		registryStore.db,
		"gps_capacity_valid",
		"2026-07",
		1,
		4096,
		false,
	)
	insertPresenceSubmission(
		t,
		registryStore.db,
		"gps_capacity_invalid",
		"2026-08",
		1,
		4097,
		true,
	)
}

func TestGlobalIdentityPresenceChunkCapacityMigrationRejectsInconsistentLegacyRows(
	t *testing.T,
) {
	databasePath := filepath.Join(t.TempDir(), "registry.db")
	database := createVersionTwentyPresenceDatabase(t, databasePath)
	seedPresenceCapacityParents(t, database)
	insertPresenceSubmission(
		t,
		database,
		"gps_capacity_legacy_invalid",
		"2026-07",
		1,
		4097,
		false,
	)
	if err := database.Close(); err != nil {
		t.Fatalf("close inconsistent version-twenty database: %v", err)
	}

	registryStore, err := Open(databasePath)
	if registryStore != nil {
		registryStore.Close()
	}
	if err == nil {
		t.Fatal("presence-capacity migration accepted an inconsistent legacy row")
	}
	if !strings.Contains(err.Error(), presenceCapacityMigrationName) {
		t.Fatalf("presence-capacity migration error = %v", err)
	}
}

func createVersionTwentyPresenceDatabase(
	t *testing.T,
	databasePath string,
) *sql.DB {
	t.Helper()

	registryStore, err := Open(databasePath)
	if err != nil {
		t.Fatalf("create current registry database: %v", err)
	}
	if _, err := registryStore.db.Exec(`
		DROP TRIGGER global_identity_presence_submissions_chunk_capacity
	`); err != nil {
		registryStore.Close()
		t.Fatalf("remove forward-only capacity trigger: %v", err)
	}
	if _, err := registryStore.db.Exec(
		"DELETE FROM schema_migrations WHERE version = 21",
	); err != nil {
		registryStore.Close()
		t.Fatalf("remove forward-only capacity migration record: %v", err)
	}
	return registryStore.db
}

func seedPresenceCapacityParents(t *testing.T, database *sql.DB) {
	t.Helper()

	signature := make([]byte, 64)
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
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"dep_presence_capacity",
		[]byte("presence-capacity-public-key"),
		"sha256:presence-capacity-fingerprint",
		"Ed25519",
		"test",
		"2026-07-29T00:00:00Z",
		"nonce_presence_capacity",
		"idempotency_presence_capacity",
		signature,
		"2026-07-29T00:00:00Z",
		"sha256:presence-capacity-registration",
		signature,
	); err != nil {
		t.Fatalf("seed presence-capacity deployment: %v", err)
	}
	if _, err := database.Exec(`
		INSERT INTO global_identity_voprf_keys (
			key_version,
			suite,
			public_key,
			activated_at
		) VALUES (?, ?, ?, ?)`,
		1,
		"P256-SHA256",
		make([]byte, 33),
		"2026-07-29T00:00:00Z",
	); err != nil {
		t.Fatalf("seed presence-capacity VOPRF key: %v", err)
	}
}

func insertPresenceSubmission(
	t *testing.T,
	database *sql.DB,
	submissionID string,
	period string,
	chunkCount int,
	totalCommitmentCount int,
	wantFailure bool,
) {
	t.Helper()

	_, err := database.Exec(`
		INSERT INTO global_identity_presence_submissions (
			submission_id,
			deployment_id,
			registry_scope,
			period,
			revision,
			reported_qmau_count,
			key_version,
			suite,
			chunk_count,
			total_commitment_count,
			commitment_set_hash,
			created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		submissionID,
		"dep_presence_capacity",
		"test:presence-capacity",
		period,
		1,
		totalCommitmentCount,
		1,
		"P256-SHA256",
		chunkCount,
		totalCommitmentCount,
		"sha256:"+submissionID,
		"2026-07-29T00:00:00Z",
	)
	if wantFailure {
		if err == nil {
			t.Fatalf(
				"inserted %d commitments into %d chunks",
				totalCommitmentCount,
				chunkCount,
			)
		}
		if !strings.Contains(
			err.Error(),
			"commitment count exceeds chunk capacity",
		) {
			t.Fatalf("unexpected presence-capacity error: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("insert presence submission %s: %v", submissionID, err)
	}
}
