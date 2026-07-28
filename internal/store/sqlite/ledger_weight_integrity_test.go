package sqlite

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const (
	ledgerIntegrityScope      = "example:ledger-integrity"
	ledgerIntegrityDeployment = "dep_ledger_integrity_000000000000001"
)

func TestAcceptInstallationBatchWritesLedgerWeightRowInSameTransaction(t *testing.T) {
	t.Run("matching row is committed with ledger entry", func(t *testing.T) {
		registryStore := newLedgerIntegrityStore(t)
		input := ledgerIntegrityBatchInput("committed")

		record, duplicate, err := registryStore.AcceptInstallationBatch(
			context.Background(),
			input,
			func(protocol.LedgerEntry, string) ([]byte, error) {
				return make([]byte, 64), nil
			},
		)
		if err != nil {
			t.Fatalf("accept installation batch: %v", err)
		}
		if duplicate {
			t.Fatalf("new installation batch reported as duplicate")
		}

		var (
			ledgerIndex       int64
			deploymentID      string
			period            string
			rulesetVersion    string
			qualifiedMAUCount int64
			weightNumerator   int64
			weightDenominator int64
			acceptedAt        string
			sourceEntryHash   string
		)
		if err := registryStore.db.QueryRow(`
			SELECT
				ledger_index,
				deployment_id,
				period,
				ruleset_version,
				qualified_mau_count,
				weight_numerator,
				weight_denominator,
				accepted_at,
				source_entry_hash
			FROM ledger_weight_rows
			WHERE ledger_index = ?`,
			record.LedgerEntry.LedgerIndex,
		).Scan(
			&ledgerIndex,
			&deploymentID,
			&period,
			&rulesetVersion,
			&qualifiedMAUCount,
			&weightNumerator,
			&weightDenominator,
			&acceptedAt,
			&sourceEntryHash,
		); err != nil {
			t.Fatalf("read ledger weight row: %v", err)
		}

		entry := record.LedgerEntry
		if ledgerIndex != entry.LedgerIndex ||
			deploymentID != entry.DeploymentID ||
			period != entry.Period ||
			rulesetVersion != entry.RulesetVersion ||
			qualifiedMAUCount != entry.QualifiedMAUCount ||
			weightNumerator != entry.QualifiedMAUCount ||
			weightDenominator != 1 ||
			acceptedAt != entry.AcceptedAt ||
			sourceEntryHash != entry.EntryHash {
			t.Fatalf("ledger weight row does not exactly mirror its ledger entry")
		}
		if err := registryStore.VerifyLedger(context.Background()); err != nil {
			t.Fatalf("verify authoritative ledger: %v", err)
		}
		if err := registryStore.VerifyLedgerWeightRows(context.Background()); err != nil {
			t.Fatalf("verify ledger weight rows: %v", err)
		}
	})

	t.Run("failed convenience-row insert rolls back ledger append", func(t *testing.T) {
		registryStore := newLedgerIntegrityStore(t)
		if _, err := registryStore.db.Exec(`
			CREATE TRIGGER reject_test_ledger_weight_insert
			BEFORE INSERT ON ledger_weight_rows BEGIN
				SELECT RAISE(ABORT, 'test ledger weight insert failure');
			END`); err != nil {
			t.Fatalf("create failing test trigger: %v", err)
		}

		_, _, err := registryStore.AcceptInstallationBatch(
			context.Background(),
			ledgerIntegrityBatchInput("rolled_back"),
			func(protocol.LedgerEntry, string) ([]byte, error) {
				return make([]byte, 64), nil
			},
		)
		if err == nil {
			t.Fatalf("batch acceptance unexpectedly succeeded")
		}

		for _, query := range []string{
			"SELECT COUNT(*) FROM ledger_entries",
			"SELECT COUNT(*) FROM ledger_weight_rows",
			"SELECT COUNT(*) FROM mau_batches",
			"SELECT COUNT(*) FROM used_nonces WHERE result_type = 'batch'",
			"SELECT COUNT(*) FROM idempotency_records WHERE result_type = 'batch'",
		} {
			var count int
			if scanErr := registryStore.db.QueryRow(query).Scan(&count); scanErr != nil {
				t.Fatalf("inspect rolled-back batch state: %v", scanErr)
			}
			if count != 0 {
				t.Fatalf("%q count = %d after rollback, want 0", query, count)
			}
		}
	})
}

func TestVerifyLedgerWeightRowsDetectsMissingExtraAndMismatchedRows(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		registryStore := newLedgerIntegrityStoreWithBatch(t)
		if _, err := registryStore.db.Exec("DROP TRIGGER ledger_weight_rows_no_delete"); err != nil {
			t.Fatalf("drop append-only delete trigger for corruption test: %v", err)
		}
		if _, err := registryStore.db.Exec(
			"DELETE FROM ledger_weight_rows WHERE ledger_index = 1",
		); err != nil {
			t.Fatalf("delete ledger weight row for corruption test: %v", err)
		}
		assertLedgerWeightVerificationFails(t, registryStore, "no matching ledger weight row")
	})

	t.Run("extra", func(t *testing.T) {
		registryStore := newLedgerIntegrityStoreWithBatch(t)
		setForeignKeysForCorruptionTest(t, registryStore, false)
		if _, err := registryStore.db.Exec(`
			INSERT INTO ledger_weight_rows (
				ledger_index,
				deployment_id,
				period,
				ruleset_version,
				qualified_mau_count,
				weight_numerator,
				weight_denominator,
				accepted_at,
				source_entry_hash
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			2,
			ledgerIntegrityDeployment,
			"2026-07",
			protocol.InstallationTestRuleset,
			0,
			0,
			1,
			"2026-07-28T00:00:03Z",
			"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		); err != nil {
			t.Fatalf("insert extra ledger weight row for corruption test: %v", err)
		}
		setForeignKeysForCorruptionTest(t, registryStore, true)
		assertLedgerWeightVerificationFails(t, registryStore, "no matching ledger entry")
	})

	mismatches := []struct {
		name      string
		statement string
		argument  any
		want      string
	}{
		{
			name:      "ledger index",
			statement: "UPDATE ledger_weight_rows SET ledger_index = ? WHERE ledger_index = 1",
			argument:  int64(2),
			want:      "no matching ledger weight row",
		},
		{
			name:      "deployment ID",
			statement: "UPDATE ledger_weight_rows SET deployment_id = ? WHERE ledger_index = 1",
			argument:  "dep_corrupted",
			want:      "mismatched deployment ID",
		},
		{
			name:      "period",
			statement: "UPDATE ledger_weight_rows SET period = ? WHERE ledger_index = 1",
			argument:  "2026-08",
			want:      "mismatched period",
		},
		{
			name:      "ruleset version",
			statement: "UPDATE ledger_weight_rows SET ruleset_version = ? WHERE ledger_index = 1",
			argument:  "corrupted-ruleset",
			want:      "mismatched ruleset version",
		},
		{
			name:      "qualified MAU count",
			statement: "UPDATE ledger_weight_rows SET qualified_mau_count = ? WHERE ledger_index = 1",
			argument:  int64(1),
			want:      "mismatched qualified MAU count",
		},
		{
			name:      "weight numerator",
			statement: "UPDATE ledger_weight_rows SET weight_numerator = ? WHERE ledger_index = 1",
			argument:  int64(1),
			want:      "mismatched weight numerator",
		},
		{
			name:      "weight denominator",
			statement: "UPDATE ledger_weight_rows SET weight_denominator = ? WHERE ledger_index = 1",
			argument:  int64(2),
			want:      "mismatched weight denominator",
		},
		{
			name:      "accepted at",
			statement: "UPDATE ledger_weight_rows SET accepted_at = ? WHERE ledger_index = 1",
			argument:  "2026-07-28T00:00:04Z",
			want:      "mismatched accepted_at",
		},
		{
			name:      "source entry hash",
			statement: "UPDATE ledger_weight_rows SET source_entry_hash = ? WHERE ledger_index = 1",
			argument:  "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			want:      "mismatched source entry hash",
		},
	}
	for _, mismatch := range mismatches {
		t.Run(mismatch.name, func(t *testing.T) {
			registryStore := newLedgerIntegrityStoreWithBatch(t)
			if _, err := registryStore.db.Exec("DROP TRIGGER ledger_weight_rows_no_update"); err != nil {
				t.Fatalf("drop append-only update trigger for corruption test: %v", err)
			}
			setForeignKeysForCorruptionTest(t, registryStore, false)
			if _, err := registryStore.db.Exec(mismatch.statement, mismatch.argument); err != nil {
				t.Fatalf("corrupt ledger weight row: %v", err)
			}
			setForeignKeysForCorruptionTest(t, registryStore, true)
			assertLedgerWeightVerificationFails(t, registryStore, mismatch.want)
		})
	}
}

func newLedgerIntegrityStore(t *testing.T) *Store {
	t.Helper()
	registryStore, err := Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatalf("open registry SQLite store: %v", err)
	}
	t.Cleanup(func() {
		if err := registryStore.Close(); err != nil {
			t.Errorf("close registry SQLite store: %v", err)
		}
	})

	ctx := context.Background()
	if err := registryStore.EnsureRegistryIdentity(ctx, store.RegistryIdentity{
		ProtocolVersion: protocol.Version,
		RegistryScope:   ledgerIntegrityScope,
		RegistryKeyID:   "registry-key-ledger-integrity",
		PublicKeyDER:    []byte("registry-public-key"),
		CreatedAt:       "2026-07-27T00:00:00Z",
	}); err != nil {
		t.Fatalf("seed registry identity: %v", err)
	}
	signature := make([]byte, 64)
	if _, _, err := registryStore.RegisterDeployment(ctx, store.RegistrationInput{
		SignerFingerprint:         "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Nonce:                     "nonce_registration_ledger_integrity",
		IdempotencyKey:            "idempotency_registration_ledger_integrity",
		PayloadHash:               "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		RequestHash:               "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		RequestTimestamp:          "2026-07-28T00:00:00Z",
		RequestSignature:          signature,
		PublicKeyDER:              []byte("deployment-public-key"),
		KeyAlgorithm:              protocol.KeyAlgorithmEd25519,
		SoftwareVersion:           "test",
		CandidateDeploymentID:     ledgerIntegrityDeployment,
		CandidateRegisteredAt:     "2026-07-28T00:00:01Z",
		CandidateReceiptSignature: signature,
	}); err != nil {
		t.Fatalf("seed deployment: %v", err)
	}
	return registryStore
}

func newLedgerIntegrityStoreWithBatch(t *testing.T) *Store {
	t.Helper()
	registryStore := newLedgerIntegrityStore(t)
	if _, _, err := registryStore.AcceptInstallationBatch(
		context.Background(),
		ledgerIntegrityBatchInput("verification"),
		func(protocol.LedgerEntry, string) ([]byte, error) {
			return make([]byte, 64), nil
		},
	); err != nil {
		t.Fatalf("seed installation batch: %v", err)
	}
	if err := registryStore.VerifyLedger(context.Background()); err != nil {
		t.Fatalf("verify seeded authoritative ledger: %v", err)
	}
	if err := registryStore.VerifyLedgerWeightRows(context.Background()); err != nil {
		t.Fatalf("verify seeded ledger weight row: %v", err)
	}
	return registryStore
}

func ledgerIntegrityBatchInput(suffix string) store.BatchInput {
	return store.BatchInput{
		RegistryScope:       ledgerIntegrityScope,
		Signer:              ledgerIntegrityDeployment,
		Nonce:               "nonce_batch_" + suffix,
		IdempotencyKey:      "idempotency_batch_" + suffix,
		PayloadHash:         "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		RequestHash:         "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		DeploymentID:        ledgerIntegrityDeployment,
		RequestTimestamp:    "2026-07-28T00:00:02Z",
		DeploymentSignature: make([]byte, 64),
		CandidateBatchID:    "batch_ledger_integrity_" + suffix,
		Kind:                protocol.InstallationTestKind,
		Period:              "2026-07",
		RulesetVersion:      protocol.InstallationTestRuleset,
		QualifiedMAUCount:   0,
		CommitmentHash:      "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		AcceptedAt:          "2026-07-28T00:00:03Z",
		CheckpointDate:      "2026-07-28",
	}
}

func setForeignKeysForCorruptionTest(t *testing.T, registryStore *Store, enabled bool) {
	t.Helper()
	value := "OFF"
	if enabled {
		value = "ON"
	}
	if _, err := registryStore.db.Exec("PRAGMA foreign_keys = " + value); err != nil {
		t.Fatalf("set foreign keys %s for corruption test: %v", value, err)
	}
}

func assertLedgerWeightVerificationFails(t *testing.T, registryStore *Store, want string) {
	t.Helper()
	if err := registryStore.VerifyLedger(context.Background()); err != nil {
		t.Fatalf("authoritative ledger was changed by query-row corruption: %v", err)
	}
	err := registryStore.VerifyLedgerWeightRows(context.Background())
	if err == nil {
		t.Fatalf("corrupted ledger weight rows unexpectedly verified")
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("verification error = %q, want it to contain %q", err, want)
	}
}
