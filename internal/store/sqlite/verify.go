package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

func (sqliteStore *Store) VerifyLedger(ctx context.Context) error {
	var registryScope string
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT registry_scope
		FROM registry_identity
		WHERE singleton = 1`).Scan(&registryScope); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("verify ledger identity: registry identity is missing")
		}
		return fmt.Errorf("read ledger registry scope: %w", err)
	}
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			protocol_version,
			registry_scope,
			ledger_index,
			entry_type,
			deployment_id,
			batch_id,
			kind,
			period,
			ruleset_version,
			qualified_mau_count,
			batch_hash,
			previous_entry_hash,
			entry_hash,
			accepted_at
		FROM ledger_entries
		ORDER BY ledger_index`)
	if err != nil {
		return fmt.Errorf("read ledger chain: %w", err)
	}
	defer rows.Close()

	expectedIndex := int64(1)
	previousHash := protocol.ZeroHash
	var previousAcceptedAt time.Time
	for rows.Next() {
		var entry protocol.LedgerEntry
		if err := rows.Scan(
			&entry.ProtocolVersion,
			&entry.RegistryScope,
			&entry.LedgerIndex,
			&entry.EntryType,
			&entry.DeploymentID,
			&entry.BatchID,
			&entry.Kind,
			&entry.Period,
			&entry.RulesetVersion,
			&entry.QualifiedMAUCount,
			&entry.BatchHash,
			&entry.PreviousEntryHash,
			&entry.EntryHash,
			&entry.AcceptedAt,
		); err != nil {
			return fmt.Errorf("scan ledger entry: %w", err)
		}
		if entry.LedgerIndex != expectedIndex {
			return fmt.Errorf("ledger index discontinuity: got %d, expected %d", entry.LedgerIndex, expectedIndex)
		}
		if entry.RegistryScope != registryScope {
			return fmt.Errorf("ledger entry %d has registry scope %q", entry.LedgerIndex, entry.RegistryScope)
		}
		if entry.PreviousEntryHash != previousHash {
			return fmt.Errorf("ledger entry %d has an invalid previous hash", entry.LedgerIndex)
		}
		acceptedAt, err := time.Parse(time.RFC3339Nano, entry.AcceptedAt)
		if err != nil || !strings.HasSuffix(entry.AcceptedAt, "Z") {
			return fmt.Errorf("ledger entry %d has an invalid UTC accepted_at", entry.LedgerIndex)
		}
		if expectedIndex > 1 && acceptedAt.Before(previousAcceptedAt) {
			return fmt.Errorf("ledger entry %d has a non-monotonic accepted_at", entry.LedgerIndex)
		}
		expectedHash := protocol.Digest(protocol.LedgerEntryMessage(entry))
		if entry.EntryHash != expectedHash {
			return fmt.Errorf("ledger entry %d hash verification failed", entry.LedgerIndex)
		}
		previousHash = entry.EntryHash
		previousAcceptedAt = acceptedAt
		expectedIndex++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate ledger chain: %w", err)
	}
	return nil
}
