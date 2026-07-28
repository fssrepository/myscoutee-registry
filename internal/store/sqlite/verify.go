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

func (sqliteStore *Store) VerifyLedgerWeightRows(ctx context.Context) error {
	rows, err := sqliteStore.db.QueryContext(ctx, `
			SELECT
				l.ledger_index,
				l.entry_type,
				l.deployment_id,
			l.period,
			l.ruleset_version,
			l.qualified_mau_count,
			l.accepted_at,
			l.entry_hash,
			w.ledger_index,
			w.deployment_id,
			w.period,
			w.ruleset_version,
			w.qualified_mau_count,
			w.weight_numerator,
			w.weight_denominator,
			w.accepted_at,
			w.source_entry_hash
		FROM ledger_entries l
		LEFT JOIN ledger_weight_rows w ON w.ledger_index = l.ledger_index
		ORDER BY l.ledger_index`)
	if err != nil {
		return fmt.Errorf("read ledger weight rows: %w", err)
	}

	for rows.Next() {
		var (
			ledgerIndex       int64
			entryType         string
			deploymentID      string
			period            string
			rulesetVersion    string
			qualifiedMAUCount int64
			acceptedAt        string
			entryHash         string

			rowLedgerIndex       sql.NullInt64
			rowDeploymentID      sql.NullString
			rowPeriod            sql.NullString
			rowRulesetVersion    sql.NullString
			rowQualifiedMAUCount sql.NullInt64
			rowWeightNumerator   sql.NullInt64
			rowWeightDenominator sql.NullInt64
			rowAcceptedAt        sql.NullString
			rowSourceEntryHash   sql.NullString
		)
		if err := rows.Scan(
			&ledgerIndex,
			&entryType,
			&deploymentID,
			&period,
			&rulesetVersion,
			&qualifiedMAUCount,
			&acceptedAt,
			&entryHash,
			&rowLedgerIndex,
			&rowDeploymentID,
			&rowPeriod,
			&rowRulesetVersion,
			&rowQualifiedMAUCount,
			&rowWeightNumerator,
			&rowWeightDenominator,
			&rowAcceptedAt,
			&rowSourceEntryHash,
		); err != nil {
			rows.Close()
			return fmt.Errorf("scan ledger weight row: %w", err)
		}
		if entryType == protocol.RevenueEntryType {
			if rowLedgerIndex.Valid {
				rows.Close()
				return fmt.Errorf(
					"revenue ledger entry %d unexpectedly has a weight row",
					ledgerIndex,
				)
			}
			continue
		}
		if entryType != protocol.InstallationEntryType {
			rows.Close()
			return fmt.Errorf(
				"ledger entry %d has unsupported type %q",
				ledgerIndex,
				entryType,
			)
		}
		if !rowLedgerIndex.Valid {
			rows.Close()
			return fmt.Errorf("ledger entry %d has no matching ledger weight row", ledgerIndex)
		}
		if rowLedgerIndex.Int64 != ledgerIndex {
			rows.Close()
			return fmt.Errorf(
				"ledger weight row %d has ledger index %d",
				ledgerIndex,
				rowLedgerIndex.Int64,
			)
		}
		if !rowDeploymentID.Valid || rowDeploymentID.String != deploymentID {
			rows.Close()
			return fmt.Errorf("ledger weight row %d has a mismatched deployment ID", ledgerIndex)
		}
		if !rowPeriod.Valid || rowPeriod.String != period {
			rows.Close()
			return fmt.Errorf("ledger weight row %d has a mismatched period", ledgerIndex)
		}
		if !rowRulesetVersion.Valid || rowRulesetVersion.String != rulesetVersion {
			rows.Close()
			return fmt.Errorf("ledger weight row %d has a mismatched ruleset version", ledgerIndex)
		}
		if !rowQualifiedMAUCount.Valid || rowQualifiedMAUCount.Int64 != qualifiedMAUCount {
			rows.Close()
			return fmt.Errorf("ledger weight row %d has a mismatched qualified MAU count", ledgerIndex)
		}
		if !rowWeightNumerator.Valid || rowWeightNumerator.Int64 != qualifiedMAUCount {
			rows.Close()
			return fmt.Errorf("ledger weight row %d has a mismatched weight numerator", ledgerIndex)
		}
		if !rowWeightDenominator.Valid || rowWeightDenominator.Int64 != 1 {
			rows.Close()
			return fmt.Errorf("ledger weight row %d has a mismatched weight denominator", ledgerIndex)
		}
		if !rowAcceptedAt.Valid || rowAcceptedAt.String != acceptedAt {
			rows.Close()
			return fmt.Errorf("ledger weight row %d has a mismatched accepted_at", ledgerIndex)
		}
		if !rowSourceEntryHash.Valid || rowSourceEntryHash.String != entryHash {
			rows.Close()
			return fmt.Errorf("ledger weight row %d has a mismatched source entry hash", ledgerIndex)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate ledger weight rows: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close ledger-weight rows: %w", err)
	}

	var extraLedgerIndex int64
	err = sqliteStore.db.QueryRowContext(ctx, `
		SELECT w.ledger_index
		FROM ledger_weight_rows w
		LEFT JOIN ledger_entries l ON l.ledger_index = w.ledger_index
			WHERE l.ledger_index IS NULL
			   OR l.entry_type <> 'INSTALLATION_TEST_BATCH_ACCEPTED'
		ORDER BY w.ledger_index
		LIMIT 1`).Scan(&extraLedgerIndex)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("find extra ledger weight rows: %w", err)
	}
	return fmt.Errorf(
		"ledger weight row %d has no matching ledger entry",
		extraLedgerIndex,
	)
}
