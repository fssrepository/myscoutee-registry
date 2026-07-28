package sqlite

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func (sqliteStore *Store) FinalizeCompletedCheckpoints(
	ctx context.Context,
	now time.Time,
	registryScope string,
	registryKeyID string,
	signCheckpoint store.CheckpointSigner,
) ([]store.CheckpointRecord, error) {
	now = now.UTC().Truncate(time.Second)
	targetDate := dayStart(now).AddDate(0, 0, -1)

	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin checkpoint finalization: %w", err)
	}
	defer tx.Rollback()

	var identityCreatedAt string
	if err := tx.QueryRowContext(ctx, `
		SELECT created_at
		FROM registry_identity
		WHERE singleton = 1`).Scan(&identityCreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrInconsistentState
		}
		return nil, fmt.Errorf("read registry creation time: %w", err)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, identityCreatedAt)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid registry creation timestamp", store.ErrInconsistentState)
	}

	nextDate := dayStart(createdAt.UTC())
	previousCheckpointHash := protocol.ZeroHash
	var latestDate string
	err = tx.QueryRowContext(ctx, `
		SELECT checkpoint_date, checkpoint_hash
		FROM checkpoints
		ORDER BY checkpoint_date DESC
		LIMIT 1`).Scan(&latestDate, &previousCheckpointHash)
	if err == nil {
		parsedLatestDate, parseErr := time.Parse("2006-01-02", latestDate)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: invalid persisted checkpoint date", store.ErrInconsistentState)
		}
		nextDate = parsedLatestDate.UTC().AddDate(0, 0, 1)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("read latest checkpoint: %w", err)
	}

	if nextDate.After(targetDate) {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("finish checkpoint no-op transaction: %w", err)
		}
		return nil, nil
	}

	generatedAt := now.Format(time.RFC3339)
	created := make([]store.CheckpointRecord, 0)
	for checkpointDay := nextDate; !checkpointDay.After(targetDate); checkpointDay = checkpointDay.AddDate(0, 0, 1) {
		endExclusive := checkpointDay.AddDate(0, 0, 1).Format(time.RFC3339)
		head, err := ledgerHeadBeforeTx(ctx, tx, endExclusive)
		if err != nil {
			return nil, err
		}
		checkpoint := protocol.Checkpoint{
			RegistryScope:          registryScope,
			CheckpointDate:         checkpointDay.Format("2006-01-02"),
			ThroughLedgerIndex:     head.LedgerIndex,
			EntryCount:             head.EntryCount,
			LedgerHeadHash:         head.EntryHash,
			PreviousCheckpointHash: previousCheckpointHash,
			GeneratedAt:            generatedAt,
			RegistryKeyID:          registryKeyID,
		}
		checkpoint.CheckpointHash = protocol.Digest(protocol.CheckpointMessage(checkpoint))
		signature, err := signCheckpoint(checkpoint)
		if err != nil {
			return nil, fmt.Errorf("sign checkpoint %s: %w", checkpoint.CheckpointDate, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO checkpoints (
				registry_scope,
				checkpoint_date,
				through_ledger_index,
				entry_count,
				ledger_head_hash,
				previous_checkpoint_hash,
				checkpoint_hash,
				generated_at,
				registry_key_id,
				signature
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			checkpoint.RegistryScope,
			checkpoint.CheckpointDate,
			checkpoint.ThroughLedgerIndex,
			checkpoint.EntryCount,
			checkpoint.LedgerHeadHash,
			checkpoint.PreviousCheckpointHash,
			checkpoint.CheckpointHash,
			checkpoint.GeneratedAt,
			checkpoint.RegistryKeyID,
			signature,
		); err != nil {
			return nil, fmt.Errorf("persist checkpoint %s: %w", checkpoint.CheckpointDate, err)
		}
		created = append(created, store.CheckpointRecord{
			Checkpoint: checkpoint,
			Signature:  append([]byte(nil), signature...),
		})
		previousCheckpointHash = checkpoint.CheckpointHash
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit checkpoint finalization: %w", err)
	}
	return created, nil
}

func (sqliteStore *Store) Checkpoint(ctx context.Context, checkpointDate string) (store.CheckpointRecord, error) {
	row := sqliteStore.db.QueryRowContext(ctx, `
		SELECT
			registry_scope,
			checkpoint_date,
			through_ledger_index,
			entry_count,
			ledger_head_hash,
			previous_checkpoint_hash,
			checkpoint_hash,
			generated_at,
			registry_key_id,
			signature
		FROM checkpoints
		WHERE checkpoint_date = ?`,
		checkpointDate,
	)
	return scanCheckpoint(row)
}

func ledgerHeadBeforeTx(ctx context.Context, tx *sql.Tx, endExclusive string) (store.LedgerHead, error) {
	var head store.LedgerHead
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(MAX(ledger_index), 0)
		FROM ledger_entries
		WHERE accepted_at < ?`,
		endExclusive,
	).Scan(&head.EntryCount, &head.LedgerIndex); err != nil {
		return store.LedgerHead{}, fmt.Errorf("read checkpoint ledger extent: %w", err)
	}
	head.EntryHash = protocol.ZeroHash
	if head.LedgerIndex > 0 {
		if err := tx.QueryRowContext(ctx, `
			SELECT entry_hash
			FROM ledger_entries
			WHERE ledger_index = ?`,
			head.LedgerIndex,
		).Scan(&head.EntryHash); err != nil {
			return store.LedgerHead{}, fmt.Errorf("read checkpoint ledger head hash: %w", err)
		}
	}
	return head, nil
}

func scanCheckpoint(row rowScanner) (store.CheckpointRecord, error) {
	var record store.CheckpointRecord
	if err := row.Scan(
		&record.Checkpoint.RegistryScope,
		&record.Checkpoint.CheckpointDate,
		&record.Checkpoint.ThroughLedgerIndex,
		&record.Checkpoint.EntryCount,
		&record.Checkpoint.LedgerHeadHash,
		&record.Checkpoint.PreviousCheckpointHash,
		&record.Checkpoint.CheckpointHash,
		&record.Checkpoint.GeneratedAt,
		&record.Checkpoint.RegistryKeyID,
		&record.Signature,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.CheckpointRecord{}, store.ErrNotFound
		}
		return store.CheckpointRecord{}, fmt.Errorf("read checkpoint: %w", err)
	}
	return record, nil
}

func (sqliteStore *Store) VerifyCheckpoints(
	ctx context.Context,
	publicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			registry_scope,
			checkpoint_date,
			through_ledger_index,
			entry_count,
			ledger_head_hash,
			previous_checkpoint_hash,
			checkpoint_hash,
			generated_at,
			registry_key_id,
			signature
		FROM checkpoints
		ORDER BY checkpoint_date`)
	if err != nil {
		return fmt.Errorf("read checkpoint chain: %w", err)
	}
	records := make([]store.CheckpointRecord, 0)
	for rows.Next() {
		record, scanErr := scanCheckpoint(rows)
		if scanErr != nil {
			rows.Close()
			return scanErr
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate checkpoint chain: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close checkpoint-chain rows: %w", err)
	}

	previousHash := protocol.ZeroHash
	var previousDate time.Time
	for index, record := range records {
		checkpoint := record.Checkpoint
		checkpointDate, err := time.Parse("2006-01-02", checkpoint.CheckpointDate)
		if err != nil {
			return fmt.Errorf("checkpoint %q has an invalid date", checkpoint.CheckpointDate)
		}
		if index > 0 && !checkpointDate.Equal(previousDate.AddDate(0, 0, 1)) {
			return fmt.Errorf("checkpoint chain has a date gap before %s", checkpoint.CheckpointDate)
		}
		if checkpoint.RegistryKeyID != registryKeyID {
			return fmt.Errorf("checkpoint %s has registry key ID %q", checkpoint.CheckpointDate, checkpoint.RegistryKeyID)
		}
		if checkpoint.RegistryScope != registryScope {
			return fmt.Errorf("checkpoint %s has registry scope %q", checkpoint.CheckpointDate, checkpoint.RegistryScope)
		}
		if checkpoint.PreviousCheckpointHash != previousHash {
			return fmt.Errorf("checkpoint %s has an invalid previous checkpoint hash", checkpoint.CheckpointDate)
		}
		expectedHash := protocol.Digest(protocol.CheckpointMessage(checkpoint))
		if checkpoint.CheckpointHash != expectedHash {
			return fmt.Errorf("checkpoint %s hash verification failed", checkpoint.CheckpointDate)
		}
		if !ed25519.Verify(publicKey, protocol.CheckpointMessage(checkpoint), record.Signature) {
			return fmt.Errorf("checkpoint %s signature verification failed", checkpoint.CheckpointDate)
		}
		expectedHead, err := sqliteStore.ledgerHeadBefore(ctx, checkpointDate.AddDate(0, 0, 1).Format(time.RFC3339))
		if err != nil {
			return err
		}
		if checkpoint.ThroughLedgerIndex != expectedHead.LedgerIndex ||
			checkpoint.EntryCount != expectedHead.EntryCount ||
			checkpoint.LedgerHeadHash != expectedHead.EntryHash {
			return fmt.Errorf("checkpoint %s does not match the completed-day ledger head", checkpoint.CheckpointDate)
		}
		previousHash = checkpoint.CheckpointHash
		previousDate = checkpointDate
	}
	return nil
}

func (sqliteStore *Store) ledgerHeadBefore(ctx context.Context, endExclusive string) (store.LedgerHead, error) {
	var head store.LedgerHead
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(MAX(ledger_index), 0)
		FROM ledger_entries
		WHERE accepted_at < ?`,
		endExclusive,
	).Scan(&head.EntryCount, &head.LedgerIndex); err != nil {
		return store.LedgerHead{}, fmt.Errorf("verify checkpoint ledger extent: %w", err)
	}
	head.EntryHash = protocol.ZeroHash
	if head.LedgerIndex > 0 {
		if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT entry_hash
			FROM ledger_entries
			WHERE ledger_index = ?`,
			head.LedgerIndex,
		).Scan(&head.EntryHash); err != nil {
			return store.LedgerHead{}, fmt.Errorf("verify checkpoint ledger head hash: %w", err)
		}
	}
	return head, nil
}

func dayStart(value time.Time) time.Time {
	year, month, day := value.UTC().Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}
