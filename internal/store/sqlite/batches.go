package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func (sqliteStore *Store) AcceptInstallationBatch(
	ctx context.Context,
	input store.BatchInput,
	signReceipt store.BatchReceiptSigner,
) (store.BatchRecord, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.BatchRecord{}, false, fmt.Errorf("begin MAU batch acceptance: %w", err)
	}
	defer tx.Rollback()

	nonceUsed, err := nonceState(ctx, tx, input.Signer, input.Nonce, input.RequestHash)
	if err != nil {
		return store.BatchRecord{}, false, err
	}
	idempotency, err := readIdempotency(ctx, tx, input.Signer, input.IdempotencyKey)
	if err != nil {
		return store.BatchRecord{}, false, err
	}
	if idempotency != nil {
		if idempotency.PayloadHash != input.PayloadHash {
			return store.BatchRecord{}, false, store.ErrIdempotencyConflict
		}
		if idempotency.ResultType != "batch" {
			return store.BatchRecord{}, false, store.ErrInconsistentState
		}
		record, err := batchRecordByIDTx(ctx, tx, idempotency.ResultID)
		if err != nil {
			return store.BatchRecord{}, false, err
		}
		if !nonceUsed {
			if err := insertNonce(
				ctx,
				tx,
				batchNonce(input, idempotency.ResultID),
			); err != nil {
				return store.BatchRecord{}, false, err
			}
		}
		if err := tx.Commit(); err != nil {
			return store.BatchRecord{}, false, fmt.Errorf("commit duplicate MAU batch: %w", err)
		}
		return record, true, nil
	}
	if nonceUsed {
		return store.BatchRecord{}, false, store.ErrInconsistentState
	}
	if err := ensureAcceptedAtAfterRegistryCreation(ctx, tx, input.AcceptedAt); err != nil {
		return store.BatchRecord{}, false, err
	}
	if err := ensureAcceptedAtAfterCheckpoint(ctx, tx, input.AcceptedAt); err != nil {
		return store.BatchRecord{}, false, err
	}

	head, err := ledgerHeadTx(ctx, tx)
	if err != nil {
		return store.BatchRecord{}, false, err
	}
	if err := ensureAcceptedAtNotBeforeHead(input.AcceptedAt, head.AcceptedAt); err != nil {
		return store.BatchRecord{}, false, err
	}
	entry := protocol.LedgerEntry{
		ProtocolVersion:   protocol.Version,
		RegistryScope:     input.RegistryScope,
		LedgerIndex:       head.LedgerIndex + 1,
		EntryType:         protocol.InstallationEntryType,
		DeploymentID:      input.DeploymentID,
		BatchID:           input.CandidateBatchID,
		Kind:              input.Kind,
		Period:            input.Period,
		RulesetVersion:    input.RulesetVersion,
		QualifiedMAUCount: input.QualifiedMAUCount,
		BatchHash:         input.PayloadHash,
		PreviousEntryHash: head.EntryHash,
		AcceptedAt:        input.AcceptedAt,
	}
	entry.EntryHash = protocol.Digest(protocol.LedgerEntryMessage(entry))
	receiptSignature, err := signReceipt(entry, input.CheckpointDate)
	if err != nil {
		return store.BatchRecord{}, false, fmt.Errorf("sign MAU batch receipt: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO ledger_entries (
			ledger_index,
			protocol_version,
			registry_scope,
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
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.LedgerIndex,
		entry.ProtocolVersion,
		entry.RegistryScope,
		entry.EntryType,
		entry.DeploymentID,
		entry.BatchID,
		entry.Kind,
		entry.Period,
		entry.RulesetVersion,
		entry.QualifiedMAUCount,
		entry.BatchHash,
		entry.PreviousEntryHash,
		entry.EntryHash,
		entry.AcceptedAt,
	)
	if err != nil {
		return store.BatchRecord{}, false, fmt.Errorf("append ledger entry: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO mau_batches (
			batch_id,
			deployment_id,
			idempotency_key,
			request_timestamp,
			request_nonce,
			deployment_signature,
			kind,
			period,
			ruleset_version,
			qualified_mau_count,
			commitment_hash,
			payload_hash,
			accepted_at,
			ledger_index,
			receipt_signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		input.CandidateBatchID,
		input.DeploymentID,
		input.IdempotencyKey,
		input.RequestTimestamp,
		input.Nonce,
		input.DeploymentSignature,
		input.Kind,
		input.Period,
		input.RulesetVersion,
		input.QualifiedMAUCount,
		input.CommitmentHash,
		input.PayloadHash,
		input.AcceptedAt,
		entry.LedgerIndex,
		receiptSignature,
	)
	if err != nil {
		return store.BatchRecord{}, false, fmt.Errorf("persist accepted MAU batch: %w", err)
	}
	if err := insertNonce(
		ctx,
		tx,
		batchNonce(input, input.CandidateBatchID),
	); err != nil {
		return store.BatchRecord{}, false, err
	}
	if err := insertIdempotency(
		ctx,
		tx,
		input.Signer,
		input.IdempotencyKey,
		input.PayloadHash,
		"batch",
		input.CandidateBatchID,
		input.AcceptedAt,
	); err != nil {
		return store.BatchRecord{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return store.BatchRecord{}, false, fmt.Errorf("commit MAU batch acceptance: %w", err)
	}

	return store.BatchRecord{
		BatchID:           input.CandidateBatchID,
		DeploymentID:      input.DeploymentID,
		IdempotencyKey:    input.IdempotencyKey,
		Kind:              input.Kind,
		Period:            input.Period,
		RulesetVersion:    input.RulesetVersion,
		QualifiedMAUCount: input.QualifiedMAUCount,
		CommitmentHash:    input.CommitmentHash,
		PayloadHash:       input.PayloadHash,
		AcceptedAt:        input.AcceptedAt,
		LedgerEntry:       entry,
		ReceiptSignature:  append([]byte(nil), receiptSignature...),
	}, false, nil
}

func batchNonce(input store.BatchInput, batchID string) acceptedNonce {
	return acceptedNonce{
		Signer:           input.Signer,
		Nonce:            input.Nonce,
		RequestHash:      input.RequestHash,
		IdempotencyKey:   input.IdempotencyKey,
		PayloadHash:      input.PayloadHash,
		RequestTimestamp: input.RequestTimestamp,
		RequestSignature: input.DeploymentSignature,
		ResultType:       "batch",
		ResultID:         batchID,
		AcceptedAt:       input.AcceptedAt,
	}
}

func ensureAcceptedAtAfterRegistryCreation(ctx context.Context, tx *sql.Tx, acceptedAt string) error {
	var createdAt string
	if err := tx.QueryRowContext(ctx, `
		SELECT created_at
		FROM registry_identity
		WHERE singleton = 1`).Scan(&createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrInconsistentState
		}
		return fmt.Errorf("read registry identity cutoff: %w", err)
	}
	createdTime, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return fmt.Errorf("%w: invalid registry identity timestamp", store.ErrInconsistentState)
	}
	acceptedTime, err := time.Parse(time.RFC3339Nano, acceptedAt)
	if err != nil {
		return fmt.Errorf("%w: invalid accepted_at timestamp", store.ErrInconsistentState)
	}
	if acceptedTime.Before(createdTime) {
		return store.ErrAcceptedAtBeforeIdentity
	}
	return nil
}

func ensureAcceptedAtAfterCheckpoint(ctx context.Context, tx *sql.Tx, acceptedAt string) error {
	var latestCheckpointDate string
	err := tx.QueryRowContext(ctx, `
		SELECT checkpoint_date
		FROM checkpoints
		ORDER BY checkpoint_date DESC
		LIMIT 1`).Scan(&latestCheckpointDate)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read latest checkpoint cutoff: %w", err)
	}
	checkpointDay, err := time.Parse("2006-01-02", latestCheckpointDate)
	if err != nil {
		return fmt.Errorf("%w: invalid latest checkpoint date", store.ErrInconsistentState)
	}
	acceptedTime, err := time.Parse(time.RFC3339Nano, acceptedAt)
	if err != nil {
		return fmt.Errorf("%w: invalid accepted_at timestamp", store.ErrInconsistentState)
	}
	cutoff := checkpointDay.UTC().AddDate(0, 0, 1)
	if acceptedTime.Before(cutoff) {
		return store.ErrAcceptedAtFinalized
	}
	return nil
}

func ensureAcceptedAtNotBeforeHead(acceptedAt, headAcceptedAt string) error {
	if headAcceptedAt == "" {
		return nil
	}
	acceptedTime, err := time.Parse(time.RFC3339Nano, acceptedAt)
	if err != nil {
		return fmt.Errorf("%w: invalid accepted_at timestamp", store.ErrInconsistentState)
	}
	headTime, err := time.Parse(time.RFC3339Nano, headAcceptedAt)
	if err != nil {
		return fmt.Errorf("%w: invalid ledger-head accepted_at timestamp", store.ErrInconsistentState)
	}
	if acceptedTime.Before(headTime) {
		return store.ErrAcceptedAtBeforeHead
	}
	return nil
}

func (sqliteStore *Store) BatchReceipt(ctx context.Context, batchID string) (store.BatchRecord, error) {
	return batchRecordByIDQuery(ctx, sqliteStore.db, batchID)
}

func batchRecordByIDTx(ctx context.Context, tx *sql.Tx, batchID string) (store.BatchRecord, error) {
	return batchRecordByIDQuery(ctx, tx, batchID)
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func batchRecordByIDQuery(
	ctx context.Context,
	queryer queryRower,
	batchID string,
) (store.BatchRecord, error) {
	row := queryer.QueryRowContext(ctx, `
		SELECT
			b.batch_id,
			b.deployment_id,
			b.idempotency_key,
			b.kind,
			b.period,
			b.ruleset_version,
			b.qualified_mau_count,
			b.commitment_hash,
			b.payload_hash,
			b.accepted_at,
			b.receipt_signature,
			l.protocol_version,
			l.registry_scope,
			l.ledger_index,
			l.entry_type,
			l.batch_hash,
			l.previous_entry_hash,
			l.entry_hash
		FROM mau_batches b
		JOIN ledger_entries l ON l.ledger_index = b.ledger_index
		WHERE b.batch_id = ?`,
		batchID,
	)
	var record store.BatchRecord
	var entry protocol.LedgerEntry
	if err := row.Scan(
		&record.BatchID,
		&record.DeploymentID,
		&record.IdempotencyKey,
		&record.Kind,
		&record.Period,
		&record.RulesetVersion,
		&record.QualifiedMAUCount,
		&record.CommitmentHash,
		&record.PayloadHash,
		&record.AcceptedAt,
		&record.ReceiptSignature,
		&entry.ProtocolVersion,
		&entry.RegistryScope,
		&entry.LedgerIndex,
		&entry.EntryType,
		&entry.BatchHash,
		&entry.PreviousEntryHash,
		&entry.EntryHash,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.BatchRecord{}, store.ErrNotFound
		}
		return store.BatchRecord{}, fmt.Errorf("read MAU batch receipt: %w", err)
	}
	entry.DeploymentID = record.DeploymentID
	entry.BatchID = record.BatchID
	entry.Kind = record.Kind
	entry.Period = record.Period
	entry.RulesetVersion = record.RulesetVersion
	entry.QualifiedMAUCount = record.QualifiedMAUCount
	entry.AcceptedAt = record.AcceptedAt
	record.LedgerEntry = entry
	return record, nil
}

func ledgerHeadTx(ctx context.Context, tx *sql.Tx) (store.LedgerHead, error) {
	var head store.LedgerHead
	err := tx.QueryRowContext(ctx, `
		SELECT ledger_index, entry_hash, accepted_at
		FROM ledger_entries
		ORDER BY ledger_index DESC
		LIMIT 1`).Scan(&head.LedgerIndex, &head.EntryHash, &head.AcceptedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.LedgerHead{EntryHash: protocol.ZeroHash}, nil
	}
	if err != nil {
		return store.LedgerHead{}, fmt.Errorf("read ledger head: %w", err)
	}
	head.EntryCount = head.LedgerIndex
	return head, nil
}

func (sqliteStore *Store) LedgerHead(ctx context.Context) (store.LedgerHead, error) {
	var head store.LedgerHead
	err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT ledger_index, entry_hash, accepted_at
		FROM ledger_entries
		ORDER BY ledger_index DESC
		LIMIT 1`).Scan(&head.LedgerIndex, &head.EntryHash, &head.AcceptedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return store.LedgerHead{EntryHash: protocol.ZeroHash}, nil
	}
	if err != nil {
		return store.LedgerHead{}, fmt.Errorf("read ledger head: %w", err)
	}
	if err := sqliteStore.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ledger_entries").Scan(&head.EntryCount); err != nil {
		return store.LedgerHead{}, fmt.Errorf("count ledger entries: %w", err)
	}
	return head, nil
}
