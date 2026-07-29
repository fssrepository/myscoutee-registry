package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const globalIdentityEvaluationSelect = `
	SELECT
		evaluation_id,
		deployment_id,
		idempotency_key,
		request_nonce,
		request_timestamp,
		request_hash,
		request_signature,
		payload_hash,
		key_version,
		suite,
		blinded_element,
		public_key,
		evaluated_element,
		proof,
		response_hash,
		evaluated_at,
		receipt_signature
	FROM global_identity_evaluations`

func (sqliteStore *Store) EnsureGlobalIdentityVOPRFKeys(
	ctx context.Context,
	keys []store.GlobalIdentityVOPRFKey,
) error {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin global identity key metadata sync: %w", err)
	}
	defer tx.Rollback()
	for _, key := range keys {
		var persisted store.GlobalIdentityVOPRFKey
		err := tx.QueryRowContext(ctx, `
			SELECT key_version, suite, public_key, activated_at
			FROM global_identity_voprf_keys
			WHERE key_version = ?`,
			key.KeyVersion,
		).Scan(
			&persisted.KeyVersion,
			&persisted.Suite,
			&persisted.PublicKey,
			&persisted.ActivatedAt,
		)
		if err == nil {
			if persisted.Suite != key.Suite ||
				persisted.ActivatedAt != key.ActivatedAt ||
				!bytes.Equal(persisted.PublicKey, key.PublicKey) {
				return store.ErrGlobalIdentityKeyMismatch
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("read global identity VOPRF key metadata: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO global_identity_voprf_keys (
				key_version, suite, public_key, activated_at
			) VALUES (?, ?, ?, ?)`,
			key.KeyVersion,
			key.Suite,
			key.PublicKey,
			key.ActivatedAt,
		); err != nil {
			return fmt.Errorf("persist global identity VOPRF key metadata: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit global identity key metadata sync: %w", err)
	}
	return nil
}

func (sqliteStore *Store) GlobalIdentityVOPRFKey(
	ctx context.Context,
	version int64,
) (store.GlobalIdentityVOPRFKey, error) {
	var key store.GlobalIdentityVOPRFKey
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT key_version, suite, public_key, activated_at
		FROM global_identity_voprf_keys
		WHERE key_version = ?`,
		version,
	).Scan(
		&key.KeyVersion,
		&key.Suite,
		&key.PublicKey,
		&key.ActivatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.GlobalIdentityVOPRFKey{}, store.ErrNotFound
		}
		return store.GlobalIdentityVOPRFKey{}, fmt.Errorf(
			"read global identity VOPRF key: %w",
			err,
		)
	}
	return key, nil
}

func (sqliteStore *Store) GlobalIdentityEvaluationByIdempotency(
	ctx context.Context,
	deploymentID string,
	idempotencyKey string,
) (store.GlobalIdentityEvaluationRecord, error) {
	return scanGlobalIdentityEvaluation(sqliteStore.db.QueryRowContext(
		ctx,
		globalIdentityEvaluationSelect+
			" WHERE deployment_id = ? AND idempotency_key = ?",
		deploymentID,
		idempotencyKey,
	))
}

func (sqliteStore *Store) CountGlobalIdentityEvaluationsSince(
	ctx context.Context,
	deploymentID string,
	since string,
) (int64, error) {
	var count int64
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM global_identity_evaluations
		WHERE deployment_id = ? AND evaluated_at >= ?`,
		deploymentID,
		since,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count recent global identity evaluations: %w", err)
	}
	return count, nil
}

func (sqliteStore *Store) AcceptGlobalIdentityEvaluation(
	ctx context.Context,
	input store.GlobalIdentityEvaluationInput,
) (store.GlobalIdentityEvaluationRecord, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.GlobalIdentityEvaluationRecord{}, false,
			fmt.Errorf("begin global identity evaluation audit: %w", err)
	}
	defer tx.Rollback()

	existing, err := scanGlobalIdentityEvaluation(tx.QueryRowContext(
		ctx,
		globalIdentityEvaluationSelect+
			" WHERE deployment_id = ? AND idempotency_key = ?",
		input.DeploymentID,
		input.IdempotencyKey,
	))
	if err == nil {
		if existing.PayloadHash != input.PayloadHash {
			return store.GlobalIdentityEvaluationRecord{}, false,
				store.ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return store.GlobalIdentityEvaluationRecord{}, false,
				fmt.Errorf("commit duplicate global identity evaluation: %w", err)
		}
		return existing, true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.GlobalIdentityEvaluationRecord{}, false, err
	}

	var nonceRequestHash string
	err = tx.QueryRowContext(ctx, `
		SELECT request_hash
		FROM global_identity_evaluations
		WHERE deployment_id = ? AND request_nonce = ?`,
		input.DeploymentID,
		input.Nonce,
	).Scan(&nonceRequestHash)
	if err == nil {
		if nonceRequestHash != input.RequestHash {
			return store.GlobalIdentityEvaluationRecord{}, false,
				store.ErrReplayConflict
		}
		return store.GlobalIdentityEvaluationRecord{}, false,
			store.ErrInconsistentState
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return store.GlobalIdentityEvaluationRecord{}, false,
			fmt.Errorf("read global identity evaluation nonce: %w", err)
	}
	active, err := operatorDeploymentActiveTx(ctx, tx, input.DeploymentID)
	if err != nil {
		return store.GlobalIdentityEvaluationRecord{}, false, err
	}
	if !active {
		return store.GlobalIdentityEvaluationRecord{}, false,
			store.ErrDeploymentInactive
	}
	var persistedPublicKey []byte
	var suite string
	if err := tx.QueryRowContext(ctx, `
		SELECT suite, public_key
		FROM global_identity_voprf_keys
		WHERE key_version = ?`,
		input.KeyVersion,
	).Scan(&suite, &persistedPublicKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.GlobalIdentityEvaluationRecord{}, false, store.ErrNotFound
		}
		return store.GlobalIdentityEvaluationRecord{}, false,
			fmt.Errorf("read evaluation VOPRF key: %w", err)
	}
	if suite != input.Suite || !bytes.Equal(persistedPublicKey, input.PublicKey) {
		return store.GlobalIdentityEvaluationRecord{}, false,
			store.ErrGlobalIdentityKeyMismatch
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO global_identity_evaluations (
			evaluation_id,
			deployment_id,
			idempotency_key,
			request_nonce,
			request_timestamp,
			request_hash,
			request_signature,
			payload_hash,
			key_version,
			suite,
			blinded_element,
			public_key,
			evaluated_element,
			proof,
			response_hash,
			evaluated_at,
			receipt_signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		input.EvaluationID,
		input.DeploymentID,
		input.IdempotencyKey,
		input.Nonce,
		input.RequestTimestamp,
		input.RequestHash,
		input.RequestSignature,
		input.PayloadHash,
		input.KeyVersion,
		input.Suite,
		input.BlindedElement,
		input.PublicKey,
		input.EvaluatedElement,
		input.Proof,
		input.ResponseHash,
		input.EvaluatedAt,
		input.ReceiptSignature,
	); err != nil {
		return store.GlobalIdentityEvaluationRecord{}, false,
			fmt.Errorf("persist global identity evaluation audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return store.GlobalIdentityEvaluationRecord{}, false,
			fmt.Errorf("commit global identity evaluation audit: %w", err)
	}
	return store.GlobalIdentityEvaluationRecord{
		GlobalIdentityEvaluationInput: input,
	}, false, nil
}

func scanGlobalIdentityEvaluation(
	scanner rowScanner,
) (store.GlobalIdentityEvaluationRecord, error) {
	var record store.GlobalIdentityEvaluationRecord
	if err := scanner.Scan(
		&record.EvaluationID,
		&record.DeploymentID,
		&record.IdempotencyKey,
		&record.Nonce,
		&record.RequestTimestamp,
		&record.RequestHash,
		&record.RequestSignature,
		&record.PayloadHash,
		&record.KeyVersion,
		&record.Suite,
		&record.BlindedElement,
		&record.PublicKey,
		&record.EvaluatedElement,
		&record.Proof,
		&record.ResponseHash,
		&record.EvaluatedAt,
		&record.ReceiptSignature,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.GlobalIdentityEvaluationRecord{}, store.ErrNotFound
		}
		return store.GlobalIdentityEvaluationRecord{},
			fmt.Errorf("scan global identity evaluation: %w", err)
	}
	return record, nil
}
