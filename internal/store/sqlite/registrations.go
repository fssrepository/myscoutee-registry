package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func (sqliteStore *Store) RegisterDeployment(
	ctx context.Context,
	input store.RegistrationInput,
) (store.Deployment, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.Deployment{}, false, fmt.Errorf("begin deployment registration: %w", err)
	}
	defer tx.Rollback()

	nonceUsed, err := nonceState(ctx, tx, input.SignerFingerprint, input.Nonce, input.RequestHash)
	if err != nil {
		return store.Deployment{}, false, err
	}
	idempotency, err := readIdempotency(ctx, tx, input.SignerFingerprint, input.IdempotencyKey)
	if err != nil {
		return store.Deployment{}, false, err
	}
	if idempotency != nil {
		if idempotency.PayloadHash != input.PayloadHash {
			return store.Deployment{}, false, store.ErrIdempotencyConflict
		}
		if idempotency.ResultType != "deployment" {
			return store.Deployment{}, false, store.ErrInconsistentState
		}
		deployment, err := deploymentByIDTx(ctx, tx, idempotency.ResultID)
		if err != nil {
			return store.Deployment{}, false, err
		}
		if !nonceUsed {
			if err := insertNonce(
				ctx,
				tx,
				registrationNonce(input, idempotency.ResultID),
			); err != nil {
				return store.Deployment{}, false, err
			}
		}
		if err := tx.Commit(); err != nil {
			return store.Deployment{}, false, fmt.Errorf("commit duplicate deployment registration: %w", err)
		}
		return deployment, true, nil
	}
	if nonceUsed {
		return store.Deployment{}, false, store.ErrInconsistentState
	}

	existing, err := deploymentByFingerprintTx(ctx, tx, input.SignerFingerprint)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return store.Deployment{}, false, err
	}
	if existing != nil {
		if err := insertNonce(
			ctx,
			tx,
			registrationNonce(input, existing.DeploymentID),
		); err != nil {
			return store.Deployment{}, false, err
		}
		if err := insertIdempotency(
			ctx,
			tx,
			input.SignerFingerprint,
			input.IdempotencyKey,
			input.PayloadHash,
			"deployment",
			existing.DeploymentID,
			input.CandidateRegisteredAt,
		); err != nil {
			return store.Deployment{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return store.Deployment{}, false, fmt.Errorf("commit fingerprint-idempotent registration: %w", err)
		}
		return *existing, true, nil
	}

	_, err = tx.ExecContext(ctx, `
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
		input.CandidateDeploymentID,
		input.PublicKeyDER,
		input.SignerFingerprint,
		input.KeyAlgorithm,
		input.SoftwareVersion,
		input.RequestTimestamp,
		input.Nonce,
		input.IdempotencyKey,
		input.RequestSignature,
		input.CandidateRegisteredAt,
		input.PayloadHash,
		input.CandidateReceiptSignature,
	)
	if err != nil {
		return store.Deployment{}, false, fmt.Errorf("insert deployment: %w", err)
	}
	if err := insertNonce(
		ctx,
		tx,
		registrationNonce(input, input.CandidateDeploymentID),
	); err != nil {
		return store.Deployment{}, false, err
	}
	if err := insertIdempotency(
		ctx,
		tx,
		input.SignerFingerprint,
		input.IdempotencyKey,
		input.PayloadHash,
		"deployment",
		input.CandidateDeploymentID,
		input.CandidateRegisteredAt,
	); err != nil {
		return store.Deployment{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return store.Deployment{}, false, fmt.Errorf("commit deployment registration: %w", err)
	}
	return store.Deployment{
		DeploymentID:               input.CandidateDeploymentID,
		PublicKeyDER:               append([]byte(nil), input.PublicKeyDER...),
		PublicKeyFingerprint:       input.SignerFingerprint,
		KeyAlgorithm:               input.KeyAlgorithm,
		SoftwareVersion:            input.SoftwareVersion,
		RegistrationTimestamp:      input.RequestTimestamp,
		RegistrationNonce:          input.Nonce,
		RegistrationIdempotencyKey: input.IdempotencyKey,
		RegistrationSignature:      append([]byte(nil), input.RequestSignature...),
		RegisteredAt:               input.CandidateRegisteredAt,
		PayloadHash:                input.PayloadHash,
		ReceiptSignature:           append([]byte(nil), input.CandidateReceiptSignature...),
	}, false, nil
}

func registrationNonce(input store.RegistrationInput, deploymentID string) acceptedNonce {
	return acceptedNonce{
		Signer:           input.SignerFingerprint,
		Nonce:            input.Nonce,
		RequestHash:      input.RequestHash,
		IdempotencyKey:   input.IdempotencyKey,
		PayloadHash:      input.PayloadHash,
		RequestTimestamp: input.RequestTimestamp,
		RequestSignature: input.RequestSignature,
		ResultType:       "deployment",
		ResultID:         deploymentID,
		AcceptedAt:       input.CandidateRegisteredAt,
	}
}

func (sqliteStore *Store) Deployment(ctx context.Context, deploymentID string) (store.Deployment, error) {
	row := sqliteStore.db.QueryRowContext(ctx, `
		SELECT
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
		FROM deployments
		WHERE deployment_id = ?`,
		deploymentID,
	)
	return scanDeployment(row)
}

func deploymentByIDTx(ctx context.Context, tx *sql.Tx, deploymentID string) (store.Deployment, error) {
	row := tx.QueryRowContext(ctx, `
		SELECT
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
		FROM deployments
		WHERE deployment_id = ?`,
		deploymentID,
	)
	return scanDeployment(row)
}

func deploymentByFingerprintTx(
	ctx context.Context,
	tx *sql.Tx,
	fingerprint string,
) (*store.Deployment, error) {
	row := tx.QueryRowContext(ctx, `
		SELECT
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
		FROM deployments
		WHERE public_key_fingerprint = ?`,
		fingerprint,
	)
	deployment, err := scanDeployment(row)
	if err != nil {
		return nil, err
	}
	return &deployment, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanDeployment(row rowScanner) (store.Deployment, error) {
	var deployment store.Deployment
	if err := row.Scan(
		&deployment.DeploymentID,
		&deployment.PublicKeyDER,
		&deployment.PublicKeyFingerprint,
		&deployment.KeyAlgorithm,
		&deployment.SoftwareVersion,
		&deployment.RegistrationTimestamp,
		&deployment.RegistrationNonce,
		&deployment.RegistrationIdempotencyKey,
		&deployment.RegistrationSignature,
		&deployment.RegisteredAt,
		&deployment.PayloadHash,
		&deployment.ReceiptSignature,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.Deployment{}, store.ErrNotFound
		}
		return store.Deployment{}, fmt.Errorf("read deployment: %w", err)
	}
	return deployment, nil
}
