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

const operatorClaimStatusSelect = `
	SELECT
		deployment_id,
		claim_action_id,
		claim_audit_index,
		claim_audit_hash,
		group_id,
		legal_name,
		verification_state,
		submitted_at,
		review_id,
		review_index,
		review_hash,
		approved_at,
		updated_at,
		private_record_hash
	FROM operator_claim_status`

func (sqliteStore *Store) OperatorClaimStatus(
	ctx context.Context,
	deploymentID string,
) (store.OperatorClaimStatus, error) {
	return scanOperatorClaimStatus(sqliteStore.db.QueryRowContext(
		ctx,
		operatorClaimStatusSelect+" WHERE deployment_id = ?",
		deploymentID,
	))
}

func (sqliteStore *Store) OperatorClaimSubmission(
	ctx context.Context,
	deploymentID string,
) (store.OperatorClaimSubmission, store.OperatorClaimStatus, error) {
	status, err := sqliteStore.OperatorClaimStatus(ctx, deploymentID)
	if err != nil {
		return store.OperatorClaimSubmission{}, store.OperatorClaimStatus{}, err
	}
	submission, err := scanOperatorClaimSubmission(sqliteStore.db.QueryRowContext(ctx, `
		SELECT
			claim_action_id,
			deployment_id,
			group_id,
			legal_name,
			registration_number,
			jurisdiction,
			registered_address,
			website,
			verification_contact_name,
			verification_contact_role,
			verification_contact_email,
			authority_attested,
			operator_avatar_url,
			payload_hash,
			submitted_at,
			private_record_hash
		FROM operator_claim_verification_submissions
		WHERE claim_action_id = ?`,
		status.ClaimActionID,
	))
	if err != nil {
		return store.OperatorClaimSubmission{}, store.OperatorClaimStatus{}, err
	}
	return submission, status, nil
}

func (sqliteStore *Store) OperatorClaims(
	ctx context.Context,
	query store.OperatorClaimQuery,
) (store.OperatorClaimPage, error) {
	statement := operatorClaimStatusSelect + `
		WHERE (? = '' OR verification_state = ?)
		  AND deployment_id > ?
		ORDER BY deployment_id
		LIMIT ?`
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		statement,
		query.Status,
		query.Status,
		query.AfterDeploymentID,
		query.Limit+1,
	)
	if err != nil {
		return store.OperatorClaimPage{}, fmt.Errorf("list operator claim statuses: %w", err)
	}
	defer rows.Close()

	items := make([]store.OperatorClaimStatus, 0, query.Limit+1)
	for rows.Next() {
		status, err := scanOperatorClaimStatus(rows)
		if err != nil {
			return store.OperatorClaimPage{}, err
		}
		items = append(items, status)
	}
	if err := rows.Err(); err != nil {
		return store.OperatorClaimPage{}, fmt.Errorf("iterate operator claim statuses: %w", err)
	}
	page := store.OperatorClaimPage{Items: items}
	if len(items) > query.Limit {
		page.NextDeploymentID = items[query.Limit-1].DeploymentID
		page.Items = items[:query.Limit]
	}
	return page, nil
}

func (sqliteStore *Store) ApproveOperatorClaim(
	ctx context.Context,
	input store.OperatorClaimReviewInput,
	signReview store.OperatorClaimReviewSigner,
) (store.OperatorClaimReview, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.OperatorClaimReview{}, false, fmt.Errorf("begin operator claim review: %w", err)
	}
	defer tx.Rollback()

	existing, err := operatorClaimReviewByIdempotencyTx(ctx, tx, input.IdempotencyKey)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return store.OperatorClaimReview{}, false, err
	}
	if err == nil {
		if existing.DeploymentID != input.DeploymentID ||
			existing.ClaimActionID != input.ClaimActionID ||
			existing.GroupID != input.GroupID ||
			existing.LegalName != input.LegalName ||
			existing.ReviewerID != input.ReviewerID ||
			existing.ReviewReference != input.ReviewReference {
			return store.OperatorClaimReview{}, false, store.ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return store.OperatorClaimReview{}, false, fmt.Errorf(
				"commit duplicate operator claim review: %w",
				err,
			)
		}
		return existing, true, nil
	}

	status, err := scanOperatorClaimStatus(tx.QueryRowContext(
		ctx,
		operatorClaimStatusSelect+" WHERE deployment_id = ?",
		input.DeploymentID,
	))
	if err != nil {
		return store.OperatorClaimReview{}, false, err
	}
	if status.ClaimActionID != input.ClaimActionID ||
		status.GroupID != input.GroupID ||
		status.LegalName != input.LegalName {
		return store.OperatorClaimReview{}, false, store.ErrOperatorClaimStale
	}
	if status.VerificationState != protocol.OperatorClaimStatePendingReview {
		return store.OperatorClaimReview{}, false, store.ErrOperatorClaimAlreadyReviewed
	}
	if input.ReviewedAt < status.SubmittedAt {
		return store.OperatorClaimReview{}, false, store.ErrInconsistentState
	}
	head, err := operatorClaimReviewHeadTx(ctx, tx)
	if err != nil {
		return store.OperatorClaimReview{}, false, err
	}
	if head.ReviewedAt != "" {
		reviewedAt, parseErr := time.Parse(time.RFC3339Nano, input.ReviewedAt)
		headAt, headParseErr := time.Parse(time.RFC3339Nano, head.ReviewedAt)
		if parseErr != nil || headParseErr != nil || reviewedAt.Before(headAt) {
			return store.OperatorClaimReview{}, false, store.ErrInconsistentState
		}
	}

	review := store.OperatorClaimReview{
		ReviewIndex:        head.ReviewIndex + 1,
		ReviewID:           input.CandidateReviewID,
		DeploymentID:       input.DeploymentID,
		ClaimActionID:      input.ClaimActionID,
		GroupID:            input.GroupID,
		LegalName:          input.LegalName,
		Decision:           protocol.OperatorClaimReviewApproved,
		ReviewerID:         input.ReviewerID,
		ReviewReference:    input.ReviewReference,
		IdempotencyKey:     input.IdempotencyKey,
		ReviewedAt:         input.ReviewedAt,
		PreviousReviewHash: head.ReviewHash,
		RegistryKeyID:      input.RegistryKeyID,
	}
	unsigned := operatorClaimReviewReceipt(review, input.RegistryScope)
	review.ReviewHash = protocol.Digest(protocol.OperatorClaimReviewHashMessage(unsigned))
	review.Signature, err = signReview(review)
	if err != nil {
		return store.OperatorClaimReview{}, false, fmt.Errorf("sign operator claim review: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO operator_claim_reviews (
			review_index,
			review_id,
			deployment_id,
			claim_action_id,
			group_id,
			legal_name,
			decision,
			reviewer_id,
			review_reference,
			idempotency_key,
			reviewed_at,
			previous_review_hash,
			review_hash,
			registry_key_id,
			signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		review.ReviewIndex,
		review.ReviewID,
		review.DeploymentID,
		review.ClaimActionID,
		review.GroupID,
		review.LegalName,
		review.Decision,
		review.ReviewerID,
		review.ReviewReference,
		review.IdempotencyKey,
		review.ReviewedAt,
		review.PreviousReviewHash,
		review.ReviewHash,
		review.RegistryKeyID,
		review.Signature,
	); err != nil {
		return store.OperatorClaimReview{}, false, fmt.Errorf("append operator claim review: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE operator_claim_status
		SET verification_state = ?,
		    review_id = ?,
		    review_index = ?,
		    review_hash = ?,
		    approved_at = ?,
		    updated_at = ?
		WHERE deployment_id = ?
		  AND claim_action_id = ?
		  AND verification_state = ?`,
		protocol.OperatorClaimStateApproved,
		review.ReviewID,
		review.ReviewIndex,
		review.ReviewHash,
		review.ReviewedAt,
		review.ReviewedAt,
		review.DeploymentID,
		review.ClaimActionID,
		protocol.OperatorClaimStatePendingReview,
	)
	if err != nil {
		return store.OperatorClaimReview{}, false, fmt.Errorf("update approved operator claim status: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return store.OperatorClaimReview{}, false, store.ErrOperatorClaimStale
	}
	if err := tx.Commit(); err != nil {
		return store.OperatorClaimReview{}, false, fmt.Errorf("commit operator claim review: %w", err)
	}
	return review, false, nil
}

func operatorClaimReviewHeadTx(
	ctx context.Context,
	tx *sql.Tx,
) (store.OperatorClaimReview, error) {
	return operatorClaimReviewHeadQuery(ctx, tx)
}

func operatorClaimReviewHeadQuery(
	ctx context.Context,
	queryer operatorAuditQueryer,
) (store.OperatorClaimReview, error) {
	review, err := scanOperatorClaimReview(queryer.QueryRowContext(ctx, `
		SELECT
			review_index,
			review_id,
			deployment_id,
			claim_action_id,
			group_id,
			legal_name,
			decision,
			reviewer_id,
			review_reference,
			idempotency_key,
			reviewed_at,
			previous_review_hash,
			review_hash,
			registry_key_id,
			signature
		FROM operator_claim_reviews
		ORDER BY review_index DESC
		LIMIT 1`))
	if errors.Is(err, store.ErrNotFound) {
		return store.OperatorClaimReview{ReviewHash: protocol.OperatorClaimReviewZeroHash}, nil
	}
	return review, err
}

func operatorClaimReviewByIdempotencyTx(
	ctx context.Context,
	tx *sql.Tx,
	idempotencyKey string,
) (store.OperatorClaimReview, error) {
	return scanOperatorClaimReview(tx.QueryRowContext(ctx, `
		SELECT
			review_index,
			review_id,
			deployment_id,
			claim_action_id,
			group_id,
			legal_name,
			decision,
			reviewer_id,
			review_reference,
			idempotency_key,
			reviewed_at,
			previous_review_hash,
			review_hash,
			registry_key_id,
			signature
		FROM operator_claim_reviews
		WHERE idempotency_key = ?`,
		idempotencyKey,
	))
}

func scanOperatorClaimStatus(scanner rowScanner) (store.OperatorClaimStatus, error) {
	var status store.OperatorClaimStatus
	if err := scanner.Scan(
		&status.DeploymentID,
		&status.ClaimActionID,
		&status.ClaimAuditIndex,
		&status.ClaimAuditHash,
		&status.GroupID,
		&status.LegalName,
		&status.VerificationState,
		&status.SubmittedAt,
		&status.ReviewID,
		&status.ReviewIndex,
		&status.ReviewHash,
		&status.ApprovedAt,
		&status.UpdatedAt,
		&status.PrivateRecordHash,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.OperatorClaimStatus{}, store.ErrNotFound
		}
		return store.OperatorClaimStatus{}, fmt.Errorf("read operator claim status: %w", err)
	}
	return status, nil
}

func scanOperatorClaimSubmission(scanner rowScanner) (store.OperatorClaimSubmission, error) {
	var submission store.OperatorClaimSubmission
	if err := scanner.Scan(
		&submission.ClaimActionID,
		&submission.DeploymentID,
		&submission.GroupID,
		&submission.LegalName,
		&submission.RegistrationNumber,
		&submission.Jurisdiction,
		&submission.RegisteredAddress,
		&submission.Website,
		&submission.VerificationContactName,
		&submission.VerificationContactRole,
		&submission.VerificationContactEmail,
		&submission.AuthorityAttested,
		&submission.OperatorAvatarURL,
		&submission.PayloadHash,
		&submission.SubmittedAt,
		&submission.PrivateRecordHash,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.OperatorClaimSubmission{}, store.ErrNotFound
		}
		return store.OperatorClaimSubmission{}, fmt.Errorf(
			"read private operator claim submission: %w",
			err,
		)
	}
	return submission, nil
}

func scanOperatorClaimReview(scanner rowScanner) (store.OperatorClaimReview, error) {
	var review store.OperatorClaimReview
	if err := scanner.Scan(
		&review.ReviewIndex,
		&review.ReviewID,
		&review.DeploymentID,
		&review.ClaimActionID,
		&review.GroupID,
		&review.LegalName,
		&review.Decision,
		&review.ReviewerID,
		&review.ReviewReference,
		&review.IdempotencyKey,
		&review.ReviewedAt,
		&review.PreviousReviewHash,
		&review.ReviewHash,
		&review.RegistryKeyID,
		&review.Signature,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.OperatorClaimReview{}, store.ErrNotFound
		}
		return store.OperatorClaimReview{}, fmt.Errorf("read operator claim review: %w", err)
	}
	return review, nil
}

func operatorClaimReviewReceipt(
	review store.OperatorClaimReview,
	registryScope string,
) protocol.OperatorClaimReviewReceipt {
	return protocol.OperatorClaimReviewReceipt{
		ReviewIndex:        review.ReviewIndex,
		ReviewID:           review.ReviewID,
		DeploymentID:       review.DeploymentID,
		ClaimActionID:      review.ClaimActionID,
		GroupID:            review.GroupID,
		LegalName:          review.LegalName,
		Decision:           review.Decision,
		ReviewerID:         review.ReviewerID,
		ReviewReference:    review.ReviewReference,
		IdempotencyKey:     review.IdempotencyKey,
		ReviewedAt:         review.ReviewedAt,
		PreviousReviewHash: review.PreviousReviewHash,
		ReviewHash:         review.ReviewHash,
		RegistryScope:      registryScope,
		RegistryKeyID:      review.RegistryKeyID,
	}
}
