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

const operatorClaimEligibilitySelect = `
	SELECT
		eligibility_index,
		eligibility_id,
		deployment_id,
		claim_action_id,
		group_id,
		legal_name,
		decision,
		actor_id,
		decision_reference,
		reason_code,
		idempotency_key,
		decided_at,
		previous_eligibility_hash,
		eligibility_hash,
		registry_key_id,
		signature
	FROM operator_claim_eligibility_events`

func (sqliteStore *Store) DecideOperatorClaimEligibility(
	ctx context.Context,
	input store.OperatorClaimEligibilityInput,
	signDecision store.OperatorClaimEligibilitySigner,
) (store.OperatorClaimEligibility, bool, error) {
	validDecision := (input.Decision == protocol.OperatorClaimEligibilitySuspend &&
		protocol.IsOperatorClaimEligibilityReasonCode(input.ReasonCode)) ||
		(input.Decision == protocol.OperatorClaimEligibilityReinstate &&
			input.ReasonCode == "")
	if !validDecision {
		return store.OperatorClaimEligibility{}, false, store.ErrInconsistentState
	}

	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.OperatorClaimEligibility{}, false, fmt.Errorf(
			"begin operator claim eligibility decision: %w",
			err,
		)
	}
	defer tx.Rollback()

	existing, err := operatorClaimEligibilityByIdempotencyTx(
		ctx,
		tx,
		input.IdempotencyKey,
	)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return store.OperatorClaimEligibility{}, false, err
	}
	if err == nil {
		if existing.DeploymentID != input.DeploymentID ||
			existing.ClaimActionID != input.ClaimActionID ||
			existing.GroupID != input.GroupID ||
			existing.LegalName != input.LegalName ||
			existing.Decision != input.Decision ||
			existing.ActorID != input.ActorID ||
			existing.DecisionReference != input.DecisionReference ||
			existing.ReasonCode != input.ReasonCode {
			return store.OperatorClaimEligibility{}, false,
				store.ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return store.OperatorClaimEligibility{}, false, fmt.Errorf(
				"commit duplicate operator claim eligibility decision: %w",
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
		return store.OperatorClaimEligibility{}, false, err
	}
	if status.ClaimActionID != input.ClaimActionID ||
		status.GroupID != input.GroupID ||
		status.LegalName != input.LegalName {
		return store.OperatorClaimEligibility{}, false,
			store.ErrOperatorClaimEligibilityStale
	}
	if status.VerificationState != protocol.OperatorClaimStateApproved {
		return store.OperatorClaimEligibility{}, false,
			store.ErrOperatorClaimNotEligible
	}

	var (
		currentClaimActionID string
		currentGroupID       string
		currentLegalName     string
		currentState         string
		approvedReviewIndex  int64
		approvedReviewHash   string
	)
	err = tx.QueryRowContext(ctx, `
		SELECT
			claim_action_id,
			group_id,
			legal_name,
			eligibility_state,
			approved_review_index,
			approved_review_hash
		FROM operator_claim_eligibility_current
		WHERE deployment_id = ?`,
		input.DeploymentID,
	).Scan(
		&currentClaimActionID,
		&currentGroupID,
		&currentLegalName,
		&currentState,
		&approvedReviewIndex,
		&approvedReviewHash,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.OperatorClaimEligibility{}, false,
				store.ErrOperatorClaimEligibilityStale
		}
		return store.OperatorClaimEligibility{}, false, fmt.Errorf(
			"read current operator claim eligibility: %w",
			err,
		)
	}
	if currentClaimActionID != input.ClaimActionID ||
		currentGroupID != input.GroupID ||
		currentLegalName != input.LegalName ||
		approvedReviewIndex != status.ReviewIndex ||
		approvedReviewHash != status.ReviewHash {
		return store.OperatorClaimEligibility{}, false,
			store.ErrOperatorClaimEligibilityStale
	}
	switch input.Decision {
	case protocol.OperatorClaimEligibilitySuspend:
		if currentState != protocol.OperatorEligibilityActive {
			return store.OperatorClaimEligibility{}, false,
				store.ErrOperatorClaimNotEligible
		}
	case protocol.OperatorClaimEligibilityReinstate:
		if currentState != protocol.OperatorEligibilitySuspended {
			return store.OperatorClaimEligibility{}, false,
				store.ErrOperatorClaimNotSuspended
		}
	}

	head, err := operatorClaimEligibilityHeadQuery(ctx, tx)
	if err != nil {
		return store.OperatorClaimEligibility{}, false, err
	}
	if input.DecidedAt < status.ApprovedAt {
		return store.OperatorClaimEligibility{}, false,
			store.ErrInconsistentState
	}
	if head.DecidedAt != "" {
		decidedAt, parseErr := time.Parse(time.RFC3339Nano, input.DecidedAt)
		headAt, headParseErr := time.Parse(time.RFC3339Nano, head.DecidedAt)
		if parseErr != nil || headParseErr != nil || decidedAt.Before(headAt) {
			return store.OperatorClaimEligibility{}, false,
				store.ErrInconsistentState
		}
	}

	decision := store.OperatorClaimEligibility{
		EligibilityIndex:         head.EligibilityIndex + 1,
		EligibilityID:            input.CandidateEligibilityID,
		DeploymentID:             input.DeploymentID,
		ClaimActionID:            input.ClaimActionID,
		GroupID:                  input.GroupID,
		LegalName:                input.LegalName,
		Decision:                 input.Decision,
		ActorID:                  input.ActorID,
		DecisionReference:        input.DecisionReference,
		ReasonCode:               input.ReasonCode,
		IdempotencyKey:           input.IdempotencyKey,
		DecidedAt:                input.DecidedAt,
		PreviousEligibilityHash: head.EligibilityHash,
		RegistryKeyID:            input.RegistryKeyID,
	}
	unsigned := operatorClaimEligibilityReceipt(decision, input.RegistryScope)
	decision.EligibilityHash = protocol.Digest(
		protocol.OperatorClaimEligibilityHashMessage(unsigned),
	)
	decision.Signature, err = signDecision(decision)
	if err != nil {
		return store.OperatorClaimEligibility{}, false, fmt.Errorf(
			"sign operator claim eligibility decision: %w",
			err,
		)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO operator_claim_eligibility_events (
			eligibility_index,
			eligibility_id,
			deployment_id,
			claim_action_id,
			group_id,
			legal_name,
			decision,
			actor_id,
			decision_reference,
			reason_code,
			idempotency_key,
			decided_at,
			previous_eligibility_hash,
			eligibility_hash,
			registry_key_id,
			signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		decision.EligibilityIndex,
		decision.EligibilityID,
		decision.DeploymentID,
		decision.ClaimActionID,
		decision.GroupID,
		decision.LegalName,
		decision.Decision,
		decision.ActorID,
		decision.DecisionReference,
		decision.ReasonCode,
		decision.IdempotencyKey,
		decision.DecidedAt,
		decision.PreviousEligibilityHash,
		decision.EligibilityHash,
		decision.RegistryKeyID,
		decision.Signature,
	); err != nil {
		return store.OperatorClaimEligibility{}, false, fmt.Errorf(
			"append operator claim eligibility decision: %w",
			err,
		)
	}
	nextState := protocol.OperatorEligibilitySuspended
	if decision.Decision == protocol.OperatorClaimEligibilityReinstate {
		nextState = protocol.OperatorEligibilityActive
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE operator_claim_eligibility_current
		SET eligibility_state = ?,
		    eligibility_id = ?,
		    eligibility_index = ?,
		    eligibility_hash = ?,
		    updated_at = ?
		WHERE deployment_id = ?
		  AND claim_action_id = ?
		  AND eligibility_state = ?`,
		nextState,
		decision.EligibilityID,
		decision.EligibilityIndex,
		decision.EligibilityHash,
		decision.DecidedAt,
		decision.DeploymentID,
		decision.ClaimActionID,
		currentState,
	)
	if err != nil {
		return store.OperatorClaimEligibility{}, false, fmt.Errorf(
			"update current operator claim eligibility: %w",
			err,
		)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return store.OperatorClaimEligibility{}, false,
			store.ErrOperatorClaimEligibilityStale
	}
	if err := tx.Commit(); err != nil {
		return store.OperatorClaimEligibility{}, false, fmt.Errorf(
			"commit operator claim eligibility decision: %w",
			err,
		)
	}
	return decision, false, nil
}

func (sqliteStore *Store) OperatorClaimEligibilityHead(
	ctx context.Context,
) (store.OperatorClaimEligibility, error) {
	return operatorClaimEligibilityHeadQuery(ctx, sqliteStore.db)
}

func operatorClaimEligibilityHeadQuery(
	ctx context.Context,
	queryer operatorActionQuerier,
) (store.OperatorClaimEligibility, error) {
	decision, err := scanOperatorClaimEligibility(queryer.QueryRowContext(
		ctx,
		operatorClaimEligibilitySelect+`
		ORDER BY eligibility_index DESC
		LIMIT 1`,
	))
	if errors.Is(err, store.ErrNotFound) {
		return store.OperatorClaimEligibility{
			EligibilityHash: protocol.OperatorClaimEligibilityZeroHash,
		}, nil
	}
	return decision, err
}

func operatorClaimEligibilityByIdempotencyTx(
	ctx context.Context,
	tx *sql.Tx,
	idempotencyKey string,
) (store.OperatorClaimEligibility, error) {
	return scanOperatorClaimEligibility(tx.QueryRowContext(
		ctx,
		operatorClaimEligibilitySelect+" WHERE idempotency_key = ?",
		idempotencyKey,
	))
}

func scanOperatorClaimEligibility(
	scanner rowScanner,
) (store.OperatorClaimEligibility, error) {
	var decision store.OperatorClaimEligibility
	if err := scanner.Scan(
		&decision.EligibilityIndex,
		&decision.EligibilityID,
		&decision.DeploymentID,
		&decision.ClaimActionID,
		&decision.GroupID,
		&decision.LegalName,
		&decision.Decision,
		&decision.ActorID,
		&decision.DecisionReference,
		&decision.ReasonCode,
		&decision.IdempotencyKey,
		&decision.DecidedAt,
		&decision.PreviousEligibilityHash,
		&decision.EligibilityHash,
		&decision.RegistryKeyID,
		&decision.Signature,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.OperatorClaimEligibility{}, store.ErrNotFound
		}
		return store.OperatorClaimEligibility{}, fmt.Errorf(
			"read operator claim eligibility decision: %w",
			err,
		)
	}
	return decision, nil
}

func operatorClaimEligibilityReceipt(
	decision store.OperatorClaimEligibility,
	registryScope string,
) protocol.OperatorClaimEligibilityReceipt {
	return protocol.OperatorClaimEligibilityReceipt{
		EligibilityIndex:         decision.EligibilityIndex,
		EligibilityID:            decision.EligibilityID,
		DeploymentID:             decision.DeploymentID,
		ClaimActionID:            decision.ClaimActionID,
		GroupID:                  decision.GroupID,
		LegalName:                decision.LegalName,
		Decision:                 decision.Decision,
		ActorID:                  decision.ActorID,
		DecisionReference:        decision.DecisionReference,
		ReasonCode:               decision.ReasonCode,
		IdempotencyKey:           decision.IdempotencyKey,
		DecidedAt:                decision.DecidedAt,
		PreviousEligibilityHash: decision.PreviousEligibilityHash,
		EligibilityHash:          decision.EligibilityHash,
		RegistryScope:            registryScope,
		RegistryKeyID:            decision.RegistryKeyID,
	}
}
