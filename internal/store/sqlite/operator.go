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

type operatorClaimState struct {
	AuditIndex        int64
	Claimed           bool
	ClaimState        string
	GroupID           string
	OperatorName      string
	OperatorAvatarURL string
}

type operatorMembership struct {
	operatorClaimState
	LinkID              string
	RelatedDeploymentID string
}

type operatorLink struct {
	TargetDeploymentID string
	IssuerDeploymentID string
	GroupID            string
	LinkID             string
	TokenID            string
}

func (sqliteStore *Store) AppendOperatorAction(
	ctx context.Context,
	input store.OperatorActionInput,
	signReceipt store.OperatorAuditSigner,
) (store.OperatorAuditEvent, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.OperatorAuditEvent{}, false, fmt.Errorf("begin operator action: %w", err)
	}
	defer tx.Rollback()

	if err := requireDeploymentTx(ctx, tx, input.DeploymentID); err != nil {
		return store.OperatorAuditEvent{}, false, err
	}

	nonceActionID, nonceRequestHash, err := operatorNonceStateTx(
		ctx,
		tx,
		input.DeploymentID,
		input.Nonce,
	)
	if err != nil {
		return store.OperatorAuditEvent{}, false, err
	}
	if nonceActionID != "" {
		if nonceRequestHash != input.RequestHash {
			return store.OperatorAuditEvent{}, false, store.ErrReplayConflict
		}
		event, err := operatorActionByIDTx(ctx, tx, nonceActionID)
		if err != nil {
			return store.OperatorAuditEvent{}, false, err
		}
		if event.IdempotencyKey != input.IdempotencyKey ||
			event.PayloadHash != input.PayloadHash {
			return store.OperatorAuditEvent{}, false, store.ErrInconsistentState
		}
		if err := tx.Commit(); err != nil {
			return store.OperatorAuditEvent{}, false, fmt.Errorf(
				"commit duplicate operator nonce: %w",
				err,
			)
		}
		return event, true, nil
	}

	existing, err := operatorActionByIdempotencyTx(
		ctx,
		tx,
		input.DeploymentID,
		input.IdempotencyKey,
	)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return store.OperatorAuditEvent{}, false, err
	}
	if err == nil {
		if existing.PayloadHash != input.PayloadHash {
			return store.OperatorAuditEvent{}, false, store.ErrIdempotencyConflict
		}
		if err := insertOperatorNonceTx(ctx, tx, input, existing.ActionID); err != nil {
			return store.OperatorAuditEvent{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return store.OperatorAuditEvent{}, false, fmt.Errorf(
				"commit duplicate operator action: %w",
				err,
			)
		}
		return existing, true, nil
	}

	if err := ensureAcceptedAtAfterRegistryCreation(ctx, tx, input.AcceptedAt); err != nil {
		return store.OperatorAuditEvent{}, false, err
	}
	head, err := operatorAuditHeadTx(ctx, tx)
	if err != nil {
		return store.OperatorAuditEvent{}, false, err
	}
	if err := ensureAcceptedAtNotBeforeHead(input.AcceptedAt, head.AcceptedAt); err != nil {
		return store.OperatorAuditEvent{}, false, err
	}

	event := store.OperatorAuditEvent{
		AuditIndex:          head.AuditIndex + 1,
		ActionID:            input.CandidateActionID,
		DeploymentID:        input.DeploymentID,
		SubjectDeploymentID: input.DeploymentID,
		Action:              input.Action,
		RequestTimestamp:    input.RequestTimestamp,
		Nonce:               input.Nonce,
		IdempotencyKey:      input.IdempotencyKey,
		PayloadHash:         input.PayloadHash,
		RequestHash:         input.RequestHash,
		DeploymentSignature: append([]byte(nil), input.DeploymentSignature...),
		AcceptedAt:          input.AcceptedAt,
		PreviousAuditHash:   head.AuditHash,
		RegistryKeyID:       input.RegistryKeyID,
	}
	if err := deriveOperatorActionTx(ctx, tx, input, &event); err != nil {
		return store.OperatorAuditEvent{}, false, err
	}
	event.AuditHash = protocol.Digest(protocol.OperatorAuditMessage(
		event.AuditIndex,
		event.ActionID,
		event.DeploymentID,
		event.SubjectDeploymentID,
		event.RelatedDeploymentID,
		event.Action,
		event.PayloadHash,
		event.AcceptedAt,
		event.ClaimState,
		event.GroupID,
		event.LinkID,
		event.TokenID,
		event.ClientTokenHash,
		event.TokenExpiresAt,
		event.PreviousAuditHash,
	))
	event.ReceiptSignature, err = signReceipt(event)
	if err != nil {
		return store.OperatorAuditEvent{}, false, fmt.Errorf("sign operator action receipt: %w", err)
	}

	if err := insertOperatorAuditEventTx(ctx, tx, event); err != nil {
		return store.OperatorAuditEvent{}, false, err
	}
	if err := writeOperatorClaimStateTx(ctx, tx, input, event); err != nil {
		return store.OperatorAuditEvent{}, false, err
	}
	if err := insertOperatorNonceTx(ctx, tx, input, event.ActionID); err != nil {
		return store.OperatorAuditEvent{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return store.OperatorAuditEvent{}, false, fmt.Errorf("commit operator action: %w", err)
	}
	return event, false, nil
}

func deriveOperatorActionTx(
	ctx context.Context,
	tx *sql.Tx,
	input store.OperatorActionInput,
	event *store.OperatorAuditEvent,
) error {
	active, err := operatorDeploymentActiveTx(ctx, tx, input.DeploymentID)
	if err != nil {
		return err
	}
	claim, err := operatorClaimTx(ctx, tx, input.DeploymentID, 0)
	if err != nil {
		return err
	}

	switch input.Action {
	case protocol.OperatorActionClaim:
		if !active {
			return store.ErrDeploymentInactive
		}
		event.ClaimState = protocol.OperatorClaimStatePendingReview
		event.OperatorName = input.LegalName
		event.OperatorAvatarURL = input.OperatorAvatarURL
		if claim.Claimed {
			event.GroupID = claim.GroupID
		} else {
			event.GroupID = input.CandidateGroupID
		}
	case protocol.OperatorActionWithdrawClaim:
		if !claim.Claimed {
			return store.ErrOperatorClaimRequired
		}
		event.ClaimState = protocol.OperatorClaimStateWithdrawn
		event.GroupID = claim.GroupID
		event.OperatorName = claim.OperatorName
		event.OperatorAvatarURL = claim.OperatorAvatarURL
	case protocol.OperatorActionIssueClientToken:
		membership, err := operatorMembershipTx(ctx, tx, input.DeploymentID, 0)
		if err != nil {
			return err
		}
		if !active || !membership.Claimed {
			return store.ErrOperatorClaimRequired
		}
		event.ClaimState = membership.ClaimState
		event.GroupID = membership.GroupID
		event.TokenID = input.CandidateTokenID
		event.ClientTokenHash = input.CandidateClientTokenHash
		event.TokenTTLSeconds = input.TokenTTLSeconds
		event.TokenExpiresAt = input.CandidateTokenExpiresAt
	case protocol.OperatorActionRevokeClientToken:
		token, err := activeClientTokenTx(ctx, tx, input.TokenID, "", input.AcceptedAt)
		if err != nil {
			return err
		}
		if token.DeploymentID != input.DeploymentID {
			return store.ErrOperatorActionConflict
		}
		event.GroupID = token.GroupID
		event.TokenID = token.TokenID
		event.ClientTokenHash = token.ClientTokenHash
		event.TokenExpiresAt = token.TokenExpiresAt
	case protocol.OperatorActionRedeemClientToken:
		if !active || !claim.Claimed {
			return store.ErrOperatorClaimRequired
		}
		targetMembership, err := operatorMembershipTx(ctx, tx, input.DeploymentID, 0)
		if err != nil {
			return err
		}
		if targetMembership.LinkID != "" {
			return store.ErrOperatorActionConflict
		}
		token, err := activeClientTokenTx(
			ctx,
			tx,
			"",
			input.ClientTokenHash,
			input.AcceptedAt,
		)
		if err != nil {
			return err
		}
		if token.DeploymentID == input.DeploymentID {
			return store.ErrOperatorActionConflict
		}
		issuerActive, err := operatorDeploymentActiveTx(ctx, tx, token.DeploymentID)
		if err != nil {
			return err
		}
		issuerMembership, err := operatorMembershipTx(ctx, tx, token.DeploymentID, 0)
		if err != nil {
			return err
		}
		if !issuerActive || !issuerMembership.Claimed {
			return store.ErrOperatorClaimRequired
		}
		if issuerMembership.GroupID == targetMembership.GroupID {
			return store.ErrOperatorActionConflict
		}
		event.ClaimState = claim.ClaimState
		event.GroupID = issuerMembership.GroupID
		event.LinkID = input.CandidateLinkID
		event.TokenID = token.TokenID
		event.ClientTokenHash = token.ClientTokenHash
		event.RelatedDeploymentID = token.DeploymentID
	case protocol.OperatorActionRevokeGroupLink:
		link, err := activeOperatorLinkTx(ctx, tx, input.LinkID)
		if err != nil {
			return err
		}
		callerMembership, err := operatorMembershipTx(ctx, tx, input.DeploymentID, 0)
		if err != nil {
			return err
		}
		if input.DeploymentID != link.TargetDeploymentID &&
			callerMembership.GroupID != link.GroupID {
			return store.ErrOperatorActionConflict
		}
		event.SubjectDeploymentID = link.TargetDeploymentID
		event.RelatedDeploymentID = link.IssuerDeploymentID
		event.GroupID = link.GroupID
		event.LinkID = link.LinkID
		event.TokenID = link.TokenID
	case protocol.OperatorActionDeactivateDeployment:
		if !active {
			return store.ErrOperatorActionConflict
		}
	case protocol.OperatorActionReactivateDeployment:
		if active {
			return store.ErrOperatorActionConflict
		}
	default:
		return store.ErrOperatorActionConflict
	}
	return nil
}

type operatorToken struct {
	DeploymentID    string
	GroupID         string
	TokenID         string
	ClientTokenHash string
	TokenExpiresAt  string
	AuditIndex      int64
}

func activeClientTokenTx(
	ctx context.Context,
	tx *sql.Tx,
	tokenID string,
	tokenHash string,
	at string,
) (operatorToken, error) {
	query := `
		SELECT
			a.deployment_id,
			a.group_id,
			a.token_id,
			a.client_token_hash,
			a.token_expires_at,
			a.audit_index
		FROM operator_audit_events a
		WHERE a.action_type = 'issue-client-token'`
	argument := tokenID
	if tokenID != "" {
		query += " AND a.token_id = ?"
	} else {
		query += " AND a.client_token_hash = ?"
		argument = tokenHash
	}
	query += " ORDER BY a.audit_index DESC LIMIT 1"

	var token operatorToken
	if err := tx.QueryRowContext(ctx, query, argument).Scan(
		&token.DeploymentID,
		&token.GroupID,
		&token.TokenID,
		&token.ClientTokenHash,
		&token.TokenExpiresAt,
		&token.AuditIndex,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return operatorToken{}, store.ErrNotFound
		}
		return operatorToken{}, fmt.Errorf("read operator client token: %w", err)
	}
	var revoked int
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM operator_audit_events
			WHERE action_type = 'revoke-client-token'
			  AND token_id = ?
			  AND audit_index > ?
		)`,
		token.TokenID,
		token.AuditIndex,
	).Scan(&revoked); err != nil {
		return operatorToken{}, fmt.Errorf("read operator token revocation: %w", err)
	}
	if revoked != 0 {
		return operatorToken{}, store.ErrClientTokenRevoked
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, token.TokenExpiresAt)
	if err != nil {
		return operatorToken{}, store.ErrInconsistentState
	}
	currentAt, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return operatorToken{}, store.ErrInconsistentState
	}
	if !currentAt.Before(expiresAt) {
		return operatorToken{}, store.ErrClientTokenExpired
	}
	return token, nil
}

func activeOperatorLinkTx(
	ctx context.Context,
	tx *sql.Tx,
	linkID string,
) (operatorLink, error) {
	var link operatorLink
	var auditIndex int64
	if err := tx.QueryRowContext(ctx, `
		SELECT
			subject_deployment_id,
			related_deployment_id,
			group_id,
			link_id,
			token_id,
			audit_index
		FROM operator_audit_events
		WHERE action_type = 'redeem-client-token'
		  AND link_id = ?
		ORDER BY audit_index DESC
		LIMIT 1`,
		linkID,
	).Scan(
		&link.TargetDeploymentID,
		&link.IssuerDeploymentID,
		&link.GroupID,
		&link.LinkID,
		&link.TokenID,
		&auditIndex,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return operatorLink{}, store.ErrNotFound
		}
		return operatorLink{}, fmt.Errorf("read operator group link: %w", err)
	}
	var revoked int
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM operator_audit_events
			WHERE action_type = 'revoke-group-link'
			  AND link_id = ?
			  AND audit_index > ?
		)`,
		linkID,
		auditIndex,
	).Scan(&revoked); err != nil {
		return operatorLink{}, fmt.Errorf("read operator group-link revocation: %w", err)
	}
	if revoked != 0 {
		return operatorLink{}, store.ErrOperatorActionConflict
	}
	return link, nil
}

func operatorDeploymentActiveTx(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
) (bool, error) {
	var action string
	err := tx.QueryRowContext(ctx, `
		SELECT action_type
		FROM operator_audit_events
		WHERE subject_deployment_id = ?
		  AND action_type IN ('deactivate-deployment', 'reactivate-deployment')
		ORDER BY audit_index DESC
		LIMIT 1`,
		deploymentID,
	).Scan(&action)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read deployment activity state: %w", err)
	}
	return action == protocol.OperatorActionReactivateDeployment, nil
}

func operatorClaimTx(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	throughAuditIndex int64,
) (operatorClaimState, error) {
	query := `
		SELECT
			audit_index,
			claim_state,
			group_id,
			operator_name,
			operator_avatar_url
		FROM operator_audit_events
		WHERE subject_deployment_id = ?
		  AND action_type IN ('claim', 'withdraw-claim')`
	arguments := []any{deploymentID}
	if throughAuditIndex > 0 {
		query += " AND audit_index <= ?"
		arguments = append(arguments, throughAuditIndex)
	}
	query += " ORDER BY audit_index DESC LIMIT 1"

	var state operatorClaimState
	err := tx.QueryRowContext(ctx, query, arguments...).Scan(
		&state.AuditIndex,
		&state.ClaimState,
		&state.GroupID,
		&state.OperatorName,
		&state.OperatorAvatarURL,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return operatorClaimState{}, nil
	}
	if err != nil {
		return operatorClaimState{}, fmt.Errorf("read operator claim state: %w", err)
	}
	state.Claimed = state.ClaimState == protocol.OperatorClaimStateClaimed ||
		state.ClaimState == protocol.OperatorClaimStatePendingReview
	return state, nil
}

func operatorMembershipTx(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	throughAuditIndex int64,
) (operatorMembership, error) {
	claim, err := operatorClaimTx(ctx, tx, deploymentID, throughAuditIndex)
	if err != nil || !claim.Claimed {
		return operatorMembership{operatorClaimState: claim}, err
	}
	query := `
		SELECT r.group_id, r.link_id, r.related_deployment_id
		FROM operator_audit_events r
		WHERE r.action_type = 'redeem-client-token'
		  AND r.subject_deployment_id = ?
		  AND r.audit_index > ?
		  AND NOT EXISTS (
			SELECT 1
			FROM operator_audit_events x
			WHERE x.action_type = 'revoke-group-link'
			  AND x.link_id = r.link_id
			  AND x.audit_index > r.audit_index`
	arguments := []any{deploymentID, claim.AuditIndex}
	if throughAuditIndex > 0 {
		query += " AND x.audit_index <= ?"
		arguments = append(arguments, throughAuditIndex)
	}
	query += ")"
	if throughAuditIndex > 0 {
		query += " AND r.audit_index <= ?"
		arguments = append(arguments, throughAuditIndex)
	}
	query += " ORDER BY r.audit_index DESC LIMIT 1"

	membership := operatorMembership{operatorClaimState: claim}
	err = tx.QueryRowContext(ctx, query, arguments...).Scan(
		&membership.GroupID,
		&membership.LinkID,
		&membership.RelatedDeploymentID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return membership, nil
	}
	if err != nil {
		return operatorMembership{}, fmt.Errorf("read operator group membership: %w", err)
	}
	return membership, nil
}

func requireDeploymentTx(ctx context.Context, tx *sql.Tx, deploymentID string) error {
	var exists int
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM deployments WHERE deployment_id = ?
		)`,
		deploymentID,
	).Scan(&exists); err != nil {
		return fmt.Errorf("read operator deployment: %w", err)
	}
	if exists == 0 {
		return store.ErrNotFound
	}
	return nil
}

func operatorNonceStateTx(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	nonce string,
) (string, string, error) {
	var actionID, requestHash string
	err := tx.QueryRowContext(ctx, `
		SELECT action_id, request_hash
		FROM operator_action_nonces
		WHERE deployment_id = ? AND request_nonce = ?`,
		deploymentID,
		nonce,
	).Scan(&actionID, &requestHash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("read operator action nonce: %w", err)
	}
	return actionID, requestHash, nil
}

func insertOperatorNonceTx(
	ctx context.Context,
	tx *sql.Tx,
	input store.OperatorActionInput,
	actionID string,
) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO operator_action_nonces (
			deployment_id,
			request_nonce,
			request_hash,
			idempotency_key,
			payload_hash,
			request_timestamp,
			deployment_signature,
			action_id,
			accepted_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		input.DeploymentID,
		input.Nonce,
		input.RequestHash,
		input.IdempotencyKey,
		input.PayloadHash,
		input.RequestTimestamp,
		input.DeploymentSignature,
		actionID,
		input.AcceptedAt,
	); err != nil {
		return fmt.Errorf("persist operator action nonce: %w", err)
	}
	return nil
}

func insertOperatorAuditEventTx(
	ctx context.Context,
	tx *sql.Tx,
	event store.OperatorAuditEvent,
) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO operator_audit_events (
			audit_index,
			action_id,
			deployment_id,
			subject_deployment_id,
			related_deployment_id,
			action_type,
			request_timestamp,
			request_nonce,
			idempotency_key,
			payload_hash,
			request_hash,
			deployment_signature,
			operator_name,
			operator_avatar_url,
			claim_state,
			group_id,
			link_id,
			token_id,
			client_token_hash,
			token_ttl_seconds,
			token_expires_at,
			accepted_at,
			previous_audit_hash,
			audit_hash,
			registry_key_id,
			receipt_signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.AuditIndex,
		event.ActionID,
		event.DeploymentID,
		event.SubjectDeploymentID,
		event.RelatedDeploymentID,
		event.Action,
		event.RequestTimestamp,
		event.Nonce,
		event.IdempotencyKey,
		event.PayloadHash,
		event.RequestHash,
		event.DeploymentSignature,
		event.OperatorName,
		event.OperatorAvatarURL,
		event.ClaimState,
		event.GroupID,
		event.LinkID,
		event.TokenID,
		event.ClientTokenHash,
		event.TokenTTLSeconds,
		event.TokenExpiresAt,
		event.AcceptedAt,
		event.PreviousAuditHash,
		event.AuditHash,
		event.RegistryKeyID,
		event.ReceiptSignature,
	); err != nil {
		return fmt.Errorf("append operator audit event: %w", err)
	}
	return nil
}

func writeOperatorClaimStateTx(
	ctx context.Context,
	tx *sql.Tx,
	input store.OperatorActionInput,
	event store.OperatorAuditEvent,
) error {
	switch event.Action {
	case protocol.OperatorActionClaim:
		privateRecordHash := protocol.Digest(protocol.OperatorClaimPrivateRecordMessage(
			event.ActionID,
			event.DeploymentID,
			event.GroupID,
			event.PayloadHash,
			input.LegalName,
			input.RegistrationNumber,
			input.Jurisdiction,
			input.RegisteredAddress,
			input.Website,
			input.VerificationContactName,
			input.VerificationContactRole,
			input.VerificationContactEmail,
			input.AuthorityAttested,
			input.OperatorAvatarURL,
			event.AcceptedAt,
		))
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO operator_claim_verification_submissions (
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
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			event.ActionID,
			event.DeploymentID,
			event.GroupID,
			input.LegalName,
			input.RegistrationNumber,
			input.Jurisdiction,
			input.RegisteredAddress,
			input.Website,
			input.VerificationContactName,
			input.VerificationContactRole,
			input.VerificationContactEmail,
			input.AuthorityAttested,
			input.OperatorAvatarURL,
			event.PayloadHash,
			event.AcceptedAt,
			privateRecordHash,
		); err != nil {
			return fmt.Errorf("persist private operator claim submission: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO operator_claim_status (
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
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', 0, ?, '', ?, ?)
			ON CONFLICT(deployment_id) DO UPDATE SET
				claim_action_id = excluded.claim_action_id,
				claim_audit_index = excluded.claim_audit_index,
				claim_audit_hash = excluded.claim_audit_hash,
				group_id = excluded.group_id,
				legal_name = excluded.legal_name,
				verification_state = excluded.verification_state,
				submitted_at = excluded.submitted_at,
				review_id = '',
				review_index = 0,
				review_hash = excluded.review_hash,
				approved_at = '',
				updated_at = excluded.updated_at,
				private_record_hash = excluded.private_record_hash`,
			event.DeploymentID,
			event.ActionID,
			event.AuditIndex,
			event.AuditHash,
			event.GroupID,
			input.LegalName,
			protocol.OperatorClaimStatePendingReview,
			event.AcceptedAt,
			protocol.OperatorClaimReviewZeroHash,
			event.AcceptedAt,
			privateRecordHash,
		); err != nil {
			return fmt.Errorf("write current operator claim status: %w", err)
		}
	case protocol.OperatorActionWithdrawClaim:
		if _, err := tx.ExecContext(ctx, `
			UPDATE operator_claim_status
			SET verification_state = ?,
			    updated_at = ?
			WHERE deployment_id = ?`,
			protocol.OperatorClaimStateWithdrawn,
			event.AcceptedAt,
			event.SubjectDeploymentID,
		); err != nil {
			return fmt.Errorf("withdraw current operator claim status: %w", err)
		}
	}
	return nil
}

func (sqliteStore *Store) OperatorAuditHead(
	ctx context.Context,
) (store.OperatorAuditEvent, error) {
	return operatorAuditHeadQuery(ctx, sqliteStore.db)
}

func operatorAuditHeadTx(
	ctx context.Context,
	tx *sql.Tx,
) (store.OperatorAuditEvent, error) {
	return operatorAuditHeadQuery(ctx, tx)
}

type operatorActionQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func operatorAuditHeadQuery(
	ctx context.Context,
	querier operatorActionQuerier,
) (store.OperatorAuditEvent, error) {
	row := querier.QueryRowContext(ctx, operatorAuditSelect+`
		ORDER BY audit_index DESC
		LIMIT 1`)
	event, err := scanOperatorAuditEvent(row)
	if errors.Is(err, store.ErrNotFound) {
		return store.OperatorAuditEvent{
			AuditHash: protocol.OperatorAuditZeroHash,
		}, nil
	}
	return event, err
}

func operatorActionByIDTx(
	ctx context.Context,
	tx *sql.Tx,
	actionID string,
) (store.OperatorAuditEvent, error) {
	return scanOperatorAuditEvent(tx.QueryRowContext(
		ctx,
		operatorAuditSelect+" WHERE action_id = ?",
		actionID,
	))
}

func operatorActionByIdempotencyTx(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	idempotencyKey string,
) (store.OperatorAuditEvent, error) {
	return scanOperatorAuditEvent(tx.QueryRowContext(
		ctx,
		operatorAuditSelect+`
		WHERE deployment_id = ? AND idempotency_key = ?`,
		deploymentID,
		idempotencyKey,
	))
}

const operatorAuditSelect = `
	SELECT
		audit_index,
		action_id,
		deployment_id,
		subject_deployment_id,
		related_deployment_id,
		action_type,
		request_timestamp,
		request_nonce,
		idempotency_key,
		payload_hash,
		request_hash,
		deployment_signature,
		operator_name,
		operator_avatar_url,
		claim_state,
		group_id,
		link_id,
		token_id,
		client_token_hash,
		token_ttl_seconds,
		token_expires_at,
		accepted_at,
		previous_audit_hash,
		audit_hash,
		registry_key_id,
		receipt_signature
	FROM operator_audit_events`

func scanOperatorAuditEvent(row rowScanner) (store.OperatorAuditEvent, error) {
	var event store.OperatorAuditEvent
	if err := row.Scan(
		&event.AuditIndex,
		&event.ActionID,
		&event.DeploymentID,
		&event.SubjectDeploymentID,
		&event.RelatedDeploymentID,
		&event.Action,
		&event.RequestTimestamp,
		&event.Nonce,
		&event.IdempotencyKey,
		&event.PayloadHash,
		&event.RequestHash,
		&event.DeploymentSignature,
		&event.OperatorName,
		&event.OperatorAvatarURL,
		&event.ClaimState,
		&event.GroupID,
		&event.LinkID,
		&event.TokenID,
		&event.ClientTokenHash,
		&event.TokenTTLSeconds,
		&event.TokenExpiresAt,
		&event.AcceptedAt,
		&event.PreviousAuditHash,
		&event.AuditHash,
		&event.RegistryKeyID,
		&event.ReceiptSignature,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.OperatorAuditEvent{}, store.ErrNotFound
		}
		return store.OperatorAuditEvent{}, fmt.Errorf("read operator audit event: %w", err)
	}
	return event, nil
}
