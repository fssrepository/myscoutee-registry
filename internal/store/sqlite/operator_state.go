package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

type operatorNetworkStateRow struct {
	AuditIndex             int64
	ActionID               string
	DeploymentID           string
	Claimed                bool
	Active                 bool
	ClaimState             string
	ClaimStateAuditIndex   int64
	ProfileClaimAuditIndex int64
	ClaimGroupID           string
	EffectiveGroupID       string
	OperatorName           string
	OperatorAvatarURL      string
	ProfileClaimState      string
	LinkID                 string
	RelatedDeploymentID    string
	SourceAuditHash        string
	AcceptedAt             string
}

const operatorNetworkStateSelect = `
	SELECT
		audit_index,
		action_id,
		deployment_id,
		claimed,
		active,
		claim_state,
		claim_state_audit_index,
		profile_claim_audit_index,
		claim_group_id,
		effective_group_id,
		operator_name,
		operator_avatar_url,
		profile_claim_state,
		link_id,
		related_deployment_id,
		source_audit_hash,
		accepted_at
	FROM operator_network_state_rows`

func insertOperatorNetworkStateTx(
	ctx context.Context,
	tx *sql.Tx,
	event store.OperatorAuditEvent,
) error {
	state, err := operatorNetworkStateBeforeTx(
		ctx,
		tx,
		event.SubjectDeploymentID,
		event.AuditIndex,
	)
	if err != nil {
		return err
	}
	applyOperatorNetworkEvent(&state, event)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO operator_network_state_rows (
			audit_index,
			action_id,
			deployment_id,
			claimed,
			active,
			claim_state,
			claim_state_audit_index,
			profile_claim_audit_index,
			claim_group_id,
			effective_group_id,
			operator_name,
			operator_avatar_url,
			profile_claim_state,
			link_id,
			related_deployment_id,
			source_audit_hash,
			accepted_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		state.AuditIndex,
		state.ActionID,
		state.DeploymentID,
		state.Claimed,
		state.Active,
		state.ClaimState,
		state.ClaimStateAuditIndex,
		state.ProfileClaimAuditIndex,
		state.ClaimGroupID,
		state.EffectiveGroupID,
		state.OperatorName,
		state.OperatorAvatarURL,
		state.ProfileClaimState,
		state.LinkID,
		state.RelatedDeploymentID,
		state.SourceAuditHash,
		state.AcceptedAt,
	); err != nil {
		return fmt.Errorf("append operator network state row: %w", err)
	}
	return nil
}

func operatorNetworkStateBeforeTx(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	beforeAuditIndex int64,
) (operatorNetworkStateRow, error) {
	state, err := scanOperatorNetworkState(tx.QueryRowContext(
		ctx,
		operatorNetworkStateSelect+`
		WHERE deployment_id = ?
		  AND audit_index < ?
		ORDER BY audit_index DESC
		LIMIT 1`,
		deploymentID,
		beforeAuditIndex,
	))
	if errors.Is(err, store.ErrNotFound) {
		return operatorNetworkStateRow{
			DeploymentID: deploymentID,
			Active:       true,
		}, nil
	}
	return state, err
}

func operatorNetworkStateAtTx(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	throughAuditIndex int64,
) (operatorNetworkStateRow, error) {
	statement := operatorNetworkStateSelect + `
		WHERE deployment_id = ?`
	arguments := []any{deploymentID}
	if throughAuditIndex > 0 {
		statement += " AND audit_index <= ?"
		arguments = append(arguments, throughAuditIndex)
	}
	statement += " ORDER BY audit_index DESC LIMIT 1"
	state, err := scanOperatorNetworkState(
		tx.QueryRowContext(ctx, statement, arguments...),
	)
	if errors.Is(err, store.ErrNotFound) {
		return operatorNetworkStateRow{
			DeploymentID: deploymentID,
			Active:       true,
		}, nil
	}
	return state, err
}

func applyOperatorNetworkEvent(
	state *operatorNetworkStateRow,
	event store.OperatorAuditEvent,
) {
	state.AuditIndex = event.AuditIndex
	state.ActionID = event.ActionID
	state.DeploymentID = event.SubjectDeploymentID
	state.SourceAuditHash = event.AuditHash
	state.AcceptedAt = event.AcceptedAt

	switch event.Action {
	case protocol.OperatorActionClaim:
		state.Claimed = true
		state.ClaimState = event.ClaimState
		state.ClaimStateAuditIndex = event.AuditIndex
		state.ProfileClaimAuditIndex = event.AuditIndex
		state.ClaimGroupID = event.GroupID
		state.EffectiveGroupID = event.GroupID
		state.OperatorName = event.OperatorName
		state.OperatorAvatarURL = event.OperatorAvatarURL
		state.ProfileClaimState = event.ClaimState
		state.LinkID = ""
		state.RelatedDeploymentID = ""
	case protocol.OperatorActionWithdrawClaim:
		state.Claimed = false
		state.ClaimState = protocol.OperatorClaimStateWithdrawn
		state.ClaimStateAuditIndex = event.AuditIndex
		state.EffectiveGroupID = ""
		state.LinkID = ""
		state.RelatedDeploymentID = ""
	case protocol.OperatorActionRedeemClientToken:
		if !state.Claimed &&
			event.ClaimState == protocol.OperatorClaimStatePendingReview &&
			event.OperatorName != "" &&
			event.LinkID == "" {
			state.Claimed = true
			state.ClaimState = event.ClaimState
			state.ClaimStateAuditIndex = event.AuditIndex
			state.ProfileClaimAuditIndex = event.AuditIndex
			state.ClaimGroupID = event.GroupID
			state.EffectiveGroupID = event.GroupID
			state.OperatorName = event.OperatorName
			state.OperatorAvatarURL = event.OperatorAvatarURL
			state.ProfileClaimState = event.ClaimState
			state.RelatedDeploymentID = ""
		} else {
			state.EffectiveGroupID = event.GroupID
			state.LinkID = event.LinkID
			state.RelatedDeploymentID = event.RelatedDeploymentID
		}
	case protocol.OperatorActionRevokeGroupLink:
		if state.Claimed {
			state.EffectiveGroupID = state.ClaimGroupID
		} else {
			state.EffectiveGroupID = ""
		}
		state.LinkID = ""
		state.RelatedDeploymentID = ""
	case protocol.OperatorActionDeactivateDeployment:
		state.Active = false
	case protocol.OperatorActionReactivateDeployment:
		state.Active = true
	}
}

func scanOperatorNetworkState(scanner rowScanner) (operatorNetworkStateRow, error) {
	var state operatorNetworkStateRow
	if err := scanner.Scan(
		&state.AuditIndex,
		&state.ActionID,
		&state.DeploymentID,
		&state.Claimed,
		&state.Active,
		&state.ClaimState,
		&state.ClaimStateAuditIndex,
		&state.ProfileClaimAuditIndex,
		&state.ClaimGroupID,
		&state.EffectiveGroupID,
		&state.OperatorName,
		&state.OperatorAvatarURL,
		&state.ProfileClaimState,
		&state.LinkID,
		&state.RelatedDeploymentID,
		&state.SourceAuditHash,
		&state.AcceptedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return operatorNetworkStateRow{}, store.ErrNotFound
		}
		return operatorNetworkStateRow{}, fmt.Errorf(
			"read operator network state row: %w",
			err,
		)
	}
	return state, nil
}
