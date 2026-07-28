package sqlite

import (
	"context"
	"sort"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

func (sqliteStore *Store) verifyOperatorNetworkStateRows(
	ctx context.Context,
	actions map[string]verifiedOperatorAction,
) error {
	ordered := make([]verifiedOperatorAction, 0, len(actions))
	for _, action := range actions {
		ordered = append(ordered, action)
	}
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left].event.AuditIndex < ordered[right].event.AuditIndex
	})

	current := make(map[string]operatorNetworkStateRow)
	expected := make([]operatorNetworkStateRow, 0, len(ordered))
	for _, verified := range ordered {
		event := verified.event
		state, exists := current[event.SubjectDeploymentID]
		if !exists {
			state = operatorNetworkStateRow{
				DeploymentID: event.SubjectDeploymentID,
				Active:       true,
			}
		}

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
		current[event.SubjectDeploymentID] = state
		expected = append(expected, state)
	}

	rows, err := sqliteStore.db.QueryContext(
		ctx,
		operatorNetworkStateSelect+" ORDER BY audit_index",
	)
	if err != nil {
		return inconsistent("read direct operator network state rows", err)
	}
	defer rows.Close()

	actualIndex := 0
	for rows.Next() {
		actual, err := scanOperatorNetworkState(rows)
		if err != nil {
			return inconsistent("scan direct operator network state row", err)
		}
		if actualIndex >= len(expected) {
			return inconsistentMessage(
				"operator network state row %d has no matching audit event",
				actual.AuditIndex,
			)
		}
		if actual != expected[actualIndex] {
			return inconsistentMessage(
				"operator network state row %d does not match audit event %s",
				actual.AuditIndex,
				expected[actualIndex].ActionID,
			)
		}
		actualIndex++
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate direct operator network state rows", err)
	}
	if actualIndex != len(expected) {
		return inconsistentMessage(
			"operator network state row count is %d, expected %d",
			actualIndex,
			len(expected),
		)
	}
	return nil
}
