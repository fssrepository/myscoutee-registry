package sqlite

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

type verifiedOperatorAction struct {
	event     store.OperatorAuditEvent
	publicKey ed25519.PublicKey
}

func (sqliteStore *Store) VerifyOperatorNetwork(
	ctx context.Context,
	registryPublicKey []byte,
	registryKeyID string,
	registryScope string,
) error {
	if len(registryPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid registry public key", store.ErrInconsistentState)
	}
	actions, err := sqliteStore.verifyOperatorAuditEvents(
		ctx,
		ed25519.PublicKey(registryPublicKey),
		registryKeyID,
		registryScope,
	)
	if err != nil {
		return err
	}
	if err := sqliteStore.verifyOperatorActionNonces(ctx, actions, registryScope); err != nil {
		return err
	}
	if err := sqliteStore.verifyOperatorClaimReviews(
		ctx,
		actions,
		registryPublicKey,
		registryKeyID,
		registryScope,
	); err != nil {
		return err
	}
	return nil
}

func (sqliteStore *Store) verifyOperatorAuditEvents(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) (map[string]verifiedOperatorAction, error) {
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		operatorAuditSelect+" ORDER BY audit_index",
	)
	if err != nil {
		return nil, inconsistent("read operator audit chain", err)
	}
	records := make([]store.OperatorAuditEvent, 0)
	for rows.Next() {
		event, err := scanOperatorAuditEvent(rows)
		if err != nil {
			rows.Close()
			return nil, inconsistent("scan operator audit chain", err)
		}
		records = append(records, event)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, inconsistent("iterate operator audit chain", err)
	}
	if err := rows.Close(); err != nil {
		return nil, inconsistent("close operator audit chain", err)
	}

	deploymentKeys, err := sqliteStore.operatorDeploymentKeys(ctx)
	if err != nil {
		return nil, err
	}
	verified := make(map[string]verifiedOperatorAction, len(records))
	submissions, err := sqliteStore.operatorClaimSubmissions(ctx)
	if err != nil {
		return nil, err
	}
	usedSubmissions := make(map[string]bool, len(submissions))
	expectedIndex := int64(1)
	previousHash := protocol.OperatorAuditZeroHash
	var previousAcceptedAt time.Time
	for _, event := range records {
		publicKey, exists := deploymentKeys[event.DeploymentID]
		if !exists {
			return nil, inconsistentMessage(
				"operator action %s references an unknown signer",
				event.ActionID,
			)
		}
		if _, exists := deploymentKeys[event.SubjectDeploymentID]; !exists {
			return nil, inconsistentMessage(
				"operator action %s references an unknown subject",
				event.ActionID,
			)
		}
		if event.RelatedDeploymentID != "" {
			if _, exists := deploymentKeys[event.RelatedDeploymentID]; !exists {
				return nil, inconsistentMessage(
					"operator action %s references an unknown related deployment",
					event.ActionID,
				)
			}
		}
		if event.AuditIndex != expectedIndex {
			return nil, inconsistentMessage(
				"operator audit index discontinuity: got %d, expected %d",
				event.AuditIndex,
				expectedIndex,
			)
		}
		if !validHexID(event.ActionID, "opa_", 32) {
			return nil, inconsistentMessage(
				"operator action has malformed ID %q",
				event.ActionID,
			)
		}
		if event.PreviousAuditHash != previousHash {
			return nil, inconsistentMessage(
				"operator action %s has an invalid previous hash",
				event.ActionID,
			)
		}
		acceptedAt, err := time.Parse(time.RFC3339Nano, event.AcceptedAt)
		if err != nil {
			return nil, inconsistentMessage(
				"operator action %s has an invalid accepted_at",
				event.ActionID,
			)
		}
		if expectedIndex > 1 && acceptedAt.Before(previousAcceptedAt) {
			return nil, inconsistentMessage(
				"operator action %s has a non-monotonic accepted_at",
				event.ActionID,
			)
		}
		expectedPayloadHash, structuredClaim, err := operatorEventPayloadHash(
			event,
			submissions[event.ActionID],
		)
		if err != nil {
			return nil, inconsistent(
				"validate operator action private payload",
				err,
			)
		}
		if structuredClaim {
			usedSubmissions[event.ActionID] = true
		}
		if event.PayloadHash != expectedPayloadHash {
			return nil, inconsistentMessage(
				"operator action %s payload hash verification failed",
				event.ActionID,
			)
		}
		requestMessage := protocol.CanonicalRequest(
			"POST",
			protocol.OperatorActionPath,
			protocol.Version,
			registryScope,
			event.DeploymentID,
			event.RequestTimestamp,
			event.Nonce,
			event.IdempotencyKey,
			event.PayloadHash,
		)
		if event.RequestHash != protocol.Digest(requestMessage) ||
			!ed25519.Verify(publicKey, requestMessage, event.DeploymentSignature) {
			return nil, inconsistentMessage(
				"operator action %s deployment proof verification failed",
				event.ActionID,
			)
		}
		expectedAuditHash := protocol.Digest(protocol.OperatorAuditMessage(
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
		if event.AuditHash != expectedAuditHash {
			return nil, inconsistentMessage(
				"operator action %s audit hash verification failed",
				event.ActionID,
			)
		}
		if event.RegistryKeyID != registryKeyID {
			return nil, inconsistentMessage(
				"operator action %s has registry key ID %q",
				event.ActionID,
				event.RegistryKeyID,
			)
		}
		receipt := operatorReceipt(event, registryScope)
		if !ed25519.Verify(
			registryPublicKey,
			protocol.OperatorActionReceiptMessage(receipt),
			event.ReceiptSignature,
		) {
			return nil, inconsistentMessage(
				"operator action %s registry receipt verification failed",
				event.ActionID,
			)
		}
		verified[event.ActionID] = verifiedOperatorAction{
			event:     event,
			publicKey: publicKey,
		}
		previousHash = event.AuditHash
		previousAcceptedAt = acceptedAt
		expectedIndex++
	}
	for actionID := range submissions {
		if !usedSubmissions[actionID] {
			return nil, inconsistentMessage(
				"private operator claim submission %s has no matching structured claim",
				actionID,
			)
		}
	}
	return verified, nil
}

func (sqliteStore *Store) operatorDeploymentKeys(
	ctx context.Context,
) (map[string]ed25519.PublicKey, error) {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT deployment_id, public_key_der
		FROM deployments`)
	if err != nil {
		return nil, inconsistent("read operator deployment keys", err)
	}
	defer rows.Close()

	keys := make(map[string]ed25519.PublicKey)
	for rows.Next() {
		var deploymentID string
		var der []byte
		if err := rows.Scan(&deploymentID, &der); err != nil {
			return nil, inconsistent("scan operator deployment key", err)
		}
		parsed, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, inconsistent("parse operator deployment key", err)
		}
		publicKey, ok := parsed.(ed25519.PublicKey)
		if !ok || len(publicKey) != ed25519.PublicKeySize {
			return nil, inconsistentMessage(
				"deployment %s has a non-Ed25519 operator key",
				deploymentID,
			)
		}
		keys[deploymentID] = publicKey
	}
	if err := rows.Err(); err != nil {
		return nil, inconsistent("iterate operator deployment keys", err)
	}
	return keys, nil
}

func (sqliteStore *Store) verifyOperatorActionNonces(
	ctx context.Context,
	actions map[string]verifiedOperatorAction,
	registryScope string,
) error {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			deployment_id,
			request_nonce,
			request_hash,
			idempotency_key,
			payload_hash,
			request_timestamp,
			deployment_signature,
			action_id
		FROM operator_action_nonces
		ORDER BY deployment_id, request_nonce`)
	if err != nil {
		return inconsistent("read operator nonce records", err)
	}
	defer rows.Close()

	initialNonces := make(map[string]bool, len(actions))
	for rows.Next() {
		var deploymentID, nonce, requestHash, idempotencyKey string
		var payloadHash, requestTimestamp, actionID string
		var signature []byte
		if err := rows.Scan(
			&deploymentID,
			&nonce,
			&requestHash,
			&idempotencyKey,
			&payloadHash,
			&requestTimestamp,
			&signature,
			&actionID,
		); err != nil {
			return inconsistent("scan operator nonce record", err)
		}
		action, exists := actions[actionID]
		if !exists ||
			action.event.DeploymentID != deploymentID ||
			action.event.IdempotencyKey != idempotencyKey ||
			action.event.PayloadHash != payloadHash {
			return inconsistentMessage(
				"operator nonce %q references inconsistent action %q",
				nonce,
				actionID,
			)
		}
		requestMessage := protocol.CanonicalRequest(
			"POST",
			protocol.OperatorActionPath,
			protocol.Version,
			registryScope,
			deploymentID,
			requestTimestamp,
			nonce,
			idempotencyKey,
			payloadHash,
		)
		if requestHash != protocol.Digest(requestMessage) ||
			!ed25519.Verify(action.publicKey, requestMessage, signature) {
			return inconsistentMessage(
				"operator nonce %q request proof verification failed",
				nonce,
			)
		}
		if nonce == action.event.Nonce {
			if requestTimestamp != action.event.RequestTimestamp ||
				requestHash != action.event.RequestHash ||
				!bytes.Equal(signature, action.event.DeploymentSignature) {
				return inconsistentMessage(
					"operator action %s initial nonce does not match its event",
					actionID,
				)
			}
			initialNonces[actionID] = true
		}
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate operator nonce records", err)
	}
	for actionID := range actions {
		if !initialNonces[actionID] {
			return inconsistentMessage(
				"operator action %s is missing its initial nonce record",
				actionID,
			)
		}
	}
	return nil
}

func operatorEventPayloadHash(
	event store.OperatorAuditEvent,
	submission store.OperatorClaimSubmission,
) (string, bool, error) {
	operatorName := ""
	operatorAvatarURL := ""
	clientTokenHash := ""
	tokenTTLSeconds := int64(0)
	tokenID := ""
	linkID := ""
	switch event.Action {
	case protocol.OperatorActionClaim:
		if event.ClaimState == protocol.OperatorClaimStatePendingReview {
			if submission.ClaimActionID == "" ||
				submission.ClaimActionID != event.ActionID ||
				submission.DeploymentID != event.DeploymentID ||
				submission.GroupID != event.GroupID ||
				submission.LegalName != event.OperatorName ||
				submission.OperatorAvatarURL != event.OperatorAvatarURL ||
				submission.PayloadHash != event.PayloadHash ||
				submission.SubmittedAt != event.AcceptedAt ||
				!submission.AuthorityAttested {
				return "", false, store.ErrInconsistentState
			}
			expectedPrivateHash := protocol.Digest(
				protocol.OperatorClaimPrivateRecordMessage(
					submission.ClaimActionID,
					submission.DeploymentID,
					submission.GroupID,
					submission.PayloadHash,
					submission.LegalName,
					submission.RegistrationNumber,
					submission.Jurisdiction,
					submission.RegisteredAddress,
					submission.Website,
					submission.VerificationContactName,
					submission.VerificationContactRole,
					submission.VerificationContactEmail,
					submission.AuthorityAttested,
					submission.OperatorAvatarURL,
					submission.SubmittedAt,
				),
			)
			if submission.PrivateRecordHash != expectedPrivateHash {
				return "", false, store.ErrInconsistentState
			}
			return protocol.Digest(protocol.OperatorClaimPayload(
				submission.LegalName,
				submission.RegistrationNumber,
				submission.Jurisdiction,
				submission.RegisteredAddress,
				submission.Website,
				submission.VerificationContactName,
				submission.VerificationContactRole,
				submission.VerificationContactEmail,
				submission.AuthorityAttested,
				submission.OperatorAvatarURL,
			)), true, nil
		}
		if event.ClaimState != protocol.OperatorClaimStateClaimed ||
			submission.ClaimActionID != "" {
			return "", false, store.ErrInconsistentState
		}
		operatorName = event.OperatorName
		operatorAvatarURL = event.OperatorAvatarURL
	case protocol.OperatorActionIssueClientToken:
		tokenTTLSeconds = event.TokenTTLSeconds
	case protocol.OperatorActionRevokeClientToken:
		tokenID = event.TokenID
	case protocol.OperatorActionRedeemClientToken:
		clientTokenHash = event.ClientTokenHash
	case protocol.OperatorActionRevokeGroupLink:
		linkID = event.LinkID
	}
	return protocol.Digest(protocol.OperatorActionPayload(
		event.Action,
		operatorName,
		operatorAvatarURL,
		clientTokenHash,
		tokenTTLSeconds,
		tokenID,
		linkID,
	)), false, nil
}

func operatorReceipt(
	event store.OperatorAuditEvent,
	registryScope string,
) protocol.OperatorActionReceipt {
	return protocol.OperatorActionReceipt{
		AuditIndex:          event.AuditIndex,
		AuditHash:           event.AuditHash,
		PreviousAuditHash:   event.PreviousAuditHash,
		ActionID:            event.ActionID,
		DeploymentID:        event.DeploymentID,
		SubjectDeploymentID: event.SubjectDeploymentID,
		RelatedDeploymentID: event.RelatedDeploymentID,
		Action:              event.Action,
		AcceptedAt:          event.AcceptedAt,
		ClaimState:          event.ClaimState,
		GroupID:             event.GroupID,
		LinkID:              event.LinkID,
		TokenID:             event.TokenID,
		ClientTokenHash:     event.ClientTokenHash,
		TokenExpiresAt:      event.TokenExpiresAt,
		RegistryScope:       registryScope,
		RegistryKeyID:       event.RegistryKeyID,
	}
}
