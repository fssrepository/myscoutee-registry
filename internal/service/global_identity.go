package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/globalidentity"
	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const (
	globalIdentityEvaluationLimitPerMinute = int64(60)
	globalIdentityMaximumCommitments       = 4096
	globalIdentityMaximumPresenceChunks    = int64(4096)
)

func (registry *Service) CurrentGlobalIdentityVOPRFKey(
	ctx context.Context,
) (protocol.GlobalIdentityVOPRFKey, error) {
	if registry.globalIdentityKeys == nil {
		return protocol.GlobalIdentityVOPRFKey{},
			requestError(
				"global_identity_unavailable",
				"privacy-preserving global identity service is unavailable",
			)
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.GlobalIdentityVOPRFKey{},
			registryIntegrityRequestError(err)
	}
	key := registry.globalIdentityKeys.ActivePublicKey()
	response := protocol.GlobalIdentityVOPRFKey{
		ProtocolVersion:   protocol.Version,
		RegistryScope:     registry.registryScope,
		KeyVersion:        key.Version,
		Suite:             key.Suite,
		Mode:              globalidentity.ModeName,
		PublicKey:         base64.StdEncoding.EncodeToString(key.PublicKey),
		Status:            protocol.GlobalIdentityKeyActive,
		ActivatedAt:       key.ActivatedAt,
		RegistryKeyID:     registry.signingKey.KeyID(),
		RegistryPublicKey: registry.signingKey.EncodedPublicKey(),
	}
	response.Signature = protocol.EncodeSignature(
		registry.signingKey.Sign(
			protocol.GlobalIdentityVOPRFKeyMessage(response),
		),
	)
	return response, nil
}

func (registry *Service) EvaluateGlobalIdentity(
	ctx context.Context,
	request protocol.GlobalIdentityEvaluationRequest,
) (protocol.GlobalIdentityEvaluationResponse, error) {
	payload := protocol.GlobalIdentityEvaluationPayload(
		request.KeyVersion,
		request.Suite,
		request.BlindedElement,
	)
	requestHash, signature, err := registry.verifyGlobalIdentityRequest(
		ctx,
		protocol.GlobalIdentityEvaluatePath,
		request.ProtocolVersion,
		request.RegistryScope,
		request.DeploymentID,
		request.Timestamp,
		request.Nonce,
		request.IdempotencyKey,
		request.PayloadHash,
		request.Signature,
		payload,
	)
	if err != nil {
		return protocol.GlobalIdentityEvaluationResponse{}, err
	}
	if request.Suite != protocol.GlobalIdentityVOPRFSuite ||
		request.KeyVersion < 1 {
		return protocol.GlobalIdentityEvaluationResponse{},
			requestError(
				"invalid_request",
				"key_version and suite do not identify a supported RFC 9497 VOPRF key",
			)
	}
	blinded, err := decodeCanonicalBase64(
		"blinded_element",
		request.BlindedElement,
		33,
	)
	if err != nil {
		return protocol.GlobalIdentityEvaluationResponse{}, err
	}
	if registry.globalIdentityKeys == nil {
		return protocol.GlobalIdentityEvaluationResponse{},
			requestError(
				"global_identity_unavailable",
				"privacy-preserving global identity service is unavailable",
			)
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.GlobalIdentityEvaluationResponse{},
			registryIntegrityRequestError(err)
	}

	existing, lookupErr := registry.store.GlobalIdentityEvaluationByIdempotency(
		ctx,
		request.DeploymentID,
		request.IdempotencyKey,
	)
	if lookupErr == nil {
		if existing.PayloadHash != request.PayloadHash {
			return protocol.GlobalIdentityEvaluationResponse{},
				mapStoreError(store.ErrIdempotencyConflict)
		}
		return registry.globalIdentityEvaluationResponse(existing, true), nil
	}
	if !errors.Is(lookupErr, store.ErrNotFound) {
		return protocol.GlobalIdentityEvaluationResponse{}, lookupErr
	}
	since := registry.canonicalNow().
		Add(-time.Minute).
		Format(time.RFC3339)
	count, err := registry.store.CountGlobalIdentityEvaluationsSince(
		ctx,
		request.DeploymentID,
		since,
	)
	if err != nil {
		return protocol.GlobalIdentityEvaluationResponse{}, err
	}
	if count >= globalIdentityEvaluationLimitPerMinute {
		return protocol.GlobalIdentityEvaluationResponse{},
			requestError(
				"global_identity_rate_limited",
				"too many VOPRF evaluations were requested by this deployment",
			)
	}
	publicKey, evaluated, proof, err :=
		registry.globalIdentityKeys.Evaluate(request.KeyVersion, blinded)
	if err != nil {
		return protocol.GlobalIdentityEvaluationResponse{},
			requestError(
				"global_identity_key_unavailable",
				"requested VOPRF key version is unavailable or the blinded element is invalid",
			)
	}
	evaluatedAt := registry.canonicalNow().Format(time.RFC3339)
	publicEncoded := base64.StdEncoding.EncodeToString(publicKey)
	evaluatedEncoded := base64.StdEncoding.EncodeToString(evaluated)
	proofEncoded := base64.StdEncoding.EncodeToString(proof)
	responseHash := protocol.Digest(
		protocol.GlobalIdentityEvaluationResult(
			request.KeyVersion,
			request.Suite,
			publicEncoded,
			evaluatedEncoded,
			proofEncoded,
		),
	)
	receipt := registry.signingKey.Sign(
		protocol.GlobalIdentityEvaluationReceiptMessage(
			protocol.Version,
			registry.registryScope,
			request.DeploymentID,
			request.KeyVersion,
			request.Suite,
			requestHash,
			responseHash,
			evaluatedAt,
			registry.signingKey.KeyID(),
		),
	)
	evaluationID, err := registry.newID("gieval_")
	if err != nil {
		return protocol.GlobalIdentityEvaluationResponse{},
			fmt.Errorf("generate global identity evaluation ID: %w", err)
	}
	record, duplicate, err := registry.store.AcceptGlobalIdentityEvaluation(
		ctx,
		store.GlobalIdentityEvaluationInput{
			EvaluationID:     evaluationID,
			DeploymentID:     request.DeploymentID,
			IdempotencyKey:   request.IdempotencyKey,
			Nonce:            request.Nonce,
			RequestTimestamp: request.Timestamp,
			RequestHash:      requestHash,
			RequestSignature: signature,
			PayloadHash:      request.PayloadHash,
			KeyVersion:       request.KeyVersion,
			Suite:            request.Suite,
			BlindedElement:   blinded,
			PublicKey:        publicKey,
			EvaluatedElement: evaluated,
			Proof:            proof,
			ResponseHash:     responseHash,
			EvaluatedAt:      evaluatedAt,
			ReceiptSignature: receipt,
			RateWindowStart:  since,
			RateLimit:        globalIdentityEvaluationLimitPerMinute,
		},
	)
	if err != nil {
		return protocol.GlobalIdentityEvaluationResponse{}, mapStoreError(err)
	}
	return registry.globalIdentityEvaluationResponse(record, duplicate), nil
}

func (registry *Service) LinkGlobalIdentity(
	ctx context.Context,
	request protocol.GlobalIdentityLinkRequest,
) (protocol.GlobalIdentityMutationResponse, error) {
	payload := protocol.GlobalIdentityLinkPayload(request)
	requestHash, signature, err := registry.verifyGlobalIdentityRequest(
		ctx,
		protocol.GlobalIdentityLinkPath,
		request.ProtocolVersion,
		request.RegistryScope,
		request.DeploymentID,
		request.Timestamp,
		request.Nonce,
		request.IdempotencyKey,
		request.PayloadHash,
		request.Signature,
		payload,
	)
	if err != nil {
		return protocol.GlobalIdentityMutationResponse{}, err
	}
	if err := registry.validateGlobalIdentityAlias(
		request.KeyVersion,
		request.Suite,
		request.NetworkIdentityCommitment,
		false,
	); err != nil {
		return protocol.GlobalIdentityMutationResponse{}, err
	}
	if request.ConsentVersion != protocol.GlobalIdentityConsentVersion ||
		!protocol.IsDigest(request.ConsentEvidenceCommitment) {
		return protocol.GlobalIdentityMutationResponse{},
			requestError(
				"invalid_request",
				"consent metadata is malformed or unsupported",
			)
	}
	if err := validateHistoricalTimestamp(
		"verified_at",
		request.VerifiedAt,
		registry.canonicalNow(),
	); err != nil {
		return protocol.GlobalIdentityMutationResponse{}, err
	}
	if !periodPattern.MatchString(request.EffectivePeriod) {
		return protocol.GlobalIdentityMutationResponse{},
			requestError(
				"invalid_request",
				"effective_period must be a UTC month in YYYY-MM",
			)
	}
	return registry.applyGlobalIdentityMutation(
		ctx,
		store.GlobalIdentityMutationInput{
			Action:           protocol.GlobalIdentityActionLink,
			DeploymentID:     request.DeploymentID,
			IdempotencyKey:   request.IdempotencyKey,
			Nonce:            request.Nonce,
			RequestTimestamp: request.Timestamp,
			RequestHash:      requestHash,
			RequestSignature: signature,
			PayloadHash:      request.PayloadHash,
			KeyVersion:       request.KeyVersion,
			RequiredActiveKeyVersion: registry.globalIdentityKeys.
				ActivePublicKey().Version,
			Suite:                     request.Suite,
			NetworkIdentityCommitment: request.NetworkIdentityCommitment,
			ConsentVersion:            request.ConsentVersion,
			ConsentEvidenceCommitment: request.ConsentEvidenceCommitment,
			VerifiedAt:                request.VerifiedAt,
			EffectivePeriod:           request.EffectivePeriod,
		},
	)
}

func (registry *Service) ApplyGlobalIdentityLinkAction(
	ctx context.Context,
	request protocol.GlobalIdentityLinkActionRequest,
) (protocol.GlobalIdentityMutationResponse, error) {
	payload := protocol.GlobalIdentityLinkActionPayload(request)
	requestHash, signature, err := registry.verifyGlobalIdentityRequest(
		ctx,
		protocol.GlobalIdentityLinkActionPath,
		request.ProtocolVersion,
		request.RegistryScope,
		request.DeploymentID,
		request.Timestamp,
		request.Nonce,
		request.IdempotencyKey,
		request.PayloadHash,
		request.Signature,
		payload,
	)
	if err != nil {
		return protocol.GlobalIdentityMutationResponse{}, err
	}
	if !globalIdentityLinkIDPattern.MatchString(request.LinkID) ||
		!periodPattern.MatchString(request.EffectivePeriod) ||
		!protocol.IsDigest(request.ReasonCommitment) {
		return protocol.GlobalIdentityMutationResponse{},
			requestError(
				"invalid_request",
				"link_id, effective_period, or reason_commitment is malformed",
			)
	}
	input := store.GlobalIdentityMutationInput{
		Action:           request.Action,
		DeploymentID:     request.DeploymentID,
		IdempotencyKey:   request.IdempotencyKey,
		Nonce:            request.Nonce,
		RequestTimestamp: request.Timestamp,
		RequestHash:      requestHash,
		RequestSignature: signature,
		PayloadHash:      request.PayloadHash,
		LinkID:           request.LinkID,
		EffectivePeriod:  request.EffectivePeriod,
		ReasonCommitment: request.ReasonCommitment,
	}
	switch request.Action {
	case protocol.GlobalIdentityActionUnlink:
		if request.ReplacementKeyVersion != 0 ||
			request.ReplacementSuite != "" ||
			request.ReplacementCommitment != "" ||
			request.ConsentVersion != "" ||
			request.ConsentEvidenceCommitment != "" ||
			request.VerifiedAt != "" {
			return protocol.GlobalIdentityMutationResponse{},
				requestError(
					"invalid_request",
					"UNLINK must not contain replacement or consent fields",
				)
		}
	case protocol.GlobalIdentityActionCorrect:
		if err := registry.validateGlobalIdentityAlias(
			request.ReplacementKeyVersion,
			request.ReplacementSuite,
			request.ReplacementCommitment,
			false,
		); err != nil {
			return protocol.GlobalIdentityMutationResponse{}, err
		}
		if request.ConsentVersion != protocol.GlobalIdentityConsentVersion ||
			!protocol.IsDigest(request.ConsentEvidenceCommitment) {
			return protocol.GlobalIdentityMutationResponse{},
				requestError(
					"invalid_request",
					"corrected consent metadata is malformed or unsupported",
				)
		}
		if err := validateHistoricalTimestamp(
			"verified_at",
			request.VerifiedAt,
			registry.canonicalNow(),
		); err != nil {
			return protocol.GlobalIdentityMutationResponse{}, err
		}
		input.KeyVersion = request.ReplacementKeyVersion
		input.RequiredActiveKeyVersion = registry.globalIdentityKeys.
			ActivePublicKey().Version
		input.Suite = request.ReplacementSuite
		input.NetworkIdentityCommitment = request.ReplacementCommitment
		input.ConsentVersion = request.ConsentVersion
		input.ConsentEvidenceCommitment =
			request.ConsentEvidenceCommitment
		input.VerifiedAt = request.VerifiedAt
	default:
		return protocol.GlobalIdentityMutationResponse{},
			requestError(
				"invalid_request",
				"action must be UNLINK or CORRECT",
			)
	}
	return registry.applyGlobalIdentityMutation(ctx, input)
}

func (registry *Service) SubmitGlobalIdentityPresenceBatch(
	ctx context.Context,
	request protocol.GlobalIdentityPresenceBatchRequest,
) (protocol.GlobalIdentityPresenceBatchResponse, error) {
	payload := protocol.GlobalIdentityPresenceBatchPayload(request)
	requestHash, signature, err := registry.verifyGlobalIdentityRequest(
		ctx,
		protocol.GlobalIdentityPresenceBatchPath,
		request.ProtocolVersion,
		request.RegistryScope,
		request.DeploymentID,
		request.Timestamp,
		request.Nonce,
		request.IdempotencyKey,
		request.PayloadHash,
		request.Signature,
		payload,
	)
	if err != nil {
		return protocol.GlobalIdentityPresenceBatchResponse{}, err
	}
	if !periodPattern.MatchString(request.Period) ||
		request.Revision < 1 ||
		request.ReportedQMAUCount < 0 ||
		len(request.Commitments) > globalIdentityMaximumCommitments ||
		!globalIdentityPresenceSubmissionIDPattern.MatchString(
			request.SubmissionID,
		) ||
		request.ChunkCount < 1 ||
		request.ChunkCount > globalIdentityMaximumPresenceChunks ||
		request.ChunkIndex < 0 ||
		request.ChunkIndex >= request.ChunkCount ||
		request.TotalCommitmentCount < 0 ||
		request.TotalCommitmentCount > request.ReportedQMAUCount ||
		int64(len(request.Commitments)) > request.TotalCommitmentCount ||
		request.TotalCommitmentCount >
			request.ChunkCount*globalIdentityMaximumCommitments ||
		request.ChunkCount > maxInt64(1, request.TotalCommitmentCount) ||
		(request.TotalCommitmentCount == 0 &&
			(request.ChunkCount != 1 ||
				request.ChunkIndex != 0 ||
				len(request.Commitments) != 0)) ||
		(request.TotalCommitmentCount > 0 &&
			len(request.Commitments) == 0) ||
		!protocol.IsDigest(request.CommitmentSetHash) {
		return protocol.GlobalIdentityPresenceBatchResponse{},
			requestError(
				"invalid_request",
				"presence submission, period, revision, chunk manifest, or counts are invalid",
			)
	}
	if request.SupersedesBatchID != "" &&
		!batchIDPattern.MatchString(request.SupersedesBatchID) {
		return protocol.GlobalIdentityPresenceBatchResponse{},
			requestError(
				"invalid_request",
				"supersedes_batch_id is malformed",
			)
	}
	if err := registry.validateGlobalIdentityKey(
		request.KeyVersion,
		request.Suite,
		false,
	); err != nil {
		return protocol.GlobalIdentityPresenceBatchResponse{}, err
	}
	for index, commitment := range request.Commitments {
		if !protocol.IsDigest(commitment) {
			return protocol.GlobalIdentityPresenceBatchResponse{},
				requestError(
					"invalid_request",
					"network_identity_commitments must contain only lowercase sha256 commitments",
				)
		}
		if index > 0 &&
			strings.Compare(
				request.Commitments[index-1],
				commitment,
			) > 0 {
			return protocol.GlobalIdentityPresenceBatchResponse{},
				requestError(
					"invalid_request",
					"network_identity_commitments must be sorted bytewise",
				)
		}
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.GlobalIdentityPresenceBatchResponse{},
			registryIntegrityRequestError(err)
	}
	eventID, err := registry.newID("gievt_")
	if err != nil {
		return protocol.GlobalIdentityPresenceBatchResponse{}, err
	}
	batchID, err := registry.newID("batch_")
	if err != nil {
		return protocol.GlobalIdentityPresenceBatchResponse{}, err
	}
	acceptedAt := registry.canonicalNow().Format(time.RFC3339)
	record, duplicate, err :=
		registry.store.AcceptGlobalIdentityPresenceBatch(
			ctx,
			store.GlobalIdentityPresenceInput{
				DeploymentID:      request.DeploymentID,
				IdempotencyKey:    request.IdempotencyKey,
				Nonce:             request.Nonce,
				RequestTimestamp:  request.Timestamp,
				RequestHash:       requestHash,
				RequestSignature:  signature,
				PayloadHash:       request.PayloadHash,
				CandidateEventID:  eventID,
				CandidateBatchID:  batchID,
				SubmissionID:      request.SubmissionID,
				Period:            request.Period,
				Revision:          request.Revision,
				SupersedesBatchID: request.SupersedesBatchID,
				ReportedQMAUCount: request.ReportedQMAUCount,
				KeyVersion:        request.KeyVersion,
				RequiredActiveKeyVersion: registry.globalIdentityKeys.
					ActivePublicKey().Version,
				Suite:                request.Suite,
				ChunkIndex:           request.ChunkIndex,
				ChunkCount:           request.ChunkCount,
				TotalCommitmentCount: request.TotalCommitmentCount,
				CommitmentSetHash:    request.CommitmentSetHash,
				Commitments: append(
					[]string(nil),
					request.Commitments...,
				),
				AcceptedAt:    acceptedAt,
				RegistryScope: registry.registryScope,
				RegistryKeyID: registry.signingKey.KeyID(),
			},
			registry.signGlobalIdentityEvent,
			registry.signGlobalIdentityPresenceReceipt,
		)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.GlobalIdentityPresenceBatchResponse{},
				requestError(
					"qmau_source_not_found",
					"matching qualified MAU revision was not found",
				)
		}
		return protocol.GlobalIdentityPresenceBatchResponse{},
			mapStoreError(err)
	}
	return registry.globalIdentityPresenceResponse(
		record,
		duplicate,
	), nil
}

func (registry *Service) GlobalIdentityDedupSnapshot(
	ctx context.Context,
	period string,
) (protocol.GlobalIdentityDedupSnapshot, error) {
	if !periodPattern.MatchString(period) {
		return protocol.GlobalIdentityDedupSnapshot{},
			requestError(
				"invalid_request",
				"period must be a UTC month in YYYY-MM",
			)
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.GlobalIdentityDedupSnapshot{},
			registryIntegrityRequestError(err)
	}
	snapshot, err := registry.store.GlobalIdentityDedupSnapshot(ctx, period)
	if errors.Is(err, store.ErrNotFound) {
		return protocol.GlobalIdentityDedupSnapshot{},
			requestError(
				"global_identity_snapshot_not_found",
				"global identity dedup snapshot was not found",
			)
	}
	if err != nil {
		return protocol.GlobalIdentityDedupSnapshot{}, err
	}
	snapshot.RegistryScope = registry.registryScope
	return snapshot, nil
}

func (registry *Service) applyGlobalIdentityMutation(
	ctx context.Context,
	input store.GlobalIdentityMutationInput,
) (protocol.GlobalIdentityMutationResponse, error) {
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.GlobalIdentityMutationResponse{},
			registryIntegrityRequestError(err)
	}
	eventID, err := registry.newID("gievt_")
	if err != nil {
		return protocol.GlobalIdentityMutationResponse{}, err
	}
	linkID, err := registry.newID("gil_")
	if err != nil {
		return protocol.GlobalIdentityMutationResponse{}, err
	}
	globalID, err := registry.newID("gid_")
	if err != nil {
		return protocol.GlobalIdentityMutationResponse{}, err
	}
	input.CandidateEventID = eventID
	input.CandidateLinkID = linkID
	input.CandidateGlobalIdentityID = globalID
	input.PrivateEventHash = protocol.Digest(
		protocol.GlobalIdentityPrivateEventCommitment(
			input.Action,
			input.DeploymentID,
			firstNonEmpty(input.LinkID, input.CandidateLinkID),
			input.KeyVersion,
			input.NetworkIdentityCommitment,
			input.ConsentEvidenceCommitment,
			input.ReasonCommitment,
			input.EffectivePeriod,
			input.PayloadHash,
		),
	)
	input.AcceptedAt = registry.canonicalNow().Format(time.RFC3339)
	input.RegistryScope = registry.registryScope
	input.RegistryKeyID = registry.signingKey.KeyID()
	link, event, duplicate, err := registry.store.ApplyGlobalIdentityMutation(
		ctx,
		input,
		registry.signGlobalIdentityEvent,
	)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.GlobalIdentityMutationResponse{},
				requestError(
					"global_identity_link_not_found",
					"global identity link was not found",
				)
		}
		return protocol.GlobalIdentityMutationResponse{}, mapStoreError(err)
	}
	return protocol.GlobalIdentityMutationResponse{
		ProtocolVersion:   protocol.Version,
		RegistryScope:     registry.registryScope,
		Link:              globalIdentityProtocolLink(link),
		Event:             globalIdentityProtocolEvent(event),
		RegistryPublicKey: registry.signingKey.EncodedPublicKey(),
		Duplicate:         duplicate,
	}, nil
}

func (registry *Service) verifyGlobalIdentityRequest(
	ctx context.Context,
	path string,
	protocolVersion string,
	registryScope string,
	deploymentID string,
	timestamp string,
	nonce string,
	idempotencyKey string,
	payloadHash string,
	encodedSignature string,
	payload []byte,
) (string, []byte, error) {
	if protocolVersion != protocol.Version {
		return "", nil,
			requestError(
				"unsupported_protocol",
				"protocol_version must be \"1\"",
			)
	}
	if registryScope != registry.registryScope ||
		!protocol.IsRegistryScope(registryScope) {
		return "", nil,
			requestError(
				"registry_scope_mismatch",
				"request is addressed to a different sovereign registry scope",
			)
	}
	if !deploymentIDPattern.MatchString(deploymentID) {
		return "", nil,
			requestError(
				"invalid_request",
				"deployment_id is malformed",
			)
	}
	if err := validateToken("nonce", nonce); err != nil {
		return "", nil, err
	}
	if err := validateToken("idempotency_key", idempotencyKey); err != nil {
		return "", nil, err
	}
	if _, err := registry.validateTimestamp(timestamp); err != nil {
		return "", nil, err
	}
	if !protocol.IsDigest(payloadHash) ||
		payloadHash != protocol.Digest(payload) {
		return "", nil,
			requestError(
				"invalid_payload_hash",
				"payload_hash does not match the canonical global identity payload",
			)
	}
	deployment, err := registry.store.Deployment(ctx, deploymentID)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil,
			requestError(
				"deployment_not_found",
				"deployment is not registered",
			)
	}
	if err != nil {
		return "", nil, err
	}
	publicKey, err := parseStoredPublicKey(deployment.PublicKeyDER)
	if err != nil {
		return "", nil,
			fmt.Errorf("%w: %v", store.ErrInconsistentState, err)
	}
	signature, err := protocol.ParseSignature(encodedSignature)
	if err != nil {
		return "", nil,
			requestError(
				"invalid_signature",
				"signature must be canonical padded base64 Ed25519",
			)
	}
	message := protocol.CanonicalRequest(
		"POST",
		path,
		protocolVersion,
		registryScope,
		deploymentID,
		timestamp,
		nonce,
		idempotencyKey,
		payloadHash,
	)
	if !ed25519.Verify(publicKey, message, signature) {
		return "", nil,
			requestError(
				"invalid_signature",
				"deployment signature verification failed",
			)
	}
	return protocol.Digest(message), signature, nil
}

func (registry *Service) validateGlobalIdentityAlias(
	keyVersion int64,
	suite string,
	commitment string,
	requireActive bool,
) error {
	if !protocol.IsDigest(commitment) {
		return requestError(
			"invalid_request",
			"network_identity_commitment must be a lowercase sha256 commitment",
		)
	}
	return registry.validateGlobalIdentityKey(
		keyVersion,
		suite,
		requireActive,
	)
}

func (registry *Service) validateGlobalIdentityKey(
	keyVersion int64,
	suite string,
	requireActive bool,
) error {
	if registry.globalIdentityKeys == nil ||
		keyVersion < 1 ||
		suite != protocol.GlobalIdentityVOPRFSuite {
		return requestError(
			"global_identity_key_unavailable",
			"requested VOPRF key is unavailable",
		)
	}
	key, ok := registry.globalIdentityKeys.PublicKey(keyVersion)
	if !ok || (requireActive && !key.Active) {
		return requestError(
			"global_identity_key_unavailable",
			"requested VOPRF key is unavailable or retired",
		)
	}
	return nil
}

func (registry *Service) globalIdentityEvaluationResponse(
	record store.GlobalIdentityEvaluationRecord,
	duplicate bool,
) protocol.GlobalIdentityEvaluationResponse {
	return protocol.GlobalIdentityEvaluationResponse{
		ProtocolVersion:   protocol.Version,
		RegistryScope:     registry.registryScope,
		DeploymentID:      record.DeploymentID,
		KeyVersion:        record.KeyVersion,
		Suite:             record.Suite,
		PublicKey:         base64.StdEncoding.EncodeToString(record.PublicKey),
		EvaluatedElement:  base64.StdEncoding.EncodeToString(record.EvaluatedElement),
		Proof:             base64.StdEncoding.EncodeToString(record.Proof),
		RequestHash:       record.RequestHash,
		ResponseHash:      record.ResponseHash,
		EvaluatedAt:       record.EvaluatedAt,
		RegistryKeyID:     registry.signingKey.KeyID(),
		RegistryPublicKey: registry.signingKey.EncodedPublicKey(),
		ReceiptSignature:  protocol.EncodeSignature(record.ReceiptSignature),
		Duplicate:         duplicate,
	}
}

func (registry *Service) signGlobalIdentityEvent(
	event store.GlobalIdentityEvent,
) ([]byte, error) {
	return registry.signingKey.Sign(
		protocol.GlobalIdentityEventReceiptMessage(
			globalIdentityProtocolEvent(event),
		),
	), nil
}

func (registry *Service) signGlobalIdentityPresenceReceipt(
	response protocol.GlobalIdentityPresenceBatchResponse,
) ([]byte, error) {
	return registry.signingKey.Sign(
		protocol.GlobalIdentityPresenceChunkReceiptMessage(response),
	), nil
}

func (registry *Service) globalIdentityPresenceResponse(
	record store.GlobalIdentityPresenceRecord,
	duplicate bool,
) protocol.GlobalIdentityPresenceBatchResponse {
	response := protocol.GlobalIdentityPresenceBatchResponse{
		ProtocolVersion:      protocol.Version,
		RegistryScope:        registry.registryScope,
		SubmissionID:         record.SubmissionID,
		DeploymentID:         record.DeploymentID,
		Period:               record.Period,
		Revision:             record.Revision,
		ChunkIndex:           record.ChunkIndex,
		ChunkCount:           record.ChunkCount,
		ReceivedChunkCount:   record.ReceivedChunkCount,
		TotalCommitmentCount: record.TotalCommitmentCount,
		CommitmentSetHash:    record.CommitmentSetHash,
		Complete:             record.Complete,
		BatchID:              record.BatchID,
		LinkedCount:          record.LinkedObservationCount,
		UnlinkedCount:        record.UnlinkedQMAUCount,
		RequestHash:          record.RequestHash,
		PayloadHash:          record.PayloadHash,
		AcceptedAt:           record.AcceptedAt,
		RegistryKeyID:        record.RegistryKeyID,
		RegistryPublicKey:    registry.signingKey.EncodedPublicKey(),
		ReceiptHash:          record.ReceiptHash,
		ReceiptSignature: protocol.EncodeSignature(
			record.ReceiptSignature,
		),
		Duplicate: duplicate,
	}
	if record.Complete {
		event := globalIdentityProtocolEvent(record.Event)
		snapshot := record.Snapshot
		snapshot.RegistryScope = registry.registryScope
		response.Event = &event
		response.Snapshot = &snapshot
	}
	return response
}

func globalIdentityProtocolLink(
	link store.GlobalIdentityLink,
) protocol.GlobalIdentityLink {
	return protocol.GlobalIdentityLink{
		LinkID:             link.LinkID,
		DeploymentID:       link.DeploymentID,
		Status:             link.Status,
		KeyVersion:         link.KeyVersion,
		Suite:              link.Suite,
		ActiveFromPeriod:   link.ActiveFromPeriod,
		InactiveFromPeriod: link.InactiveFromPeriod,
		ConsentVersion:     link.ConsentVersion,
		VerifiedAt:         link.VerifiedAt,
		LatestEventIndex:   link.LatestEventIndex,
		LatestEventHash:    link.LatestEventHash,
	}
}

func globalIdentityProtocolEvent(
	event store.GlobalIdentityEvent,
) protocol.GlobalIdentityEvent {
	return protocol.GlobalIdentityEvent{
		EventIndex:          event.EventIndex,
		EventID:             event.EventID,
		Action:              event.Action,
		DeploymentID:        event.DeploymentID,
		Period:              event.Period,
		AggregateCommitment: event.AggregateCommitment,
		ReportedCount:       event.ReportedCount,
		DeduplicatedCount:   event.DeduplicatedCount,
		AcceptedAt:          event.AcceptedAt,
		PreviousEventHash:   event.PreviousEventHash,
		EventHash:           event.EventHash,
		RegistryScope:       event.RegistryScope,
		RegistryKeyID:       event.RegistryKeyID,
		Signature:           protocol.EncodeSignature(event.ReceiptSignature),
	}
}

func decodeCanonicalBase64(
	name string,
	value string,
	expectedLength int,
) ([]byte, error) {
	if value == "" || protocol.HasCanonicalLineBreak(value) {
		return nil,
			requestError(
				"invalid_request",
				name+" must be canonical padded base64",
			)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil ||
		len(decoded) != expectedLength ||
		base64.StdEncoding.EncodeToString(decoded) != value {
		return nil,
			requestError(
				"invalid_request",
				name+" must be canonical padded base64 with the expected length",
			)
	}
	return decoded, nil
}

func validateHistoricalTimestamp(
	name string,
	value string,
	now time.Time,
) error {
	if protocol.HasCanonicalLineBreak(value) ||
		!strings.HasSuffix(value, "Z") {
		return requestError(
			"invalid_request",
			name+" must be an RFC 3339 UTC timestamp",
		)
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.After(now.Add(time.Minute)) {
		return requestError(
			"invalid_request",
			name+" must be a non-future RFC 3339 UTC timestamp",
		)
	}
	return nil
}

func registryIntegrityRequestError(err error) error {
	return requestError(
		"registry_integrity_unavailable",
		"registry integrity verification failed; global identity writes are temporarily unavailable",
	)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

var globalIdentityLinkIDPattern = regexp.MustCompile(`^gil_[0-9a-f]{32}$`)
var globalIdentityPresenceSubmissionIDPattern = regexp.MustCompile(
	`^gipsub_[0-9a-f]{32}$`,
)

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
