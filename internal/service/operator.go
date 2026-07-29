package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const (
	defaultLeaderboardLimit = 20
	maxLeaderboardLimit     = 100
	operatorWeightMonths    = int64(6)
)

var (
	operatorTokenIDPattern    = regexp.MustCompile(`^opt_[0-9a-f]{32}$`)
	operatorLinkIDPattern     = regexp.MustCompile(`^opl_[0-9a-f]{32}$`)
	operatorGroupIDPattern    = regexp.MustCompile(`^opg_[0-9a-f]{32}$`)
	operatorActionIDPattern   = regexp.MustCompile(`^opa_[0-9a-f]{32}$`)
	operatorEmailLocalPattern = regexp.MustCompile(
		`^[a-z0-9!#$%&'*+/=?^_` + "`" + `{|}~.-]+$`,
	)
	operatorEmailDomainLabelPattern = regexp.MustCompile(
		`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`,
	)
)

type validatedOperatorAction struct {
	ClientTokenHash string
	TokenTTLSeconds int64
}

type leaderboardCursor struct {
	Version            int    `json:"version"`
	Kind               string `json:"kind"`
	View               string `json:"view"`
	GroupID            string `json:"group_id,omitempty"`
	SnapshotID         string `json:"snapshot_id"`
	FromPeriod         string `json:"from_period"`
	ThroughPeriod      string `json:"through_period"`
	ThroughLedgerIndex int64  `json:"through_ledger_index"`
	ThroughAuditIndex  int64  `json:"through_audit_index"`
	LedgerHeadHash     string `json:"ledger_head_hash"`
	AuditHeadHash      string `json:"audit_head_hash"`
	CreatedAt          string `json:"created_at"`
	AfterWeight        int64  `json:"after_weight"`
	AfterID            string `json:"after_id"`
}

func (registry *Service) ApplyOperatorAction(
	ctx context.Context,
	request protocol.OperatorActionRequest,
) (protocol.OperatorActionResponse, error) {
	if request.ProtocolVersion != protocol.Version {
		return protocol.OperatorActionResponse{}, requestError(
			"unsupported_protocol",
			"protocol_version must be \"1\"",
		)
	}
	if request.RegistryScope != registry.registryScope {
		return protocol.OperatorActionResponse{}, requestError(
			"registry_scope_mismatch",
			"request is addressed to a different sovereign registry scope",
		)
	}
	if !deploymentIDPattern.MatchString(request.DeploymentID) {
		return protocol.OperatorActionResponse{}, requestError(
			"invalid_request",
			"deployment_id is malformed",
		)
	}
	if err := validateToken("nonce", request.Nonce); err != nil {
		return protocol.OperatorActionResponse{}, err
	}
	if err := validateToken("idempotency_key", request.IdempotencyKey); err != nil {
		return protocol.OperatorActionResponse{}, err
	}
	if !protocol.IsDigest(request.PayloadHash) {
		return protocol.OperatorActionResponse{}, requestError(
			"invalid_request",
			"payload_hash must be a lowercase sha256 digest",
		)
	}
	if _, err := registry.validateTimestamp(request.Timestamp); err != nil {
		return protocol.OperatorActionResponse{}, err
	}
	validated, err := validateOperatorActionRequest(request)
	if err != nil {
		return protocol.OperatorActionResponse{}, err
	}
	expectedPayloadHash := operatorActionRequestPayloadHash(request, validated)
	if request.PayloadHash != expectedPayloadHash {
		return protocol.OperatorActionResponse{}, requestError(
			"invalid_payload_hash",
			"operator action payload_hash does not match the canonical payload",
		)
	}
	deployment, err := registry.store.Deployment(ctx, request.DeploymentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.OperatorActionResponse{}, requestError(
				"deployment_not_found",
				"deployment is not registered",
			)
		}
		return protocol.OperatorActionResponse{}, err
	}
	publicKey, err := parseStoredPublicKey(deployment.PublicKeyDER)
	if err != nil {
		return protocol.OperatorActionResponse{}, fmt.Errorf(
			"%w: invalid deployment public key: %v",
			store.ErrInconsistentState,
			err,
		)
	}
	signature, err := protocol.ParseSignature(request.Signature)
	if err != nil {
		return protocol.OperatorActionResponse{}, requestError(
			"invalid_signature",
			"signature must be canonical padded base64 Ed25519",
		)
	}
	requestMessage := protocol.CanonicalRequest(
		"POST",
		protocol.OperatorActionPath,
		request.ProtocolVersion,
		request.RegistryScope,
		request.DeploymentID,
		request.Timestamp,
		request.Nonce,
		request.IdempotencyKey,
		request.PayloadHash,
	)
	if !protocol.Verify(publicKey, requestMessage, signature) {
		return protocol.OperatorActionResponse{}, requestError(
			"invalid_signature",
			"operator action signature verification failed",
		)
	}
	if err := registry.VerifyState(ctx); err != nil {
		registry.logger.Error(
			"refusing operator action while registry integrity verification fails",
			"error",
			err,
		)
		return protocol.OperatorActionResponse{}, requestError(
			"registry_integrity_unavailable",
			"registry integrity verification failed; operator actions are temporarily unavailable",
		)
	}

	actionID, err := registry.newID("opa_")
	if err != nil {
		return protocol.OperatorActionResponse{}, fmt.Errorf("generate operator action ID: %w", err)
	}
	acceptedAtTime := registry.canonicalNow()
	input := store.OperatorActionInput{
		RegistryScope:            registry.registryScope,
		DeploymentID:             request.DeploymentID,
		Action:                   request.Action,
		RequestTimestamp:         request.Timestamp,
		Nonce:                    request.Nonce,
		IdempotencyKey:           request.IdempotencyKey,
		PayloadHash:              request.PayloadHash,
		RequestHash:              protocol.Digest(requestMessage),
		DeploymentSignature:      signature,
		OperatorName:             request.OperatorName,
		OperatorAvatarURL:        request.OperatorAvatarURL,
		LegalName:                request.LegalName,
		RegistrationNumber:       request.RegistrationNumber,
		Jurisdiction:             request.Jurisdiction,
		RegisteredAddress:        request.RegisteredAddress,
		Website:                  request.Website,
		VerificationContactName:  request.VerificationContactName,
		VerificationContactRole:  request.VerificationContactRole,
		VerificationContactEmail: request.VerificationContactEmail,
		AuthorityAttested:        request.AuthorityAttested,
		ClientTokenHash:          validated.ClientTokenHash,
		TokenTTLSeconds:          validated.TokenTTLSeconds,
		TokenID:                  request.TokenID,
		LinkID:                   request.LinkID,
		CandidateActionID:        actionID,
		AcceptedAt:               acceptedAtTime.Format(time.RFC3339),
		RegistryKeyID:            registry.signingKey.KeyID(),
	}

	issuedClientToken := ""
	switch request.Action {
	case protocol.OperatorActionClaim:
		input.CandidateGroupID, err = registry.newID("opg_")
	case protocol.OperatorActionIssueClientToken:
		input.CandidateTokenID, err = registry.newID("opt_")
		if err == nil {
			issuedClientToken, err = registry.newID("opc_")
		}
		if err == nil {
			input.CandidateClientTokenHash = protocol.Digest([]byte(issuedClientToken))
			input.CandidateTokenExpiresAt = acceptedAtTime.
				Add(time.Duration(validated.TokenTTLSeconds) * time.Second).
				Format(time.RFC3339)
		}
	case protocol.OperatorActionRedeemClientToken:
		input.CandidateLinkID, err = registry.newID("opl_")
	}
	if err != nil {
		return protocol.OperatorActionResponse{}, fmt.Errorf(
			"generate operator action material: %w",
			err,
		)
	}

	event, duplicate, err := registry.store.AppendOperatorAction(
		ctx,
		input,
		func(event store.OperatorAuditEvent) ([]byte, error) {
			receipt := registry.operatorActionReceipt(event)
			return registry.signingKey.Sign(
				protocol.OperatorActionReceiptMessage(receipt),
			), nil
		},
	)
	if err != nil {
		return protocol.OperatorActionResponse{}, mapOperatorStoreError(err)
	}
	receipt := registry.operatorActionReceipt(event)
	if request.Action == protocol.OperatorActionIssueClientToken && !duplicate {
		receipt.ClientToken = issuedClientToken
	}
	receipt.Signature = protocol.EncodeSignature(event.ReceiptSignature)
	return protocol.OperatorActionResponse{
		ProtocolVersion: protocol.Version,
		RegistryScope:   registry.registryScope,
		Duplicate:       duplicate,
		Receipt:         receipt,
	}, nil
}

func operatorActionRequestPayloadHash(
	request protocol.OperatorActionRequest,
	validated validatedOperatorAction,
) string {
	if request.Action == protocol.OperatorActionClaim {
		return protocol.Digest(protocol.OperatorClaimPayload(
			request.LegalName,
			request.RegistrationNumber,
			request.Jurisdiction,
			request.RegisteredAddress,
			request.Website,
			request.VerificationContactName,
			request.VerificationContactRole,
			request.VerificationContactEmail,
			request.AuthorityAttested,
			request.OperatorAvatarURL,
		))
	}
	return protocol.Digest(protocol.OperatorActionPayload(
		request.Action,
		request.OperatorName,
		request.OperatorAvatarURL,
		validated.ClientTokenHash,
		validated.TokenTTLSeconds,
		request.TokenID,
		request.LinkID,
	))
}

func validateOperatorActionRequest(
	request protocol.OperatorActionRequest,
) (validatedOperatorAction, error) {
	validated := validatedOperatorAction{}
	unexpected := func(values ...bool) bool {
		for _, value := range values {
			if value {
				return true
			}
		}
		return false
	}
	hasName := request.OperatorName != ""
	hasAvatar := request.OperatorAvatarURL != ""
	hasClaimVerification := request.LegalName != "" ||
		request.RegistrationNumber != "" ||
		request.Jurisdiction != "" ||
		request.RegisteredAddress != "" ||
		request.Website != "" ||
		request.VerificationContactName != "" ||
		request.VerificationContactRole != "" ||
		request.VerificationContactEmail != "" ||
		request.AuthorityAttested
	hasToken := request.ClientToken != ""
	hasTTL := request.TokenTTLSeconds != 0
	hasTokenID := request.TokenID != ""
	hasLinkID := request.LinkID != ""

	switch request.Action {
	case protocol.OperatorActionClaim:
		if hasName {
			return validated, requestError(
				"invalid_request",
				"operator_name is not accepted for structured claims; legal_name is the operator label",
			)
		}
		if err := validateClaimText("legal_name", request.LegalName, 160); err != nil {
			return validated, err
		}
		if err := validateClaimText(
			"registration_number",
			request.RegistrationNumber,
			80,
		); err != nil {
			return validated, err
		}
		if err := validateClaimText("jurisdiction", request.Jurisdiction, 80); err != nil {
			return validated, err
		}
		if err := validateClaimText(
			"registered_address",
			request.RegisteredAddress,
			500,
		); err != nil {
			return validated, err
		}
		if err := validateOperatorHTTPSURL("website", request.Website); err != nil {
			return validated, err
		}
		if err := validateClaimText(
			"verification_contact_name",
			request.VerificationContactName,
			120,
		); err != nil {
			return validated, err
		}
		if err := validateClaimText(
			"verification_contact_role",
			request.VerificationContactRole,
			120,
		); err != nil {
			return validated, err
		}
		if err := validateOperatorEmail(request.VerificationContactEmail); err != nil {
			return validated, err
		}
		if !request.AuthorityAttested {
			return validated, requestError(
				"invalid_request",
				"authority_attested must be true",
			)
		}
		if !hasClaimVerification {
			return validated, requestError(
				"invalid_request",
				"structured company verification fields are required",
			)
		}
		if hasAvatar {
			if err := validateOperatorAvatarURL(request.OperatorAvatarURL); err != nil {
				return validated, err
			}
		}
		if unexpected(hasToken, hasTTL, hasTokenID, hasLinkID) {
			return validated, unexpectedOperatorFields()
		}
	case protocol.OperatorActionWithdrawClaim,
		protocol.OperatorActionDeactivateDeployment,
		protocol.OperatorActionReactivateDeployment:
		if unexpected(
			hasName,
			hasAvatar,
			hasClaimVerification,
			hasToken,
			hasTTL,
			hasTokenID,
			hasLinkID,
		) {
			return validated, unexpectedOperatorFields()
		}
	case protocol.OperatorActionIssueClientToken:
		if unexpected(hasName, hasAvatar, hasClaimVerification, hasToken, hasTokenID, hasLinkID) {
			return validated, unexpectedOperatorFields()
		}
		if request.TokenTTLSeconds < 60 || request.TokenTTLSeconds > 3600 {
			return validated, requestError(
				"invalid_request",
				"token_ttl_seconds must be between 60 and 3600",
			)
		}
		validated.TokenTTLSeconds = request.TokenTTLSeconds
	case protocol.OperatorActionRevokeClientToken:
		if unexpected(hasName, hasAvatar, hasClaimVerification, hasToken, hasTTL, hasLinkID) ||
			!operatorTokenIDPattern.MatchString(request.TokenID) {
			return validated, requestError(
				"invalid_request",
				"token_id is malformed or incompatible fields were supplied",
			)
		}
	case protocol.OperatorActionRedeemClientToken:
		if unexpected(hasName, hasAvatar, hasClaimVerification, hasTTL, hasTokenID, hasLinkID) {
			return validated, unexpectedOperatorFields()
		}
		if err := validateToken("client_token", request.ClientToken); err != nil {
			return validated, err
		}
		validated.ClientTokenHash = protocol.Digest([]byte(request.ClientToken))
	case protocol.OperatorActionRevokeGroupLink:
		if unexpected(hasName, hasAvatar, hasClaimVerification, hasToken, hasTTL, hasTokenID) ||
			!operatorLinkIDPattern.MatchString(request.LinkID) {
			return validated, requestError(
				"invalid_request",
				"link_id is malformed or incompatible fields were supplied",
			)
		}
	default:
		return validated, requestError(
			"invalid_request",
			"action is not supported",
		)
	}
	return validated, nil
}

func validateClaimText(name, value string, maximum int) error {
	if err := validateCanonicalText(name, value, 1, maximum); err != nil {
		return err
	}
	if strings.TrimSpace(value) != value {
		return requestError("invalid_request", name+" must not have surrounding whitespace")
	}
	return nil
}

func validateOperatorEmail(value string) error {
	if err := validateClaimText("verification_contact_email", value, 254); err != nil {
		return err
	}
	if value != strings.ToLower(value) || !strings.Contains(value, "@") {
		return requestError(
			"invalid_request",
			"verification_contact_email must be a canonical lowercase email address",
		)
	}
	local, domain, found := strings.Cut(value, "@")
	if !found ||
		strings.Contains(domain, "@") ||
		len(local) > 64 ||
		local == "" ||
		domain == "" ||
		strings.HasPrefix(local, ".") ||
		strings.HasSuffix(local, ".") ||
		strings.Contains(local, "..") ||
		!operatorEmailLocalPattern.MatchString(local) {
		return requestError(
			"invalid_request",
			"verification_contact_email must be a canonical lowercase email address",
		)
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return requestError(
			"invalid_request",
			"verification_contact_email must be a canonical lowercase email address",
		)
	}
	for _, label := range labels {
		if !operatorEmailDomainLabelPattern.MatchString(label) {
			return requestError(
				"invalid_request",
				"verification_contact_email must be a canonical lowercase email address",
			)
		}
	}
	return nil
}

func unexpectedOperatorFields() error {
	return requestError(
		"invalid_request",
		"operator action contains fields that are not valid for this action",
	)
}

func validateOperatorAvatarURL(value string) error {
	return validateOperatorHTTPSURL("operator_avatar_url", value)
}

func validateOperatorHTTPSURL(name, value string) error {
	if err := validateClaimText(name, value, 2048); err != nil {
		return err
	}
	parsed, err := url.Parse(value)
	if err != nil ||
		parsed.Scheme != "https" ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.Fragment != "" {
		return requestError(
			"invalid_request",
			name+" must be an absolute HTTPS URL without credentials or fragment",
		)
	}
	return nil
}

func (registry *Service) operatorActionReceipt(
	event store.OperatorAuditEvent,
) protocol.OperatorActionReceipt {
	return protocol.OperatorActionReceipt{
		AuditIndex:              event.AuditIndex,
		AuditHash:               event.AuditHash,
		PreviousAuditHash:       event.PreviousAuditHash,
		ActionID:                event.ActionID,
		DeploymentID:            event.DeploymentID,
		SubjectDeploymentID:     event.SubjectDeploymentID,
		RelatedDeploymentID:     event.RelatedDeploymentID,
		Action:                  event.Action,
		AcceptedAt:              event.AcceptedAt,
		ClaimState:              event.ClaimState,
		GroupID:                 event.GroupID,
		LinkID:                  event.LinkID,
		TokenID:                 event.TokenID,
		ClientTokenHash:         event.ClientTokenHash,
		SourceClaimActionID:     event.SourceClaimActionID,
		SourcePrivateRecordHash: event.SourcePrivateRecordHash,
		TokenExpiresAt:          event.TokenExpiresAt,
		RegistryScope:           registry.registryScope,
		RegistryKeyID:           registry.signingKey.KeyID(),
	}
}

func mapOperatorStoreError(err error) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return requestError(
			"operator_reference_not_found",
			"the deployment, client token, or group link was not found",
		)
	case errors.Is(err, store.ErrOperatorClaimRequired):
		return requestError(
			"operator_claim_required",
			"an active claimed deployment is required",
		)
	case errors.Is(err, store.ErrClientTokenExpired):
		return requestError("client_token_expired", "the operator client token has expired")
	case errors.Is(err, store.ErrClientTokenRevoked):
		return requestError("client_token_revoked", "the operator client token was revoked")
	case errors.Is(err, store.ErrClientTokenUsed):
		return requestError("client_token_used", "the operator client token was already used")
	case errors.Is(err, store.ErrDeploymentInactive):
		return requestError("deployment_inactive", "the deployment is inactive")
	case errors.Is(err, store.ErrOperatorActionConflict):
		return requestError(
			"operator_action_conflict",
			"the action conflicts with current claim or grouping state",
		)
	default:
		return mapStoreError(err)
	}
}

func (registry *Service) Leaderboard(
	ctx context.Context,
	view string,
	throughPeriod string,
	limit int,
	cursor string,
) (protocol.LeaderboardPageDto, error) {
	if view != "founder" && view != "claimed" && view != "unclaimed" {
		return protocol.LeaderboardPageDto{}, requestError(
			"invalid_request",
			"leaderboard view must be founder, claimed, or unclaimed",
		)
	}
	pageLimit, err := validateLeaderboardLimit(limit)
	if err != nil {
		return protocol.LeaderboardPageDto{}, err
	}
	if err := registry.VerifyState(ctx); err != nil {
		registry.logger.Error("refusing leaderboard read while registry integrity verification fails", "error", err)
		return protocol.LeaderboardPageDto{}, requestError(
			"registry_integrity_unavailable",
			"registry integrity verification failed; leaderboard is temporarily unavailable",
		)
	}

	state, hasCursor, err := registry.leaderboardState(
		ctx,
		"rows",
		view,
		"",
		throughPeriod,
		cursor,
	)
	if err != nil {
		return protocol.LeaderboardPageDto{}, err
	}
	totals, err := registry.store.LeaderboardTotals(
		ctx,
		state.FromPeriod,
		state.ThroughPeriod,
		state.ThroughLedgerIndex,
		state.ThroughAuditIndex,
	)
	if err != nil {
		return protocol.LeaderboardPageDto{}, err
	}
	snapshot := registry.leaderboardSnapshot(state, totals)

	records := make([]store.LeaderboardRecord, 0, pageLimit+1)
	if view == "founder" {
		if !hasCursor {
			records = append(records, store.LeaderboardRecord{
				RowID:           "founder",
				View:            "founder",
				Label:           "Founder",
				ClaimState:      "founder",
				DeploymentCount: 0,
				Weight:          protocol.FounderContributionUnits * operatorWeightMonths,
				SortWeight:      protocol.FounderContributionUnits * operatorWeightMonths,
			})
		}
	} else {
		records, err = registry.store.LeaderboardRows(ctx, store.LeaderboardQuery{
			View:               view,
			FromPeriod:         state.FromPeriod,
			ThroughPeriod:      state.ThroughPeriod,
			ThroughLedgerIndex: state.ThroughLedgerIndex,
			ThroughAuditIndex:  state.ThroughAuditIndex,
			Limit:              pageLimit + 1,
			AfterWeight:        state.AfterWeight,
			AfterID:            state.AfterID,
			HasAfter:           hasCursor,
		})
		if err != nil {
			return protocol.LeaderboardPageDto{}, err
		}
	}

	hasMore := len(records) > pageLimit
	if hasMore {
		records = records[:pageLimit]
	}
	items := make([]protocol.LeaderboardRowDto, 0, len(records))
	for _, record := range records {
		weight := big.NewRat(record.Weight, operatorWeightMonths)
		share := registry.leaderboardShare(
			view,
			record.ClaimState,
			record.SortWeight,
			totals,
			snapshot,
		)
		items = append(items, protocol.LeaderboardRowDto{
			RowID:             record.RowID,
			View:              record.View,
			GroupID:           record.GroupID,
			Label:             record.Label,
			AvatarURL:         record.AvatarURL,
			ClaimState:        record.ClaimState,
			DeploymentCount:   record.DeploymentCount,
			WeightNumerator:   weight.Num().String(),
			WeightDenominator: weight.Denom().String(),
			ShareNumerator:    share.Num().String(),
			ShareDenominator:  share.Denom().String(),
		})
	}

	nextCursor := ""
	if hasMore && len(records) > 0 {
		last := records[len(records)-1]
		state.AfterWeight = last.SortWeight
		state.AfterID = last.RowID
		nextCursor, err = registry.encodeLeaderboardCursor(state)
		if err != nil {
			return protocol.LeaderboardPageDto{}, err
		}
	}
	return protocol.LeaderboardPageDto{
		Snapshot:   snapshot,
		View:       view,
		Items:      items,
		NextCursor: nextCursor,
	}, nil
}

func (registry *Service) LeaderboardDeployments(
	ctx context.Context,
	groupID string,
	throughPeriod string,
	limit int,
	cursor string,
) (protocol.LeaderboardDeploymentPageDto, error) {
	if !operatorGroupIDPattern.MatchString(groupID) {
		return protocol.LeaderboardDeploymentPageDto{}, requestError(
			"invalid_request",
			"group_id is malformed",
		)
	}
	pageLimit, err := validateLeaderboardLimit(limit)
	if err != nil {
		return protocol.LeaderboardDeploymentPageDto{}, err
	}
	if err := registry.VerifyState(ctx); err != nil {
		return protocol.LeaderboardDeploymentPageDto{}, requestError(
			"registry_integrity_unavailable",
			"registry integrity verification failed; leaderboard is temporarily unavailable",
		)
	}
	state, hasCursor, err := registry.leaderboardState(
		ctx,
		"deployments",
		"claimed",
		groupID,
		throughPeriod,
		cursor,
	)
	if err != nil {
		return protocol.LeaderboardDeploymentPageDto{}, err
	}
	totals, err := registry.store.LeaderboardTotals(
		ctx,
		state.FromPeriod,
		state.ThroughPeriod,
		state.ThroughLedgerIndex,
		state.ThroughAuditIndex,
	)
	if err != nil {
		return protocol.LeaderboardDeploymentPageDto{}, err
	}
	snapshot := registry.leaderboardSnapshot(state, totals)
	records, err := registry.store.LeaderboardDeployments(
		ctx,
		store.LeaderboardDeploymentQuery{
			GroupID:            groupID,
			FromPeriod:         state.FromPeriod,
			ThroughPeriod:      state.ThroughPeriod,
			ThroughLedgerIndex: state.ThroughLedgerIndex,
			ThroughAuditIndex:  state.ThroughAuditIndex,
			Limit:              pageLimit + 1,
			AfterWeight:        state.AfterWeight,
			AfterID:            state.AfterID,
			HasAfter:           hasCursor,
		},
	)
	if err != nil {
		return protocol.LeaderboardDeploymentPageDto{}, err
	}
	hasMore := len(records) > pageLimit
	if hasMore {
		records = records[:pageLimit]
	}
	items := make([]protocol.LeaderboardDeploymentDto, 0, len(records))
	for _, record := range records {
		weight := big.NewRat(record.Weight, operatorWeightMonths)
		share := registry.leaderboardShare(
			"claimed",
			record.ClaimState,
			record.SortWeight,
			totals,
			snapshot,
		)
		items = append(items, protocol.LeaderboardDeploymentDto{
			DeploymentID:      record.DeploymentID,
			GroupID:           record.GroupID,
			ClaimState:        record.ClaimState,
			MembershipState:   record.MembershipState,
			WeightNumerator:   weight.Num().String(),
			WeightDenominator: weight.Denom().String(),
			ShareNumerator:    share.Num().String(),
			ShareDenominator:  share.Denom().String(),
		})
	}
	nextCursor := ""
	if hasMore && len(records) > 0 {
		last := records[len(records)-1]
		state.AfterWeight = last.SortWeight
		state.AfterID = last.DeploymentID
		nextCursor, err = registry.encodeLeaderboardCursor(state)
		if err != nil {
			return protocol.LeaderboardDeploymentPageDto{}, err
		}
	}
	return protocol.LeaderboardDeploymentPageDto{
		Snapshot:   snapshot,
		GroupID:    groupID,
		Items:      items,
		NextCursor: nextCursor,
	}, nil
}

func (registry *Service) leaderboardState(
	ctx context.Context,
	kind string,
	view string,
	groupID string,
	requestedThroughPeriod string,
	encodedCursor string,
) (leaderboardCursor, bool, error) {
	if encodedCursor != "" {
		state, err := registry.decodeLeaderboardCursor(encodedCursor)
		if err != nil {
			return leaderboardCursor{}, false, err
		}
		if state.Kind != kind ||
			state.View != view ||
			state.GroupID != groupID ||
			(requestedThroughPeriod != "" &&
				requestedThroughPeriod != state.ThroughPeriod) {
			return leaderboardCursor{}, false, requestError(
				"invalid_cursor",
				"cursor does not belong to this leaderboard request",
			)
		}
		return state, true, nil
	}

	throughPeriod := requestedThroughPeriod
	latestCompleteMonth := monthStart(registry.canonicalNow()).AddDate(0, -1, 0)
	if throughPeriod == "" {
		throughPeriod = latestCompleteMonth.Format("2006-01")
	} else {
		parsed, err := time.Parse("2006-01", throughPeriod)
		if err != nil ||
			parsed.Format("2006-01") != throughPeriod ||
			parsed.After(latestCompleteMonth) {
			return leaderboardCursor{}, false, requestError(
				"invalid_request",
				"through_period must be a completed UTC month in YYYY-MM format",
			)
		}
	}
	parsedThrough, _ := time.Parse("2006-01", throughPeriod)
	fromPeriod := parsedThrough.AddDate(0, -5, 0).Format("2006-01")
	boundary, err := registry.store.LeaderboardBoundary(ctx)
	if err != nil {
		return leaderboardCursor{}, false, err
	}
	createdAt := registry.canonicalNow().Format(time.RFC3339)
	snapshotSeed := strings.Join([]string{
		kind,
		view,
		groupID,
		fromPeriod,
		throughPeriod,
		strconv.FormatInt(boundary.LedgerIndex, 10),
		strconv.FormatInt(boundary.AuditIndex, 10),
		boundary.LedgerHash,
		boundary.AuditHash,
		createdAt,
	}, "\x00")
	snapshotDigest := strings.TrimPrefix(
		protocol.Digest([]byte(snapshotSeed)),
		"sha256:",
	)
	return leaderboardCursor{
		Version:            1,
		Kind:               kind,
		View:               view,
		GroupID:            groupID,
		SnapshotID:         "snap_" + snapshotDigest[:32],
		FromPeriod:         fromPeriod,
		ThroughPeriod:      throughPeriod,
		ThroughLedgerIndex: boundary.LedgerIndex,
		ThroughAuditIndex:  boundary.AuditIndex,
		LedgerHeadHash:     boundary.LedgerHash,
		AuditHeadHash:      boundary.AuditHash,
		CreatedAt:          createdAt,
	}, false, nil
}

func (registry *Service) leaderboardSnapshot(
	state leaderboardCursor,
	totals store.LeaderboardTotals,
) protocol.LeaderboardSnapshotDto {
	founderShare := founderShare(totals.MeasuredWeight)
	measuredWeight := big.NewRat(totals.MeasuredWeight, operatorWeightMonths)
	claimedWeight := big.NewRat(totals.ClaimedWeight, operatorWeightMonths)
	snapshot := protocol.LeaderboardSnapshotDto{
		SnapshotID:                state.SnapshotID,
		FormulaVersion:            protocol.LeaderboardFormulaVersion,
		RulesetVersion:            protocol.LeaderboardRulesetVersion,
		ThroughPeriod:             state.ThroughPeriod,
		ThroughLedgerIndex:        state.ThroughLedgerIndex,
		ThroughAuditIndex:         state.ThroughAuditIndex,
		LedgerHeadHash:            state.LedgerHeadHash,
		AuditHeadHash:             state.AuditHeadHash,
		FounderUnitsNumerator:     strconv.FormatInt(protocol.FounderContributionUnits, 10),
		FounderUnitsDenominator:   "1",
		FounderShareNumerator:     founderShare.Num().String(),
		FounderShareDenominator:   founderShare.Denom().String(),
		MeasuredWeightNumerator:   measuredWeight.Num().String(),
		MeasuredWeightDenominator: measuredWeight.Denom().String(),
		ClaimedWeightNumerator:    claimedWeight.Num().String(),
		ClaimedWeightDenominator:  claimedWeight.Denom().String(),
		CreatedAt:                 state.CreatedAt,
		RegistryScope:             registry.registryScope,
		RegistryKeyID:             registry.signingKey.KeyID(),
	}
	snapshot.SnapshotHash = protocol.Digest(
		protocol.LeaderboardSnapshotHashMessage(snapshot),
	)
	snapshot.Signature = protocol.EncodeSignature(registry.signingKey.Sign(
		protocol.LeaderboardSnapshotMessage(snapshot),
	))
	return snapshot
}

func (registry *Service) leaderboardShare(
	view string,
	claimState string,
	weight int64,
	totals store.LeaderboardTotals,
	snapshot protocol.LeaderboardSnapshotDto,
) *big.Rat {
	founder := new(big.Rat)
	founder.SetString(
		snapshot.FounderShareNumerator + "/" + snapshot.FounderShareDenominator,
	)
	if view == "founder" {
		return founder
	}
	if view != "claimed" ||
		claimState == protocol.OperatorClaimStatePendingReview ||
		totals.ClaimedWeight <= 0 ||
		weight <= 0 {
		return new(big.Rat)
	}
	operatorPool := new(big.Rat).Sub(big.NewRat(1, 1), founder)
	return new(big.Rat).Mul(
		operatorPool,
		big.NewRat(weight, totals.ClaimedWeight),
	)
}

func founderShare(measuredWeight int64) *big.Rat {
	founderScaled := protocol.FounderContributionUnits * operatorWeightMonths
	share := big.NewRat(founderScaled, founderScaled+measuredWeight)
	minimum := big.NewRat(1, 10)
	if share.Cmp(minimum) < 0 {
		return minimum
	}
	return share
}

func validateLeaderboardLimit(limit int) (int, error) {
	if limit == 0 {
		return defaultLeaderboardLimit, nil
	}
	if limit < 1 || limit > maxLeaderboardLimit {
		return 0, requestError(
			"invalid_request",
			"limit must be between 1 and 100",
		)
	}
	return limit, nil
}

func (registry *Service) encodeLeaderboardCursor(
	cursor leaderboardCursor,
) (string, error) {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", fmt.Errorf("encode leaderboard cursor: %w", err)
	}
	signature := registry.signingKey.Sign(leaderboardCursorMessage(payload))
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(signature), nil
}

func (registry *Service) decodeLeaderboardCursor(
	value string,
) (leaderboardCursor, error) {
	if len(value) > 4096 {
		return leaderboardCursor{}, requestError("invalid_cursor", "cursor is malformed")
	}
	payloadText, signatureText, found := strings.Cut(value, ".")
	if !found || strings.Contains(signatureText, ".") {
		return leaderboardCursor{}, requestError("invalid_cursor", "cursor is malformed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadText)
	if err != nil {
		return leaderboardCursor{}, requestError("invalid_cursor", "cursor is malformed")
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil ||
		!protocol.Verify(
			registry.signingKey.PublicKey(),
			leaderboardCursorMessage(payload),
			signature,
		) {
		return leaderboardCursor{}, requestError(
			"invalid_cursor",
			"cursor signature is invalid",
		)
	}
	var cursor leaderboardCursor
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cursor); err != nil ||
		cursor.Version != 1 ||
		cursor.SnapshotID == "" ||
		!periodPattern.MatchString(cursor.FromPeriod) ||
		!periodPattern.MatchString(cursor.ThroughPeriod) ||
		!protocol.IsDigest(cursor.LedgerHeadHash) ||
		!protocol.IsDigest(cursor.AuditHeadHash) ||
		cursor.ThroughLedgerIndex < 0 ||
		cursor.ThroughAuditIndex < 0 ||
		cursor.AfterWeight < 0 ||
		cursor.AfterID == "" {
		return leaderboardCursor{}, requestError("invalid_cursor", "cursor payload is invalid")
	}
	return cursor, nil
}

func leaderboardCursorMessage(payload []byte) []byte {
	message := make([]byte, 0, len(payload)+48)
	message = append(message, []byte("myscoutee-registry-leaderboard-cursor-v1\n")...)
	message = append(message, payload...)
	return message
}

func monthStart(value time.Time) time.Time {
	year, month, _ := value.UTC().Date()
	return time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
}
