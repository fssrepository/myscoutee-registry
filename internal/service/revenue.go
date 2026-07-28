package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

var (
	revenuePeriodPattern  = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$`)
	revenueBatchIDPattern = regexp.MustCompile(`^revbatch_[0-9a-f]{32}$`)
	currencyCodePattern   = regexp.MustCompile(`^[A-Z]{3}$`)
)

func (registry *Service) SubmitRevenueBatch(
	ctx context.Context,
	request protocol.RevenueBatchRequest,
) (protocol.RevenueBatchResponse, error) {
	if request.ProtocolVersion != protocol.Version {
		return protocol.RevenueBatchResponse{}, requestError(
			"unsupported_protocol",
			"protocol_version must be \"1\"",
		)
	}
	if !protocol.IsRegistryScope(request.RegistryScope) {
		return protocol.RevenueBatchResponse{}, requestError(
			"invalid_request",
			"registry_scope is malformed",
		)
	}
	if !deploymentIDPattern.MatchString(request.DeploymentID) {
		return protocol.RevenueBatchResponse{}, requestError(
			"invalid_request",
			"deployment_id is malformed",
		)
	}
	if err := validateToken("nonce", request.Nonce); err != nil {
		return protocol.RevenueBatchResponse{}, err
	}
	if err := validateToken("idempotency_key", request.IdempotencyKey); err != nil {
		return protocol.RevenueBatchResponse{}, err
	}
	if !protocol.IsDigest(request.PayloadHash) {
		return protocol.RevenueBatchResponse{}, requestError(
			"invalid_request",
			"payload_hash must be a lowercase sha256 digest",
		)
	}
	if _, err := registry.validateTimestamp(request.Timestamp); err != nil {
		return protocol.RevenueBatchResponse{}, err
	}
	deployment, err := registry.store.Deployment(ctx, request.DeploymentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.RevenueBatchResponse{}, requestError(
				"deployment_not_found",
				"deployment is not registered",
			)
		}
		return protocol.RevenueBatchResponse{}, err
	}
	deploymentPublicKey, err := parseStoredPublicKey(deployment.PublicKeyDER)
	if err != nil {
		return protocol.RevenueBatchResponse{}, fmt.Errorf(
			"%w: %v",
			store.ErrInconsistentState,
			err,
		)
	}
	signature, err := protocol.ParseSignature(request.Signature)
	if err != nil {
		return protocol.RevenueBatchResponse{}, requestError(
			"invalid_signature",
			"signature must be canonical padded base64 Ed25519",
		)
	}
	signingMessage := protocol.CanonicalRequest(
		"POST",
		protocol.RevenueBatchPath,
		request.ProtocolVersion,
		request.RegistryScope,
		request.DeploymentID,
		request.Timestamp,
		request.Nonce,
		request.IdempotencyKey,
		request.PayloadHash,
	)
	if !protocol.Verify(deploymentPublicKey, signingMessage, signature) {
		return protocol.RevenueBatchResponse{}, requestError(
			"invalid_signature",
			"revenue batch signature verification failed",
		)
	}
	if request.RegistryScope != registry.registryScope {
		return protocol.RevenueBatchResponse{}, requestError(
			"registry_scope_mismatch",
			"request is addressed to a different sovereign registry scope",
		)
	}
	if err := validateRevenueRequest(request); err != nil {
		return protocol.RevenueBatchResponse{}, err
	}
	expectedPayloadHash := protocol.Digest(protocol.RevenuePayload(
		request.Kind,
		request.Period,
		request.Revision,
		request.SupersedesBatchID,
		request.RulesetVersion,
		request.CommissionRateBasisPoints,
		request.Currencies,
	))
	if request.PayloadHash != expectedPayloadHash {
		return protocol.RevenueBatchResponse{}, requestError(
			"invalid_payload_hash",
			"revenue batch payload_hash does not match the canonical payload",
		)
	}
	if err := registry.VerifyState(ctx); err != nil {
		registry.logger.Error(
			"refusing revenue batch while registry integrity verification fails",
			"error",
			err,
		)
		return protocol.RevenueBatchResponse{}, requestError(
			"registry_integrity_unavailable",
			"registry integrity verification failed; new ledger writes are temporarily unavailable",
		)
	}

	batchID, err := registry.newID("revbatch_")
	if err != nil {
		return protocol.RevenueBatchResponse{}, fmt.Errorf(
			"generate revenue batch ID: %w",
			err,
		)
	}
	acceptedAtTime := registry.canonicalNow()
	input := store.RevenueBatchInput{
		RegistryScope:             registry.registryScope,
		Signer:                    request.DeploymentID,
		Nonce:                     request.Nonce,
		IdempotencyKey:            request.IdempotencyKey,
		PayloadHash:               request.PayloadHash,
		RequestHash:               protocol.Digest(signingMessage),
		DeploymentID:              request.DeploymentID,
		RequestTimestamp:          request.Timestamp,
		DeploymentSignature:       signature,
		CandidateBatchID:          batchID,
		Kind:                      request.Kind,
		Period:                    request.Period,
		Revision:                  request.Revision,
		SupersedesBatchID:         request.SupersedesBatchID,
		RulesetVersion:            request.RulesetVersion,
		CommissionRateBasisPoints: request.CommissionRateBasisPoints,
		Currencies:                request.Currencies,
		AcceptedAt:                acceptedAtTime.Format(time.RFC3339),
		CheckpointDate:            acceptedAtTime.Format("2006-01-02"),
	}
	record, duplicate, err := registry.store.AcceptRevenueBatch(
		ctx,
		input,
		func(
			entry protocol.LedgerEntry,
			storedInput store.RevenueBatchInput,
			currencyCount int64,
			checkpointDate string,
		) ([]byte, error) {
			return registry.signingKey.Sign(protocol.RevenueReceiptMessage(
				protocol.Version,
				registry.registryScope,
				entry.BatchID,
				entry.DeploymentID,
				entry.LedgerIndex,
				entry.EntryHash,
				entry.PreviousEntryHash,
				entry.BatchHash,
				storedInput.Kind,
				storedInput.Period,
				storedInput.Revision,
				storedInput.SupersedesBatchID,
				storedInput.RulesetVersion,
				storedInput.CommissionRateBasisPoints,
				currencyCount,
				entry.AcceptedAt,
				checkpointDate,
				registry.signingKey.KeyID(),
			)), nil
		},
	)
	if err != nil {
		return protocol.RevenueBatchResponse{}, mapRevenueStoreError(err)
	}
	return registry.revenueBatchResponse(record, duplicate), nil
}

func validateRevenueRequest(request protocol.RevenueBatchRequest) error {
	if request.Kind != protocol.RevenueKind {
		return requestError(
			"invalid_revenue_batch",
			"kind must be daily-revenue",
		)
	}
	if _, err := time.Parse("2006-01-02", request.Period); err != nil ||
		!revenuePeriodPattern.MatchString(request.Period) {
		return requestError(
			"invalid_revenue_batch",
			"period must be a valid UTC calendar date in YYYY-MM-DD form",
		)
	}
	if request.Revision < 1 {
		return requestError(
			"invalid_revenue_batch",
			"revision must be at least 1",
		)
	}
	if request.Revision == 1 && request.SupersedesBatchID != "" {
		return requestError(
			"invalid_revenue_batch",
			"supersedes_batch_id must be empty for revision 1",
		)
	}
	if request.Revision > 1 &&
		!revenueBatchIDPattern.MatchString(request.SupersedesBatchID) {
		return requestError(
			"invalid_revenue_batch",
			"supersedes_batch_id must identify the active prior revenue batch",
		)
	}
	if request.RulesetVersion != protocol.RevenueRulesetVersion {
		return requestError(
			"invalid_revenue_batch",
			"ruleset_version must be net-captured-revenue-v1",
		)
	}
	if request.CommissionRateBasisPoints != protocol.RevenueCommissionBasisPoints {
		return requestError(
			"invalid_revenue_batch",
			"commission_rate_basis_points must be 500",
		)
	}
	if len(request.Currencies) > protocol.MaximumRevenueCurrencyRows {
		return requestError(
			"invalid_revenue_batch",
			"currencies must contain at most 32 aggregate rows",
		)
	}
	previousCode := ""
	for _, currency := range request.Currencies {
		expectedFractionDigits, supportedCurrency := protocol.ISO4217FractionDigits(
			currency.CurrencyCode,
		)
		if !currencyCodePattern.MatchString(currency.CurrencyCode) ||
			!supportedCurrency {
			return requestError(
				"invalid_revenue_batch",
				"currency_code must be a supported uppercase ISO-4217 settlement currency",
			)
		}
		if currency.CurrencyCode <= previousCode {
			return requestError(
				"invalid_revenue_batch",
				"currencies must be strictly sorted and unique by currency_code",
			)
		}
		previousCode = currency.CurrencyCode
		if currency.FractionDigits != expectedFractionDigits {
			return requestError(
				"invalid_revenue_batch",
				"fraction_digits does not match the ISO-4217 currency exponent",
			)
		}
		if currency.CapturedMinor < 0 ||
			currency.CapturedMinor > protocol.MaximumRevenueMinor ||
			currency.RefundedMinor < 0 ||
			currency.RefundedMinor > protocol.MaximumRevenueMinor ||
			currency.RefundedMinor > currency.CapturedMinor ||
			currency.NetMinor != currency.CapturedMinor-currency.RefundedMinor ||
			currency.NetMinor > protocol.MaximumRevenueMinor ||
			currency.CommissionBasisMinor != currency.NetMinor ||
			currency.CommissionBasisMinor > protocol.MaximumRevenueMinor ||
			currency.EstimatedCommissionMinor != revenueCommission(
				currency.CommissionBasisMinor,
			) ||
			currency.EstimatedCommissionMinor > protocol.MaximumRevenueMinor ||
			currency.PaymentCount < 0 ||
			currency.PaymentCount > protocol.MaximumRevenuePaymentCount {
			return requestError(
				"invalid_revenue_batch",
				"currency aggregate does not satisfy net-captured-revenue-v1",
			)
		}
	}
	return nil
}

func revenueCommission(netMinor int64) int64 {
	return protocol.RevenueCommissionMinor(netMinor)
}

func (registry *Service) RevenueReceipt(
	ctx context.Context,
	batchID string,
) (protocol.RevenueBatchResponse, error) {
	if !revenueBatchIDPattern.MatchString(batchID) {
		return protocol.RevenueBatchResponse{}, requestError(
			"invalid_request",
			"revenue batch_id is malformed",
		)
	}
	record, err := registry.store.RevenueBatchReceipt(ctx, batchID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.RevenueBatchResponse{}, requestError(
				"revenue_receipt_not_found",
				"revenue batch receipt was not found",
			)
		}
		return protocol.RevenueBatchResponse{}, err
	}
	return registry.revenueBatchResponse(record, true), nil
}

func (registry *Service) RevenueSummary(
	ctx context.Context,
	period string,
	currencyCode string,
	deploymentID string,
) (protocol.RevenueSummary, error) {
	if _, err := time.Parse("2006-01-02", period); err != nil ||
		!revenuePeriodPattern.MatchString(period) {
		return protocol.RevenueSummary{}, requestError(
			"invalid_request",
			"period must be a valid UTC calendar date in YYYY-MM-DD form",
		)
	}
	fractionDigits, supportedCurrency := protocol.ISO4217FractionDigits(
		currencyCode,
	)
	if !currencyCodePattern.MatchString(currencyCode) || !supportedCurrency {
		return protocol.RevenueSummary{}, requestError(
			"invalid_request",
			"currency must be one supported uppercase ISO-4217 settlement code",
		)
	}
	if deploymentID != "" && !deploymentIDPattern.MatchString(deploymentID) {
		return protocol.RevenueSummary{}, requestError(
			"invalid_request",
			"deployment_id is malformed",
		)
	}
	if err := registry.VerifyState(ctx); err != nil {
		return protocol.RevenueSummary{}, requestError(
			"registry_integrity_unavailable",
			"registry integrity verification failed; revenue query is temporarily unavailable",
		)
	}
	return registry.store.RevenueSummary(ctx, store.RevenueQuery{
		Period:       period,
		CurrencyCode: currencyCode,
		FractionDigits: fractionDigits,
		DeploymentID: deploymentID,
	})
}

func (registry *Service) revenueBatchResponse(
	record store.RevenueBatchRecord,
	duplicate bool,
) protocol.RevenueBatchResponse {
	entry := record.LedgerEntry
	return protocol.RevenueBatchResponse{
		ProtocolVersion: protocol.Version,
		RegistryScope:   registry.registryScope,
		BatchID:         record.BatchID,
		DeploymentID:    record.DeploymentID,
		IdempotencyKey:  record.IdempotencyKey,
		Duplicate:       duplicate,
		Receipt: protocol.RevenueReceipt{
			LedgerIndex:               entry.LedgerIndex,
			EntryHash:                 entry.EntryHash,
			PreviousEntryHash:         entry.PreviousEntryHash,
			BatchHash:                 entry.BatchHash,
			Kind:                      record.Kind,
			Period:                    record.Period,
			Revision:                  record.Revision,
			SupersedesBatchID:         record.SupersedesBatchID,
			RulesetVersion:            record.RulesetVersion,
			CommissionRateBasisPoints: record.CommissionRateBasisPoints,
			CurrencyCount:             record.CurrencyCount,
			AcceptedAt:                record.AcceptedAt,
			CheckpointDate:            record.AcceptedAt[:len("2006-01-02")],
			RegistryScope:             registry.registryScope,
			RegistryKeyID:             registry.signingKey.KeyID(),
			RegistryPublicKey:         registry.signingKey.EncodedPublicKey(),
			Signature: protocol.EncodeSignature(
				record.ReceiptSignature,
			),
		},
	}
}

func mapRevenueStoreError(err error) error {
	if errors.Is(err, store.ErrRevenueRevisionConflict) {
		return requestError(
			"revenue_revision_conflict",
			"revision must increment and supersede the current active batch for this deployment and UTC day",
		)
	}
	if errors.Is(err, store.ErrRevenueAggregateOverflow) {
		return requestError(
			"revenue_aggregate_overflow",
			"the active per-day currency aggregate would exceed the supported signed integer range",
		)
	}
	return mapStoreError(err)
}
