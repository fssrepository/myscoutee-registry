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

var settlementIDPattern = regexp.MustCompile(`^stl_[0-9a-f]{32}$`)

func (registry *Service) CalculateSettlement(
	ctx context.Context,
	period string,
	currencyCode string,
) (protocol.SettlementCalculationResult, error) {
	fractionDigits, err := registry.validateSettlementPeriodCurrency(
		period,
		currencyCode,
	)
	if err != nil {
		return protocol.SettlementCalculationResult{}, err
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.SettlementCalculationResult{}, requestError(
			"registry_integrity_unavailable",
			"registry integrity verification failed; settlement calculation is temporarily unavailable",
		)
	}
	settlementID, err := registry.newID("stl_")
	if err != nil {
		return protocol.SettlementCalculationResult{}, fmt.Errorf(
			"generate settlement ID: %w",
			err,
		)
	}
	record, duplicate, err := registry.store.CalculateSettlement(
		ctx,
		store.SettlementCalculationInput{
			RegistryScope:                      registry.registryScope,
			Period:                             period,
			CurrencyCode:                       currencyCode,
			FractionDigits:                     fractionDigits,
			BaseValuationMultiplierBasisPoints: registry.valuationMultiplierBasisPoints,
			CandidateSettlementID:              settlementID,
			AcceptedAt: registry.canonicalNow().
				Format(time.RFC3339),
			RegistryKeyID: registry.signingKey.KeyID(),
		},
		func(record store.SettlementRecord) ([]byte, error) {
			receipt := registry.settlementReceipt(record)
			return registry.signingKey.Sign(
				protocol.SettlementReceiptMessage(receipt),
			), nil
		},
	)
	if err != nil {
		return protocol.SettlementCalculationResult{}, mapSettlementStoreError(err)
	}
	return protocol.SettlementCalculationResult{
		Duplicate: duplicate,
		Receipt:   registry.settlementReceipt(record),
	}, nil
}

func (registry *Service) SettlementHistoryForAdmin(
	ctx context.Context,
	query store.SettlementHistoryQuery,
) (store.SettlementHistoryPage, error) {
	if query.DeploymentID != "" &&
		!deploymentIDPattern.MatchString(query.DeploymentID) {
		return store.SettlementHistoryPage{}, requestError(
			"invalid_request",
			"deployment_id is malformed",
		)
	}
	if err := registry.validateSettlementHistoryQuery(&query); err != nil {
		return store.SettlementHistoryPage{}, err
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return store.SettlementHistoryPage{}, requestError(
			"registry_integrity_unavailable",
			"registry integrity verification failed; settlement history is temporarily unavailable",
		)
	}
	return registry.store.SettlementHistory(ctx, query)
}

func (registry *Service) SettlementHistoryForDeployment(
	ctx context.Context,
	request protocol.SettlementQueryRequest,
) (protocol.SettlementQueryResponse, error) {
	if request.ProtocolVersion != protocol.Version {
		return protocol.SettlementQueryResponse{}, requestError(
			"unsupported_protocol",
			"protocol_version must be \"1\"",
		)
	}
	if request.RegistryScope != registry.registryScope {
		return protocol.SettlementQueryResponse{}, requestError(
			"registry_scope_mismatch",
			"request is addressed to a different sovereign registry scope",
		)
	}
	if !deploymentIDPattern.MatchString(request.DeploymentID) {
		return protocol.SettlementQueryResponse{}, requestError(
			"invalid_request",
			"deployment_id is malformed",
		)
	}
	if err := validateToken("nonce", request.Nonce); err != nil {
		return protocol.SettlementQueryResponse{}, err
	}
	if err := validateToken("query_id", request.QueryID); err != nil {
		return protocol.SettlementQueryResponse{}, err
	}
	if _, err := registry.validateTimestamp(request.Timestamp); err != nil {
		return protocol.SettlementQueryResponse{}, err
	}
	if !protocol.IsDigest(request.PayloadHash) {
		return protocol.SettlementQueryResponse{}, requestError(
			"invalid_request",
			"payload_hash must be a lowercase sha256 digest",
		)
	}
	query := store.SettlementHistoryQuery{
		DeploymentID:      request.DeploymentID,
		CurrencyCode:      request.CurrencyCode,
		FromPeriod:        request.FromPeriod,
		ThroughPeriod:     request.ThroughPeriod,
		IncludeSuperseded: request.IncludeSuperseded,
		Limit:             request.Limit,
		AfterPeriod:       request.AfterPeriod,
		AfterSettlementID: request.AfterSettlementID,
	}
	if err := registry.validateSettlementHistoryQuery(&query); err != nil {
		return protocol.SettlementQueryResponse{}, err
	}
	expectedPayloadHash := protocol.Digest(
		protocol.SettlementQueryPayload(request),
	)
	if request.PayloadHash != expectedPayloadHash {
		return protocol.SettlementQueryResponse{}, requestError(
			"invalid_payload_hash",
			"settlement query payload_hash does not match the canonical payload",
		)
	}
	deployment, err := registry.store.Deployment(ctx, request.DeploymentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.SettlementQueryResponse{}, requestError(
				"deployment_not_found",
				"deployment is not registered",
			)
		}
		return protocol.SettlementQueryResponse{}, err
	}
	publicKey, err := parseStoredPublicKey(deployment.PublicKeyDER)
	if err != nil {
		return protocol.SettlementQueryResponse{}, fmt.Errorf(
			"%w: invalid deployment public key: %v",
			store.ErrInconsistentState,
			err,
		)
	}
	signature, err := protocol.ParseSignature(request.Signature)
	if err != nil {
		return protocol.SettlementQueryResponse{}, requestError(
			"invalid_signature",
			"signature must be canonical padded base64 Ed25519",
		)
	}
	requestMessage := protocol.CanonicalRequest(
		"POST",
		protocol.SettlementQueryPath,
		request.ProtocolVersion,
		request.RegistryScope,
		request.DeploymentID,
		request.Timestamp,
		request.Nonce,
		request.QueryID,
		request.PayloadHash,
	)
	if !protocol.Verify(publicKey, requestMessage, signature) {
		return protocol.SettlementQueryResponse{}, requestError(
			"invalid_signature",
			"settlement query signature verification failed",
		)
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.SettlementQueryResponse{}, requestError(
			"registry_integrity_unavailable",
			"registry integrity verification failed; settlement history is temporarily unavailable",
		)
	}
	page, err := registry.store.SettlementHistory(ctx, query)
	if err != nil {
		return protocol.SettlementQueryResponse{}, err
	}
	response := protocol.SettlementQueryResponse{
		ProtocolVersion:       protocol.Version,
		RegistryScope:         registry.registryScope,
		DeploymentID:          request.DeploymentID,
		QueryID:               request.QueryID,
		QueryHash:             protocol.Digest(requestMessage),
		Items:                 page.Items,
		NextAfterPeriod:       page.NextAfterPeriod,
		NextAfterSettlementID: page.NextAfterSettlementID,
		GeneratedAt: registry.canonicalNow().
			Format(time.RFC3339),
		RegistryKeyID:     registry.signingKey.KeyID(),
		RegistryPublicKey: registry.signingKey.EncodedPublicKey(),
	}
	response.ItemsHash = protocol.SettlementHistoryItemsHash(response.Items)
	response.Signature = protocol.EncodeSignature(registry.signingKey.Sign(
		protocol.SettlementQueryResponseMessage(response),
	))
	return response, nil
}

func (registry *Service) validateSettlementPeriodCurrency(
	period string,
	currencyCode string,
) (int64, error) {
	parsed, err := time.Parse("2006-01", period)
	now := registry.canonicalNow()
	latestComplete := time.Date(
		now.Year(),
		now.Month(),
		1,
		0,
		0,
		0,
		0,
		time.UTC,
	).AddDate(0, -1, 0)
	if err != nil || parsed.Format("2006-01") != period ||
		parsed.After(latestComplete) {
		return 0, requestError(
			"invalid_request",
			"period must be a completed UTC month in YYYY-MM form",
		)
	}
	fractionDigits, supported := protocol.ISO4217FractionDigits(currencyCode)
	if !supported || !currencyCodePattern.MatchString(currencyCode) {
		return 0, requestError(
			"invalid_request",
			"currency must be a supported uppercase ISO-4217 settlement code",
		)
	}
	return fractionDigits, nil
}

func (registry *Service) validateSettlementHistoryQuery(
	query *store.SettlementHistoryQuery,
) error {
	for _, item := range []struct {
		name  string
		value string
	}{
		{"period", query.Period},
		{"from_period", query.FromPeriod},
		{"through_period", query.ThroughPeriod},
		{"after_period", query.AfterPeriod},
	} {
		if item.value == "" {
			continue
		}
		parsed, err := time.Parse("2006-01", item.value)
		if err != nil || parsed.Format("2006-01") != item.value {
			return requestError(
				"invalid_request",
				item.name+" must be YYYY-MM",
			)
		}
	}
	if query.CurrencyCode != "" {
		if _, supported := protocol.ISO4217FractionDigits(
			query.CurrencyCode,
		); !supported || !currencyCodePattern.MatchString(query.CurrencyCode) {
			return requestError(
				"invalid_request",
				"currency_code must be a supported uppercase ISO-4217 settlement currency",
			)
		}
	}
	if query.FromPeriod != "" && query.ThroughPeriod != "" &&
		query.FromPeriod > query.ThroughPeriod {
		return requestError(
			"invalid_request",
			"from_period must not be after through_period",
		)
	}
	if query.Limit == 0 {
		query.Limit = 20
	}
	if query.Limit < 1 || query.Limit > protocol.SettlementMaximumQueryLimit {
		return requestError(
			"invalid_request",
			"limit must be between 1 and 100",
		)
	}
	if (query.AfterPeriod == "") != (query.AfterSettlementID == "") ||
		(query.AfterSettlementID != "" &&
			!settlementIDPattern.MatchString(query.AfterSettlementID)) {
		return requestError(
			"invalid_request",
			"after_period and after_settlement_id must be supplied together and be canonical",
		)
	}
	return nil
}

func (registry *Service) settlementReceipt(
	record store.SettlementRecord,
) protocol.SettlementReceipt {
	entry := record.LedgerEntry
	receipt := protocol.SettlementReceipt{
		SettlementID:                       record.SettlementID,
		Period:                             record.Period,
		CurrencyCode:                       record.CurrencyCode,
		FractionDigits:                     record.FractionDigits,
		Revision:                           record.Revision,
		SupersedesSettlementID:             record.SupersedesSettlementID,
		RulesetVersion:                     record.RulesetVersion,
		ValuationRulesetVersion:            record.ValuationRulesetVersion,
		CommissionRateBasisPoints:          record.CommissionRateBasisPoints,
		BaseValuationMultiplierBasisPoints: record.BaseValuationMultiplierBasisPoints,
		RecentThreeMonthAverageMinor:       record.RecentThreeMonthAverageMinor,
		PriorThreeMonthAverageMinor:        record.PriorThreeMonthAverageMinor,
		EarlierThreeMonthAverageMinor:      record.EarlierThreeMonthAverageMinor,
		RecentGrowthBasisPoints:            record.RecentGrowthBasisPoints,
		PriorGrowthBasisPoints:             record.PriorGrowthBasisPoints,
		AccelerationBasisPoints:            record.AccelerationBasisPoints,
		ValuationAdjustmentBasisPoints:     record.ValuationAdjustmentBasisPoints,
		EffectiveValuationMultiplierBasisPoints: record.EffectiveValuationMultiplierBasisPoints,
		CommissionBasisMinor:               record.CommissionBasisMinor,
		NetworkCommissionPoolMinor:         record.NetworkCommissionPoolMinor,
		TTMCommissionBasisMinor:            record.TTMCommissionBasisMinor,
		TTMNetworkCommissionPoolMinor:      record.TTMNetworkCommissionPoolMinor,
		IndicativeNetworkValueMinor:        record.IndicativeNetworkValueMinor,
		ValuationIsNonBinding:              true,
		ThroughLedgerIndex:                 record.ThroughLedgerIndex,
		ThroughAuditIndex:                  record.ThroughAuditIndex,
		ThroughReviewIndex:                 record.ThroughReviewIndex,
		ThroughEligibilityIndex:            record.ThroughEligibilityIndex,
		LedgerHeadHash:                     record.LedgerHeadHash,
		AuditHeadHash:                      record.AuditHeadHash,
		ReviewHeadHash:                     record.ReviewHeadHash,
		EligibilityHeadHash:                record.EligibilityHeadHash,
		SourceFingerprint:                  record.SourceFingerprint,
		AllocationHash:                     record.AllocationHash,
		SettlementHash:                     record.SettlementHash,
		LedgerIndex:                        entry.LedgerIndex,
		EntryHash:                          entry.EntryHash,
		PreviousEntryHash:                  entry.PreviousEntryHash,
		AcceptedAt:                         record.AcceptedAt,
		RegistryScope:                      registry.registryScope,
		RegistryKeyID:                      record.RegistryKeyID,
		Allocations: append(
			[]protocol.SettlementAllocation(nil),
			record.Allocations...,
		),
	}
	receipt.RegistryPublicKey = registry.signingKey.EncodedPublicKey()
	receipt.Signature = protocol.EncodeSignature(record.ReceiptSignature)
	return receipt
}

func mapSettlementStoreError(err error) error {
	if errors.Is(err, store.ErrRevenueAggregateOverflow) {
		return requestError(
			"settlement_aggregate_overflow",
			"settlement revenue, allocation, or valuation exceeds the protocol safe-integer range",
		)
	}
	return mapStoreError(err)
}
