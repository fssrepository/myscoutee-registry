package protocol

import "testing"

func TestSettlementCanonicalMessagesCommitValuationAndPrivateQuery(t *testing.T) {
	receipt := SettlementReceipt{
		SettlementID:                           "stl_0123456789abcdef0123456789abcdef",
		Period:                                 "2026-06",
		CurrencyCode:                           "EUR",
		FractionDigits:                         2,
		Revision:                               1,
		RulesetVersion:                         SettlementRulesetVersion,
		ValuationRulesetVersion:                SettlementValuationRulesetVersion,
		CommissionRateBasisPoints:              RevenueCommissionBasisPoints,
		BaseValuationMultiplierBasisPoints:     30_000,
		RecentThreeMonthAverageMinor:           300,
		PriorThreeMonthAverageMinor:            200,
		EarlierThreeMonthAverageMinor:          100,
		RecentGrowthBasisPoints:                5_000,
		PriorGrowthBasisPoints:                 10_000,
		AccelerationBasisPoints:                -5_000,
		ValuationAdjustmentBasisPoints:         0,
		EffectiveValuationMultiplierBasisPoints: 30_000,
		CommissionBasisMinor:                   900,
		NetworkCommissionPoolMinor:             45,
		TTMCommissionBasisMinor:                1_200,
		TTMNetworkCommissionPoolMinor:          60,
		IndicativeNetworkValueMinor:            3_600,
		ValuationIsNonBinding:                  true,
		LedgerHeadHash:                         ZeroHash,
		AuditHeadHash:                          OperatorAuditZeroHash,
		ReviewHeadHash:                         OperatorClaimReviewZeroHash,
		EligibilityHeadHash:                    OperatorClaimEligibilityZeroHash,
		SourceFingerprint:                      Digest([]byte("source")),
		AllocationHash:                         Digest([]byte("allocation")),
		AcceptedAt:                             "2026-07-01T00:00:00Z",
		RegistryScope:                          "example:region-a",
		RegistryKeyID:                          "rkey_0123456789abcdef0123456789abcdef",
	}
	original := Digest(SettlementHashMessage(receipt))
	changed := receipt
	changed.AccelerationBasisPoints++
	if original == Digest(SettlementHashMessage(changed)) {
		t.Fatal("settlement hash did not commit acceleration")
	}
	changed = receipt
	changed.IndicativeNetworkValueMinor++
	if original == Digest(SettlementHashMessage(changed)) {
		t.Fatal("settlement hash did not commit indicative value")
	}

	query := SettlementQueryRequest{
		CurrencyCode:      "EUR",
		FromPeriod:        "2026-01",
		ThroughPeriod:     "2026-06",
		IncludeSuperseded: false,
		Limit:             20,
	}
	queryHash := Digest(SettlementQueryPayload(query))
	query.IncludeSuperseded = true
	if queryHash == Digest(SettlementQueryPayload(query)) {
		t.Fatal("settlement query payload did not commit revision visibility")
	}
}

func TestSettlementMinorAmountSafeBoundary(t *testing.T) {
	if !SettlementMinorAmountIsSafe(SettlementMaximumSafeMinor) {
		t.Fatal("maximum exact JSON settlement amount was rejected")
	}
	if SettlementMinorAmountIsSafe(-1) {
		t.Fatal("negative settlement amount was accepted")
	}
	if SettlementMinorAmountIsSafe(SettlementMaximumSafeMinor + 1) {
		t.Fatal("inexact JSON settlement amount was accepted")
	}
}
