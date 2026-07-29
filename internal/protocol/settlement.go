package protocol

import "strconv"

const (
	SettlementQueryPath = "/v1/settlements/query"

	SettlementKind           = "monthly-settlement"
	SettlementRulesetVersion = "share-weighted-settlement-v1"
	SettlementValuationRulesetVersion = "three-month-acceleration-valuation-v1"
	SettlementEntryType      = "SETTLEMENT_CALCULATED"

	SettlementDefaultValuationMultiplierBasisPoints = int64(30_000)
	SettlementMinimumBaseValuationMultiplierBasisPoints = int64(1_000)
	SettlementMaximumBaseValuationMultiplierBasisPoints = int64(100_000)
	SettlementMinimumGrowthBasisPoints               = int64(-10_000)
	SettlementMaximumGrowthBasisPoints               = int64(20_000)
	SettlementMinimumAccelerationBasisPoints         = int64(-10_000)
	SettlementMaximumAccelerationBasisPoints         = int64(10_000)
	SettlementAccelerationAdjustmentDivisor          = int64(4)
	SettlementMinimumValuationAdjustmentBasisPoints  = int64(-2_500)
	SettlementMaximumValuationAdjustmentBasisPoints  = int64(2_500)
	SettlementMaximumQueryLimit                      = 100
	// SettlementMaximumSafeMinor is the largest integer minor-unit amount
	// that every supported JSON consumer, including JavaScript, can represent
	// exactly without changing the v1 numeric wire format.
	SettlementMaximumSafeMinor = int64(9_007_199_254_740_991)

	SettlementBeneficiaryFounder   = "FOUNDER"
	SettlementBeneficiaryOperator  = "OPERATOR_GROUP"
	SettlementBeneficiaryReserve   = "UNALLOCATED_RESERVE"
	SettlementFounderBeneficiaryID = "founder"
	SettlementReserveBeneficiaryID = "unallocated-reserve"
)

func SettlementMinorAmountIsSafe(value int64) bool {
	return value >= 0 && value <= SettlementMaximumSafeMinor
}

type SettlementAllocation struct {
	BeneficiaryType                 string `json:"beneficiary_type"`
	BeneficiaryID                   string `json:"beneficiary_id"`
	Label                           string `json:"label"`
	ShareNumerator                  string `json:"share_numerator"`
	ShareDenominator                string `json:"share_denominator"`
	NetworkPoolAllocationMinor      int64  `json:"network_pool_allocation_minor"`
	IndicativeValueAllocationMinor  int64  `json:"indicative_value_allocation_minor"`
}

type SettlementReceipt struct {
	SettlementID                       string                 `json:"settlement_id"`
	Period                             string                 `json:"period"`
	CurrencyCode                       string                 `json:"currency_code"`
	FractionDigits                     int64                  `json:"fraction_digits"`
	Revision                           int64                  `json:"revision"`
	SupersedesSettlementID             string                 `json:"supersedes_settlement_id,omitempty"`
	RulesetVersion                     string                 `json:"ruleset_version"`
	ValuationRulesetVersion            string                 `json:"valuation_ruleset_version"`
	CommissionRateBasisPoints          int64                  `json:"commission_rate_basis_points"`
	BaseValuationMultiplierBasisPoints int64                  `json:"base_valuation_multiplier_basis_points"`
	RecentThreeMonthAverageMinor       int64                  `json:"recent_three_month_average_minor"`
	PriorThreeMonthAverageMinor        int64                  `json:"prior_three_month_average_minor"`
	EarlierThreeMonthAverageMinor      int64                  `json:"earlier_three_month_average_minor"`
	RecentGrowthBasisPoints            int64                  `json:"recent_growth_basis_points"`
	PriorGrowthBasisPoints             int64                  `json:"prior_growth_basis_points"`
	AccelerationBasisPoints            int64                  `json:"acceleration_basis_points"`
	ValuationAdjustmentBasisPoints     int64                  `json:"valuation_adjustment_basis_points"`
	EffectiveValuationMultiplierBasisPoints int64             `json:"effective_valuation_multiplier_basis_points"`
	CommissionBasisMinor               int64                  `json:"commission_basis_minor"`
	NetworkCommissionPoolMinor         int64                  `json:"network_commission_pool_minor"`
	TTMCommissionBasisMinor            int64                  `json:"ttm_commission_basis_minor"`
	TTMNetworkCommissionPoolMinor      int64                  `json:"ttm_network_commission_pool_minor"`
	IndicativeNetworkValueMinor        int64                  `json:"indicative_network_value_minor"`
	ValuationIsNonBinding              bool                   `json:"valuation_is_non_binding"`
	ThroughLedgerIndex                 int64                  `json:"through_ledger_index"`
	ThroughAuditIndex                  int64                  `json:"through_audit_index"`
	ThroughReviewIndex                 int64                  `json:"through_review_index"`
	ThroughEligibilityIndex            int64                  `json:"through_eligibility_index"`
	LedgerHeadHash                     string                 `json:"ledger_head_hash"`
	AuditHeadHash                      string                 `json:"audit_head_hash"`
	ReviewHeadHash                     string                 `json:"review_head_hash"`
	EligibilityHeadHash                string                 `json:"eligibility_head_hash"`
	SourceFingerprint                  string                 `json:"source_fingerprint"`
	AllocationHash                     string                 `json:"allocation_hash"`
	SettlementHash                     string                 `json:"settlement_hash"`
	LedgerIndex                        int64                  `json:"ledger_index"`
	EntryHash                          string                 `json:"entry_hash"`
	PreviousEntryHash                  string                 `json:"previous_entry_hash"`
	AcceptedAt                         string                 `json:"accepted_at"`
	RegistryScope                      string                 `json:"registry_scope"`
	RegistryKeyID                      string                 `json:"registry_key_id"`
	RegistryPublicKey                  string                 `json:"registry_public_key"`
	Allocations                        []SettlementAllocation `json:"allocations"`
	Signature                          string                 `json:"signature"`
}

type SettlementCalculationResult struct {
	Duplicate bool              `json:"duplicate"`
	Receipt   SettlementReceipt `json:"receipt"`
}

type SettlementQueryRequest struct {
	ProtocolVersion   string `json:"protocol_version"`
	RegistryScope     string `json:"registry_scope"`
	DeploymentID      string `json:"deployment_id"`
	Timestamp         string `json:"timestamp"`
	Nonce             string `json:"nonce"`
	QueryID           string `json:"query_id"`
	CurrencyCode      string `json:"currency_code,omitempty"`
	FromPeriod        string `json:"from_period,omitempty"`
	ThroughPeriod     string `json:"through_period,omitempty"`
	IncludeSuperseded bool   `json:"include_superseded,omitempty"`
	Limit             int    `json:"limit,omitempty"`
	AfterPeriod       string `json:"after_period,omitempty"`
	AfterSettlementID string `json:"after_settlement_id,omitempty"`
	PayloadHash       string `json:"payload_hash"`
	Signature         string `json:"signature"`
}

type SettlementHistoryItem struct {
	SettlementID                      string `json:"settlement_id"`
	Period                            string `json:"period"`
	CurrencyCode                      string `json:"currency_code"`
	FractionDigits                    int64  `json:"fraction_digits"`
	Revision                          int64  `json:"revision"`
	SupersedesSettlementID            string `json:"supersedes_settlement_id,omitempty"`
	BeneficiaryType                   string `json:"beneficiary_type"`
	BeneficiaryID                     string `json:"beneficiary_id"`
	ShareNumerator                    string `json:"share_numerator"`
	ShareDenominator                  string `json:"share_denominator"`
	NetworkPoolMinor                  int64  `json:"network_pool_minor"`
	NetworkPoolAllocationMinor        int64  `json:"network_pool_allocation_minor"`
	TTMCommissionBasisMinor           int64  `json:"ttm_commission_basis_minor"`
	TTMNetworkCommissionPoolMinor     int64  `json:"ttm_network_commission_pool_minor"`
	IndicativeNetworkValueMinor       int64  `json:"indicative_network_value_minor"`
	IndicativeValueAllocationMinor    int64  `json:"indicative_value_allocation_minor"`
	ValuationRulesetVersion           string `json:"valuation_ruleset_version"`
	BaseValuationMultiplierBasisPoints int64 `json:"base_valuation_multiplier_basis_points"`
	RecentThreeMonthAverageMinor      int64  `json:"recent_three_month_average_minor"`
	PriorThreeMonthAverageMinor       int64  `json:"prior_three_month_average_minor"`
	EarlierThreeMonthAverageMinor     int64  `json:"earlier_three_month_average_minor"`
	RecentGrowthBasisPoints           int64  `json:"recent_growth_basis_points"`
	PriorGrowthBasisPoints            int64  `json:"prior_growth_basis_points"`
	AccelerationBasisPoints           int64  `json:"acceleration_basis_points"`
	ValuationAdjustmentBasisPoints    int64  `json:"valuation_adjustment_basis_points"`
	EffectiveValuationMultiplierBasisPoints int64 `json:"effective_valuation_multiplier_basis_points"`
	ValuationIsNonBinding             bool   `json:"valuation_is_non_binding"`
	ThroughLedgerIndex                int64  `json:"through_ledger_index"`
	ThroughAuditIndex                 int64  `json:"through_audit_index"`
	ThroughReviewIndex                int64  `json:"through_review_index"`
	ThroughEligibilityIndex           int64  `json:"through_eligibility_index"`
	SourceFingerprint                 string `json:"source_fingerprint"`
	SettlementHash                    string `json:"settlement_hash"`
	AcceptedAt                        string `json:"accepted_at"`
}

type SettlementQueryResponse struct {
	ProtocolVersion      string                  `json:"protocol_version"`
	RegistryScope        string                  `json:"registry_scope"`
	DeploymentID         string                  `json:"deployment_id"`
	QueryID              string                  `json:"query_id"`
	QueryHash            string                  `json:"query_hash"`
	ItemsHash            string                  `json:"items_hash"`
	Items                []SettlementHistoryItem `json:"items"`
	NextAfterPeriod      string                  `json:"next_after_period,omitempty"`
	NextAfterSettlementID string                 `json:"next_after_settlement_id,omitempty"`
	GeneratedAt          string                  `json:"generated_at"`
	RegistryKeyID        string                  `json:"registry_key_id"`
	RegistryPublicKey    string                  `json:"registry_public_key"`
	Signature            string                  `json:"signature"`
}

func SettlementAllocationHash(allocations []SettlementAllocation) string {
	lines := []string{
		"myscoutee-registry-settlement-allocations-v1",
		strconv.Itoa(len(allocations)),
	}
	for _, allocation := range allocations {
		lines = append(
			lines,
			allocation.BeneficiaryType,
			allocation.BeneficiaryID,
			allocation.Label,
			allocation.ShareNumerator,
			allocation.ShareDenominator,
			strconv.FormatInt(allocation.NetworkPoolAllocationMinor, 10),
			strconv.FormatInt(allocation.IndicativeValueAllocationMinor, 10),
		)
	}
	return Digest(canonical(lines...))
}

func SettlementHashMessage(receipt SettlementReceipt) []byte {
	return canonical(
		"myscoutee-registry-settlement-hash-v1",
		receipt.SettlementID,
		receipt.Period,
		receipt.CurrencyCode,
		strconv.FormatInt(receipt.FractionDigits, 10),
		strconv.FormatInt(receipt.Revision, 10),
		receipt.SupersedesSettlementID,
		receipt.RulesetVersion,
		receipt.ValuationRulesetVersion,
		strconv.FormatInt(receipt.CommissionRateBasisPoints, 10),
		strconv.FormatInt(receipt.BaseValuationMultiplierBasisPoints, 10),
		strconv.FormatInt(receipt.RecentThreeMonthAverageMinor, 10),
		strconv.FormatInt(receipt.PriorThreeMonthAverageMinor, 10),
		strconv.FormatInt(receipt.EarlierThreeMonthAverageMinor, 10),
		strconv.FormatInt(receipt.RecentGrowthBasisPoints, 10),
		strconv.FormatInt(receipt.PriorGrowthBasisPoints, 10),
		strconv.FormatInt(receipt.AccelerationBasisPoints, 10),
		strconv.FormatInt(receipt.ValuationAdjustmentBasisPoints, 10),
		strconv.FormatInt(receipt.EffectiveValuationMultiplierBasisPoints, 10),
		strconv.FormatInt(receipt.CommissionBasisMinor, 10),
		strconv.FormatInt(receipt.NetworkCommissionPoolMinor, 10),
		strconv.FormatInt(receipt.TTMCommissionBasisMinor, 10),
		strconv.FormatInt(receipt.TTMNetworkCommissionPoolMinor, 10),
		strconv.FormatInt(receipt.IndicativeNetworkValueMinor, 10),
		strconv.FormatBool(receipt.ValuationIsNonBinding),
		strconv.FormatInt(receipt.ThroughLedgerIndex, 10),
		strconv.FormatInt(receipt.ThroughAuditIndex, 10),
		strconv.FormatInt(receipt.ThroughReviewIndex, 10),
		strconv.FormatInt(receipt.ThroughEligibilityIndex, 10),
		receipt.LedgerHeadHash,
		receipt.AuditHeadHash,
		receipt.ReviewHeadHash,
		receipt.EligibilityHeadHash,
		receipt.SourceFingerprint,
		receipt.AllocationHash,
		receipt.AcceptedAt,
		receipt.RegistryScope,
		receipt.RegistryKeyID,
	)
}

func SettlementReceiptMessage(receipt SettlementReceipt) []byte {
	return canonical(
		"myscoutee-registry-settlement-receipt-v1",
		receipt.SettlementHash,
		strconv.FormatInt(receipt.LedgerIndex, 10),
		receipt.EntryHash,
		receipt.PreviousEntryHash,
		receipt.RegistryScope,
		receipt.RegistryKeyID,
	)
}

func SettlementQueryPayload(request SettlementQueryRequest) []byte {
	return canonical(
		"myscoutee-registry-settlement-query-payload-v1",
		request.CurrencyCode,
		request.FromPeriod,
		request.ThroughPeriod,
		strconv.FormatBool(request.IncludeSuperseded),
		strconv.Itoa(request.Limit),
		request.AfterPeriod,
		request.AfterSettlementID,
	)
}

func SettlementHistoryItemsHash(items []SettlementHistoryItem) string {
	lines := []string{
		"myscoutee-registry-settlement-history-items-v1",
		strconv.Itoa(len(items)),
	}
	for _, item := range items {
		lines = append(
			lines,
			item.SettlementID,
			item.Period,
			item.CurrencyCode,
			strconv.FormatInt(item.FractionDigits, 10),
			strconv.FormatInt(item.Revision, 10),
			item.SupersedesSettlementID,
			item.BeneficiaryType,
			item.BeneficiaryID,
			item.ShareNumerator,
			item.ShareDenominator,
			strconv.FormatInt(item.NetworkPoolMinor, 10),
			strconv.FormatInt(item.NetworkPoolAllocationMinor, 10),
			strconv.FormatInt(item.TTMCommissionBasisMinor, 10),
			strconv.FormatInt(item.TTMNetworkCommissionPoolMinor, 10),
			strconv.FormatInt(item.IndicativeNetworkValueMinor, 10),
			strconv.FormatInt(item.IndicativeValueAllocationMinor, 10),
			item.ValuationRulesetVersion,
			strconv.FormatInt(item.BaseValuationMultiplierBasisPoints, 10),
			strconv.FormatInt(item.RecentThreeMonthAverageMinor, 10),
			strconv.FormatInt(item.PriorThreeMonthAverageMinor, 10),
			strconv.FormatInt(item.EarlierThreeMonthAverageMinor, 10),
			strconv.FormatInt(item.RecentGrowthBasisPoints, 10),
			strconv.FormatInt(item.PriorGrowthBasisPoints, 10),
			strconv.FormatInt(item.AccelerationBasisPoints, 10),
			strconv.FormatInt(item.ValuationAdjustmentBasisPoints, 10),
			strconv.FormatInt(item.EffectiveValuationMultiplierBasisPoints, 10),
			strconv.FormatBool(item.ValuationIsNonBinding),
			strconv.FormatInt(item.ThroughLedgerIndex, 10),
			strconv.FormatInt(item.ThroughAuditIndex, 10),
			strconv.FormatInt(item.ThroughReviewIndex, 10),
			strconv.FormatInt(item.ThroughEligibilityIndex, 10),
			item.SourceFingerprint,
			item.SettlementHash,
			item.AcceptedAt,
		)
	}
	return Digest(canonical(lines...))
}

func SettlementQueryResponseMessage(response SettlementQueryResponse) []byte {
	return canonical(
		"myscoutee-registry-settlement-query-response-v1",
		response.ProtocolVersion,
		response.RegistryScope,
		response.DeploymentID,
		response.QueryID,
		response.QueryHash,
		response.ItemsHash,
		response.NextAfterPeriod,
		response.NextAfterSettlementID,
		response.GeneratedAt,
		response.RegistryKeyID,
	)
}
