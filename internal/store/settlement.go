package store

import (
	"context"
	"crypto/ed25519"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

type SettlementCalculationInput struct {
	RegistryScope                      string
	Period                             string
	CurrencyCode                       string
	FractionDigits                     int64
	BaseValuationMultiplierBasisPoints int64
	CandidateSettlementID              string
	AcceptedAt                         string
	RegistryKeyID                      string
}

type SettlementRevenueSource struct {
	SourceOrder          int64
	RevenuePeriod        string
	DeploymentID         string
	BatchID              string
	LedgerIndex          int64
	EntryHash            string
	CommissionBasisMinor int64
}

type SettlementTTMMonth struct {
	Period                     string
	CommissionBasisMinor       int64
	NetworkCommissionPoolMinor int64
}

type SettlementWeightSource struct {
	BeneficiaryID string
	Label         string
	Weight        int64
}

type SettlementBeneficiaryDeployment struct {
	BeneficiaryID string
	DeploymentID  string
}

type SettlementRecord struct {
	SettlementID                       string
	Period                             string
	CurrencyCode                       string
	FractionDigits                     int64
	Revision                           int64
	SupersedesSettlementID             string
	RulesetVersion                     string
	ValuationRulesetVersion            string
	CommissionRateBasisPoints          int64
	BaseValuationMultiplierBasisPoints int64
	RecentThreeMonthAverageMinor       int64
	PriorThreeMonthAverageMinor        int64
	EarlierThreeMonthAverageMinor      int64
	RecentGrowthBasisPoints            int64
	PriorGrowthBasisPoints             int64
	AccelerationBasisPoints            int64
	ValuationAdjustmentBasisPoints     int64
	EffectiveValuationMultiplierBasisPoints int64
	CommissionBasisMinor               int64
	NetworkCommissionPoolMinor         int64
	TTMCommissionBasisMinor            int64
	TTMNetworkCommissionPoolMinor      int64
	IndicativeNetworkValueMinor        int64
	ThroughLedgerIndex                 int64
	ThroughAuditIndex                  int64
	ThroughReviewIndex                 int64
	ThroughEligibilityIndex            int64
	LedgerHeadHash                     string
	AuditHeadHash                      string
	ReviewHeadHash                     string
	EligibilityHeadHash                string
	SourceFingerprint                  string
	AllocationHash                     string
	SettlementHash                     string
	AcceptedAt                         string
	RegistryKeyID                      string
	LedgerEntry                        protocol.LedgerEntry
	ReceiptSignature                   []byte
	Allocations                        []protocol.SettlementAllocation
	RevenueSources                     []SettlementRevenueSource
	TTMMonths                          []SettlementTTMMonth
	WeightSources                      []SettlementWeightSource
	BeneficiaryDeployments             []SettlementBeneficiaryDeployment
}

type SettlementSigner func(SettlementRecord) ([]byte, error)

type SettlementHistoryQuery struct {
	DeploymentID      string
	Period            string
	CurrencyCode      string
	FromPeriod        string
	ThroughPeriod     string
	IncludeSuperseded bool
	Limit             int
	AfterPeriod       string
	AfterSettlementID string
}

type SettlementHistoryPage struct {
	Items                 []protocol.SettlementHistoryItem
	NextAfterPeriod       string
	NextAfterSettlementID string
}

type SettlementStore interface {
	CalculateSettlement(
		context.Context,
		SettlementCalculationInput,
		SettlementSigner,
	) (SettlementRecord, bool, error)
	Settlement(context.Context, string) (SettlementRecord, error)
	SettlementHistory(
		context.Context,
		SettlementHistoryQuery,
	) (SettlementHistoryPage, error)
	VerifySettlements(
		context.Context,
		ed25519.PublicKey,
		string,
		string,
	) error
}
