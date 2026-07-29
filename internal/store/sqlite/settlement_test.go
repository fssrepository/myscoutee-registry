package sqlite

import (
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func TestSettlementTTMPoolRoundsOnceAfterAggregate(t *testing.T) {
	periodStart, err := time.Parse("2006-01", "2026-06")
	if err != nil {
		t.Fatalf("parse settlement period: %v", err)
	}
	record := store.SettlementRecord{
		Period: "2026-06",
		BaseValuationMultiplierBasisPoints:
			protocol.SettlementDefaultValuationMultiplierBasisPoints,
	}
	for offset := -11; offset <= 0; offset++ {
		record.RevenueSources = append(
			record.RevenueSources,
			store.SettlementRevenueSource{
				RevenuePeriod: periodStart.
					AddDate(0, offset, 0).
					Format("2006-01-02"),
				CommissionBasisMinor: 19,
			},
		)
	}
	recomputed, err := recomputeSettlementDerived(record, 0)
	if err != nil {
		t.Fatalf("recompute TTM settlement: %v", err)
	}
	if recomputed.TTMCommissionBasisMinor != 228 ||
		recomputed.TTMNetworkCommissionPoolMinor != 11 {
		t.Fatalf(
			"TTM basis/pool = %d/%d, want 228/11",
			recomputed.TTMCommissionBasisMinor,
			recomputed.TTMNetworkCommissionPoolMinor,
		)
	}
	var monthlyPoolSum int64
	for _, month := range recomputed.TTMMonths {
		monthlyPoolSum += month.NetworkCommissionPoolMinor
	}
	if monthlyPoolSum != 0 {
		t.Fatalf(
			"per-month audit pools unexpectedly sum to %d, want 0",
			monthlyPoolSum,
		)
	}
}

func TestSettlementValuationUsesThreeConsecutiveWindowsAndAcceleration(t *testing.T) {
	months := make([]store.SettlementTTMMonth, 12)
	for index := range months {
		months[index].Period = "test"
	}
	for index := 3; index <= 5; index++ {
		months[index].CommissionBasisMinor = 100
	}
	for index := 6; index <= 8; index++ {
		months[index].CommissionBasisMinor = 120
	}
	for index := 9; index <= 11; index++ {
		months[index].CommissionBasisMinor = 180
	}

	earlier, prior, recent := settlementThreeMonthAverages(months)
	if earlier != 100 || prior != 120 || recent != 180 {
		t.Fatalf(
			"three-month averages = (%d, %d, %d), want (100, 120, 180)",
			earlier,
			prior,
			recent,
		)
	}
	priorGrowth := settlementGrowthBasisPoints(earlier, prior)
	recentGrowth := settlementGrowthBasisPoints(prior, recent)
	acceleration := clampInt64(
		recentGrowth-priorGrowth,
		protocol.SettlementMinimumAccelerationBasisPoints,
		protocol.SettlementMaximumAccelerationBasisPoints,
	)
	adjustment := clampInt64(
		recentGrowth/protocol.SettlementAccelerationAdjustmentDivisor+
			acceleration/protocol.SettlementAccelerationAdjustmentDivisor,
		protocol.SettlementMinimumValuationAdjustmentBasisPoints,
		protocol.SettlementMaximumValuationAdjustmentBasisPoints,
	)
	effective, ok := multiplyBasisPoints(
		protocol.SettlementDefaultValuationMultiplierBasisPoints,
		10_000+adjustment,
	)
	if !ok {
		t.Fatal("bounded effective valuation multiplier overflowed")
	}
	if priorGrowth != 2_000 ||
		recentGrowth != 5_000 ||
		acceleration != 3_000 ||
		adjustment != 2_000 ||
		effective != 36_000 {
		t.Fatalf(
			"valuation motion = prior %d, recent %d, acceleration %d, adjustment %d, effective %d",
			priorGrowth,
			recentGrowth,
			acceleration,
			adjustment,
			effective,
		)
	}
}

func TestSettlementGrowthZeroWindowsAndSingleSpikeAreBounded(t *testing.T) {
	tests := []struct {
		name     string
		previous int64
		current  int64
		want     int64
	}{
		{"both zero", 0, 0, 0},
		{"zero to positive", 0, 1, protocol.SettlementMaximumGrowthBasisPoints},
		{"positive to zero", 1, 0, protocol.SettlementMinimumGrowthBasisPoints},
		{"large positive spike", 1, 1_000_000, protocol.SettlementMaximumGrowthBasisPoints},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := settlementGrowthBasisPoints(
				testCase.previous,
				testCase.current,
			); got != testCase.want {
				t.Fatalf("growth = %d, want %d", got, testCase.want)
			}
		})
	}

	adjustment := clampInt64(
		protocol.SettlementMaximumGrowthBasisPoints/
			protocol.SettlementAccelerationAdjustmentDivisor+
			protocol.SettlementMaximumAccelerationBasisPoints/
				protocol.SettlementAccelerationAdjustmentDivisor,
		protocol.SettlementMinimumValuationAdjustmentBasisPoints,
		protocol.SettlementMaximumValuationAdjustmentBasisPoints,
	)
	effective, ok := multiplyBasisPoints(
		protocol.SettlementDefaultValuationMultiplierBasisPoints,
		10_000+adjustment,
	)
	if !ok ||
		adjustment != protocol.SettlementMaximumValuationAdjustmentBasisPoints ||
		effective != 37_500 {
		t.Fatalf(
			"single-spike bound = adjustment %d, effective %d, ok %t",
			adjustment,
			effective,
			ok,
		)
	}
}

func TestSettlementLargestRemainderConservesAndUsesStableIDTieBreak(t *testing.T) {
	ratios := []settlementRatio{
		{
			beneficiaryType: protocol.SettlementBeneficiaryOperator,
			beneficiaryID:   "operator-b",
			ratio:           big.NewRat(1, 2),
		},
		{
			beneficiaryType: protocol.SettlementBeneficiaryOperator,
			beneficiaryID:   "operator-a",
			ratio:           big.NewRat(1, 2),
		},
	}
	values, err := largestRemainder(ratios, 1)
	if err != nil {
		t.Fatalf("allocate tied remainder: %v", err)
	}
	if !reflect.DeepEqual(values, []int64{0, 1}) {
		t.Fatalf("tied remainder allocation = %v, want [0 1]", values)
	}

	weighted, err := settlementRatios(
		[]store.SettlementWeightSource{
			{BeneficiaryID: "operator-a", Label: "A", Weight: 1},
			{BeneficiaryID: "operator-b", Label: "B", Weight: 1},
		},
		protocol.FounderContributionUnits*settlementWeightMonths,
	)
	if err != nil {
		t.Fatalf("derive settlement ratios: %v", err)
	}
	allocations, err := allocateSettlementAmounts(weighted, 5, 101)
	if err != nil {
		t.Fatalf("allocate settlement totals: %v", err)
	}
	var poolTotal, valueTotal int64
	for _, allocation := range allocations {
		poolTotal += allocation.NetworkPoolAllocationMinor
		valueTotal += allocation.IndicativeValueAllocationMinor
	}
	if poolTotal != 5 || valueTotal != 101 {
		t.Fatalf(
			"allocation conservation = pool %d/5, value %d/101",
			poolTotal,
			valueTotal,
		)
	}
}

func TestSettlementUsesExplicitReserveWithoutEligibleOperators(t *testing.T) {
	ratios, err := settlementRatios(
		nil,
		protocol.FounderContributionUnits*settlementWeightMonths,
	)
	if err != nil {
		t.Fatalf("derive reserve ratios: %v", err)
	}
	if len(ratios) != 2 ||
		ratios[0].beneficiaryType != protocol.SettlementBeneficiaryFounder ||
		ratios[0].ratio.Cmp(big.NewRat(1, 2)) != 0 ||
		ratios[1].beneficiaryType != protocol.SettlementBeneficiaryReserve ||
		ratios[1].ratio.Cmp(big.NewRat(1, 2)) != 0 {
		t.Fatalf("reserve ratios = %+v", ratios)
	}
}
