package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const settlementWeightMonths = int64(6)

type settlementRatio struct {
	beneficiaryType string
	beneficiaryID   string
	label           string
	ratio           *big.Rat
}

type settlementRemainder struct {
	index       int
	numerator   *big.Int
	denominator *big.Int
	id          string
}

func (sqliteStore *Store) CalculateSettlement(
	ctx context.Context,
	input store.SettlementCalculationInput,
	signReceipt store.SettlementSigner,
) (store.SettlementRecord, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.SettlementRecord{}, false, fmt.Errorf(
			"begin settlement calculation: %w",
			err,
		)
	}
	defer tx.Rollback()

	if err := ensureAcceptedAtAfterRegistryCreation(ctx, tx, input.AcceptedAt); err != nil {
		return store.SettlementRecord{}, false, err
	}
	if err := ensureAcceptedAtAfterCheckpoint(ctx, tx, input.AcceptedAt); err != nil {
		return store.SettlementRecord{}, false, err
	}
	ledgerHead, err := ledgerHeadTx(ctx, tx)
	if err != nil {
		return store.SettlementRecord{}, false, err
	}
	if err := ensureAcceptedAtNotBeforeHead(input.AcceptedAt, ledgerHead.AcceptedAt); err != nil {
		return store.SettlementRecord{}, false, err
	}

	record, err := settlementSourcesTx(ctx, tx, input)
	if err != nil {
		return store.SettlementRecord{}, false, err
	}
	latest, found, err := latestSettlementTx(
		ctx,
		tx,
		input.Period,
		input.CurrencyCode,
	)
	if err != nil {
		return store.SettlementRecord{}, false, err
	}
	if found && latest.SourceFingerprint == record.SourceFingerprint {
		if err := tx.Commit(); err != nil {
			return store.SettlementRecord{}, false, fmt.Errorf(
				"commit duplicate settlement calculation: %w",
				err,
			)
		}
		return latest, true, nil
	}
	record.SettlementID = input.CandidateSettlementID
	record.RegistryKeyID = input.RegistryKeyID
	record.Revision = 1
	if found {
		record.Revision = latest.Revision + 1
		record.SupersedesSettlementID = latest.SettlementID
	}
	record.AcceptedAt = input.AcceptedAt
	record.AllocationHash = protocol.SettlementAllocationHash(record.Allocations)

	receipt := settlementReceipt(record, input.RegistryScope)
	record.SettlementHash = protocol.Digest(
		protocol.SettlementHashMessage(receipt),
	)
	entry := protocol.LedgerEntry{
		ProtocolVersion:   protocol.Version,
		RegistryScope:     input.RegistryScope,
		LedgerIndex:       ledgerHead.LedgerIndex + 1,
		EntryType:         protocol.SettlementEntryType,
		DeploymentID:      "",
		BatchID:           record.SettlementID,
		Kind:              protocol.SettlementKind,
		Period:            record.Period,
		RulesetVersion:    protocol.SettlementRulesetVersion,
		QualifiedMAUCount: 0,
		BatchHash:         record.SettlementHash,
		PreviousEntryHash: ledgerHead.EntryHash,
		AcceptedAt:        input.AcceptedAt,
	}
	entry.EntryHash = protocol.Digest(protocol.LedgerEntryMessage(entry))
	record.LedgerEntry = entry
	signature, err := signReceipt(record)
	if err != nil {
		return store.SettlementRecord{}, false, fmt.Errorf(
			"sign settlement receipt: %w",
			err,
		)
	}
	record.ReceiptSignature = append([]byte(nil), signature...)

	if err := insertSettlementTx(ctx, tx, record); err != nil {
		return store.SettlementRecord{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return store.SettlementRecord{}, false, fmt.Errorf(
			"commit settlement calculation: %w",
			err,
		)
	}
	return record, false, nil
}

func settlementSourcesTx(
	ctx context.Context,
	tx *sql.Tx,
	input store.SettlementCalculationInput,
) (store.SettlementRecord, error) {
	boundary, err := settlementBoundaryTx(ctx, tx)
	if err != nil {
		return store.SettlementRecord{}, err
	}
	periodStart, err := time.Parse("2006-01", input.Period)
	if err != nil {
		return store.SettlementRecord{}, store.ErrInconsistentState
	}
	ttmStart := periodStart.AddDate(0, -11, 0)
	ttmEnd := periodStart.AddDate(0, 1, 0)
	revenueSources, err := settlementRevenueSourcesTx(
		ctx,
		tx,
		input.CurrencyCode,
		ttmStart.Format("2006-01-02"),
		ttmEnd.Format("2006-01-02"),
		boundary.LedgerIndex,
	)
	if err != nil {
		return store.SettlementRecord{}, err
	}
	months := make([]store.SettlementTTMMonth, 0, 12)
	monthlyBasis := make(map[string]int64, 12)
	for _, source := range revenueSources {
		month := source.RevenuePeriod[:len("2006-01")]
		next, ok := checkedRevenueAdd(
			monthlyBasis[month],
			source.CommissionBasisMinor,
		)
		if !ok {
			return store.SettlementRecord{}, store.ErrRevenueAggregateOverflow
		}
		monthlyBasis[month] = next
	}
	var ttmBasis int64
	for offset := 0; offset < 12; offset++ {
		month := ttmStart.AddDate(0, offset, 0).Format("2006-01")
		basis := monthlyBasis[month]
		pool := protocol.RevenueCommissionMinor(basis)
		var ok bool
		ttmBasis, ok = checkedRevenueAdd(ttmBasis, basis)
		if !ok {
			return store.SettlementRecord{}, store.ErrRevenueAggregateOverflow
		}
		months = append(months, store.SettlementTTMMonth{
			Period:                     month,
			CommissionBasisMinor:       basis,
			NetworkCommissionPoolMinor: pool,
		})
	}
	ttmPool := protocol.RevenueCommissionMinor(ttmBasis)
	currentBasis := monthlyBasis[input.Period]
	currentPool := protocol.RevenueCommissionMinor(currentBasis)
	earlierAverage, priorAverage, recentAverage := settlementThreeMonthAverages(months)
	priorGrowth := settlementGrowthBasisPoints(earlierAverage, priorAverage)
	recentGrowth := settlementGrowthBasisPoints(priorAverage, recentAverage)
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
	effectiveMultiplier, ok := multiplyBasisPoints(
		input.BaseValuationMultiplierBasisPoints,
		10_000+adjustment,
	)
	if !ok || effectiveMultiplier <= 0 {
		return store.SettlementRecord{}, store.ErrRevenueAggregateOverflow
	}
	indicativeValue, ok := multiplyBasisPoints(
		ttmBasis,
		effectiveMultiplier,
	)
	if !ok {
		return store.SettlementRecord{}, store.ErrRevenueAggregateOverflow
	}

	fromWeightPeriod := periodStart.AddDate(0, -5, 0).Format("2006-01")
	weightSources, members, measuredWeight, err := settlementWeightSourcesTx(
		ctx,
		tx,
		fromWeightPeriod,
		input.Period,
		boundary,
	)
	if err != nil {
		return store.SettlementRecord{}, err
	}
	ratios, err := settlementRatios(weightSources, measuredWeight)
	if err != nil {
		return store.SettlementRecord{}, err
	}
	allocations, err := allocateSettlementAmounts(
		ratios,
		currentPool,
		indicativeValue,
	)
	if err != nil {
		return store.SettlementRecord{}, err
	}

	record := store.SettlementRecord{
		Period:                         input.Period,
		CurrencyCode:                   input.CurrencyCode,
		FractionDigits:                 input.FractionDigits,
		RulesetVersion:                 protocol.SettlementRulesetVersion,
		ValuationRulesetVersion:        protocol.SettlementValuationRulesetVersion,
		CommissionRateBasisPoints:      protocol.RevenueCommissionBasisPoints,
		BaseValuationMultiplierBasisPoints: input.BaseValuationMultiplierBasisPoints,
		RecentThreeMonthAverageMinor:       recentAverage,
		PriorThreeMonthAverageMinor:        priorAverage,
		EarlierThreeMonthAverageMinor:      earlierAverage,
		RecentGrowthBasisPoints:            recentGrowth,
		PriorGrowthBasisPoints:             priorGrowth,
		AccelerationBasisPoints:            acceleration,
		ValuationAdjustmentBasisPoints:     adjustment,
		EffectiveValuationMultiplierBasisPoints: effectiveMultiplier,
		CommissionBasisMinor:           currentBasis,
		NetworkCommissionPoolMinor:     currentPool,
		TTMCommissionBasisMinor:        ttmBasis,
		TTMNetworkCommissionPoolMinor:  ttmPool,
		IndicativeNetworkValueMinor:    indicativeValue,
		ThroughLedgerIndex:             boundary.LedgerIndex,
		ThroughAuditIndex:              boundary.AuditIndex,
		ThroughReviewIndex:             boundary.ReviewIndex,
		ThroughEligibilityIndex:        boundary.EligibilityIndex,
		LedgerHeadHash:                 boundary.LedgerHash,
		AuditHeadHash:                  boundary.AuditHash,
		ReviewHeadHash:                 boundary.ReviewHash,
		EligibilityHeadHash:            boundary.EligibilityHash,
		Allocations:                    allocations,
		RevenueSources:                 revenueSources,
		TTMMonths:                      months,
		WeightSources:                  weightSources,
		BeneficiaryDeployments:         members,
	}
	if !settlementRecordHasSafeMinorAmounts(record) {
		return store.SettlementRecord{}, store.ErrRevenueAggregateOverflow
	}
	record.SourceFingerprint = settlementSourceFingerprint(record)
	return record, nil
}

func settlementRecordHasSafeMinorAmounts(
	record store.SettlementRecord,
) bool {
	for _, value := range []int64{
		record.CommissionBasisMinor,
		record.NetworkCommissionPoolMinor,
		record.TTMCommissionBasisMinor,
		record.TTMNetworkCommissionPoolMinor,
		record.IndicativeNetworkValueMinor,
		record.RecentThreeMonthAverageMinor,
		record.PriorThreeMonthAverageMinor,
		record.EarlierThreeMonthAverageMinor,
	} {
		if !protocol.SettlementMinorAmountIsSafe(value) {
			return false
		}
	}
	for _, allocation := range record.Allocations {
		if !protocol.SettlementMinorAmountIsSafe(
			allocation.NetworkPoolAllocationMinor,
		) || !protocol.SettlementMinorAmountIsSafe(
			allocation.IndicativeValueAllocationMinor,
		) {
			return false
		}
	}
	return true
}

func settlementBoundaryTx(
	ctx context.Context,
	tx *sql.Tx,
) (store.LeaderboardBoundary, error) {
	var boundary store.LeaderboardBoundary
	if err := tx.QueryRowContext(ctx, `
		SELECT ledger_index, entry_hash
		FROM ledger_entries
		WHERE entry_type <> ?
		ORDER BY ledger_index DESC
		LIMIT 1`,
		protocol.SettlementEntryType,
	).Scan(&boundary.LedgerIndex, &boundary.LedgerHash); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return store.LeaderboardBoundary{}, fmt.Errorf(
				"read settlement ledger source boundary: %w",
				err,
			)
		}
		boundary.LedgerHash = protocol.ZeroHash
	}
	audit, err := operatorAuditHeadTx(ctx, tx)
	if err != nil {
		return store.LeaderboardBoundary{}, err
	}
	review, err := operatorClaimReviewHeadTx(ctx, tx)
	if err != nil {
		return store.LeaderboardBoundary{}, err
	}
	eligibility, err := operatorClaimEligibilityHeadQuery(ctx, tx)
	if err != nil {
		return store.LeaderboardBoundary{}, err
	}
	boundary.AuditIndex = audit.AuditIndex
	boundary.AuditHash = audit.AuditHash
	boundary.ReviewIndex = review.ReviewIndex
	boundary.ReviewHash = review.ReviewHash
	boundary.EligibilityIndex = eligibility.EligibilityIndex
	boundary.EligibilityHash = eligibility.EligibilityHash
	return boundary, nil
}

func settlementRevenueSourcesTx(
	ctx context.Context,
	tx *sql.Tx,
	currencyCode string,
	fromDate string,
	throughDateExclusive string,
	throughLedgerIndex int64,
) ([]store.SettlementRevenueSource, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT
			row.period,
			row.deployment_id,
			row.batch_id,
			row.ledger_index,
			row.source_entry_hash,
			row.commission_basis_minor
		FROM revenue_query_rows row
		WHERE row.currency_code = ?
		  AND row.period >= ?
		  AND row.period < ?
		  AND row.ledger_index <= ?
		  AND NOT EXISTS (
			SELECT 1
			FROM revenue_batches newer
			WHERE newer.deployment_id = row.deployment_id
			  AND newer.period = row.period
			  AND newer.revision > row.revision
			  AND newer.ledger_index <= ?
		  )
		ORDER BY row.period, row.deployment_id, row.batch_id`,
		currencyCode,
		fromDate,
		throughDateExclusive,
		throughLedgerIndex,
		throughLedgerIndex,
	)
	if err != nil {
		return nil, fmt.Errorf("read settlement revenue sources: %w", err)
	}
	defer rows.Close()
	sources := make([]store.SettlementRevenueSource, 0)
	for rows.Next() {
		source := store.SettlementRevenueSource{
			SourceOrder: int64(len(sources)),
		}
		if err := rows.Scan(
			&source.RevenuePeriod,
			&source.DeploymentID,
			&source.BatchID,
			&source.LedgerIndex,
			&source.EntryHash,
			&source.CommissionBasisMinor,
		); err != nil {
			return nil, fmt.Errorf("scan settlement revenue source: %w", err)
		}
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate settlement revenue sources: %w", err)
	}
	return sources, nil
}

func settlementWeightSourcesTx(
	ctx context.Context,
	tx *sql.Tx,
	fromPeriod string,
	throughPeriod string,
	boundary store.LeaderboardBoundary,
) ([]store.SettlementWeightSource, []store.SettlementBeneficiaryDeployment, int64, error) {
	arguments := []any{
		boundary.AuditIndex,
		boundary.LedgerIndex,
		boundary.ReviewIndex,
		boundary.EligibilityIndex,
		fromPeriod,
		throughPeriod,
	}
	var measuredWeight int64
	if err := tx.QueryRowContext(
		ctx,
		leaderboardStateCTE+`
		SELECT COALESCE(SUM(measured_weight), 0)
		FROM weighted_memberships`,
		arguments...,
	).Scan(&measuredWeight); err != nil {
		return nil, nil, 0, fmt.Errorf(
			"read settlement measured weight: %w",
			err,
		)
	}
	rows, err := tx.QueryContext(
		ctx,
		leaderboardStateCTE+`
		SELECT
			membership.group_id,
			COALESCE(NULLIF(profile.operator_name, ''), membership.group_id),
			COALESCE(SUM(membership.eligible_weight), 0)
		FROM weighted_memberships membership
		LEFT JOIN group_profiles profile
		  ON profile.group_id = membership.group_id
		WHERE membership.active = 1
		  AND membership.claimed = 1
		  AND membership.eligible = 1
		  AND membership.group_id <> ''
		  AND COALESCE(NULLIF(profile.claim_state, ''), 'claimed')
		      IN ('claimed', 'approved')
		GROUP BY membership.group_id, profile.operator_name
		HAVING COALESCE(SUM(membership.eligible_weight), 0) > 0
		ORDER BY membership.group_id`,
		arguments...,
	)
	if err != nil {
		return nil, nil, 0, fmt.Errorf(
			"read settlement operator weights: %w",
			err,
		)
	}
	weights := make([]store.SettlementWeightSource, 0)
	for rows.Next() {
		var weight store.SettlementWeightSource
		if err := rows.Scan(
			&weight.BeneficiaryID,
			&weight.Label,
			&weight.Weight,
		); err != nil {
			rows.Close()
			return nil, nil, 0, fmt.Errorf(
				"scan settlement operator weight: %w",
				err,
			)
		}
		weights = append(weights, weight)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, 0, fmt.Errorf(
			"iterate settlement operator weights: %w",
			err,
		)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, 0, fmt.Errorf(
			"close settlement operator weights: %w",
			err,
		)
	}

	memberRows, err := tx.QueryContext(
		ctx,
		leaderboardStateCTE+`
		SELECT membership.group_id, membership.deployment_id
		FROM weighted_memberships membership
		LEFT JOIN group_profiles profile
		  ON profile.group_id = membership.group_id
		WHERE membership.active = 1
		  AND membership.claimed = 1
		  AND membership.eligible = 1
		  AND membership.group_id <> ''
		  AND COALESCE(NULLIF(profile.claim_state, ''), 'claimed')
		      IN ('claimed', 'approved')
		ORDER BY membership.group_id, membership.deployment_id`,
		arguments...,
	)
	if err != nil {
		return nil, nil, 0, fmt.Errorf(
			"read settlement beneficiary deployments: %w",
			err,
		)
	}
	defer memberRows.Close()
	members := make([]store.SettlementBeneficiaryDeployment, 0)
	for memberRows.Next() {
		var member store.SettlementBeneficiaryDeployment
		if err := memberRows.Scan(
			&member.BeneficiaryID,
			&member.DeploymentID,
		); err != nil {
			return nil, nil, 0, fmt.Errorf(
				"scan settlement beneficiary deployment: %w",
				err,
			)
		}
		members = append(members, member)
	}
	if err := memberRows.Err(); err != nil {
		return nil, nil, 0, fmt.Errorf(
			"iterate settlement beneficiary deployments: %w",
			err,
		)
	}
	return weights, members, measuredWeight, nil
}

func settlementRatios(
	weights []store.SettlementWeightSource,
	measuredWeight int64,
) ([]settlementRatio, error) {
	founderScaled := protocol.FounderContributionUnits * settlementWeightMonths
	if measuredWeight < 0 || measuredWeight > math.MaxInt64-founderScaled {
		return nil, store.ErrRevenueAggregateOverflow
	}
	founder := big.NewRat(founderScaled, founderScaled+measuredWeight)
	minimum := big.NewRat(1, 10)
	if founder.Cmp(minimum) < 0 {
		founder = minimum
	}
	ratios := []settlementRatio{{
		beneficiaryType: protocol.SettlementBeneficiaryFounder,
		beneficiaryID:   protocol.SettlementFounderBeneficiaryID,
		label:           "Founder",
		ratio:           founder,
	}}
	var eligibleWeight int64
	for _, weight := range weights {
		var ok bool
		eligibleWeight, ok = checkedRevenueAdd(eligibleWeight, weight.Weight)
		if !ok {
			return nil, store.ErrRevenueAggregateOverflow
		}
	}
	operatorPool := new(big.Rat).Sub(big.NewRat(1, 1), founder)
	if eligibleWeight > 0 {
		for _, weight := range weights {
			ratios = append(ratios, settlementRatio{
				beneficiaryType: protocol.SettlementBeneficiaryOperator,
				beneficiaryID:   weight.BeneficiaryID,
				label:           weight.Label,
				ratio: new(big.Rat).Mul(
					operatorPool,
					big.NewRat(weight.Weight, eligibleWeight),
				),
			})
		}
	} else {
		ratios = append(ratios, settlementRatio{
			beneficiaryType: protocol.SettlementBeneficiaryReserve,
			beneficiaryID:   protocol.SettlementReserveBeneficiaryID,
			label:           "Unallocated reserve",
			ratio:           operatorPool,
		})
	}
	sort.Slice(ratios, func(left, right int) bool {
		if ratios[left].beneficiaryType == protocol.SettlementBeneficiaryFounder {
			return true
		}
		if ratios[right].beneficiaryType == protocol.SettlementBeneficiaryFounder {
			return false
		}
		return ratios[left].beneficiaryID < ratios[right].beneficiaryID
	})
	return ratios, nil
}

func allocateSettlementAmounts(
	ratios []settlementRatio,
	pool int64,
	indicativeValue int64,
) ([]protocol.SettlementAllocation, error) {
	poolValues, err := largestRemainder(ratios, pool)
	if err != nil {
		return nil, err
	}
	valueValues, err := largestRemainder(ratios, indicativeValue)
	if err != nil {
		return nil, err
	}
	allocations := make([]protocol.SettlementAllocation, len(ratios))
	for index, ratio := range ratios {
		allocations[index] = protocol.SettlementAllocation{
			BeneficiaryType:                ratio.beneficiaryType,
			BeneficiaryID:                  ratio.beneficiaryID,
			Label:                          ratio.label,
			ShareNumerator:                 ratio.ratio.Num().String(),
			ShareDenominator:               ratio.ratio.Denom().String(),
			NetworkPoolAllocationMinor:     poolValues[index],
			IndicativeValueAllocationMinor: valueValues[index],
		}
	}
	return allocations, nil
}

func largestRemainder(ratios []settlementRatio, total int64) ([]int64, error) {
	if total < 0 {
		return nil, store.ErrInconsistentState
	}
	values := make([]int64, len(ratios))
	remainders := make([]settlementRemainder, len(ratios))
	var allocated int64
	totalInteger := big.NewInt(total)
	for index, item := range ratios {
		numerator := new(big.Int).Mul(totalInteger, item.ratio.Num())
		quotient, remainder := new(big.Int), new(big.Int)
		quotient.QuoRem(numerator, item.ratio.Denom(), remainder)
		if !quotient.IsInt64() {
			return nil, store.ErrRevenueAggregateOverflow
		}
		values[index] = quotient.Int64()
		allocated += values[index]
		remainders[index] = settlementRemainder{
			index:       index,
			numerator:   remainder,
			denominator: new(big.Int).Set(item.ratio.Denom()),
			id:          item.beneficiaryID,
		}
	}
	left := total - allocated
	if left < 0 || left > int64(len(ratios)) {
		return nil, store.ErrInconsistentState
	}
	sort.Slice(remainders, func(left, right int) bool {
		crossLeft := new(big.Int).Mul(
			remainders[left].numerator,
			remainders[right].denominator,
		)
		crossRight := new(big.Int).Mul(
			remainders[right].numerator,
			remainders[left].denominator,
		)
		comparison := crossLeft.Cmp(crossRight)
		if comparison != 0 {
			return comparison > 0
		}
		return remainders[left].id < remainders[right].id
	})
	for index := int64(0); index < left; index++ {
		values[remainders[index].index]++
	}
	return values, nil
}

func settlementThreeMonthAverages(
	months []store.SettlementTTMMonth,
) (int64, int64, int64) {
	if len(months) != 12 {
		return 0, 0, 0
	}
	average := func(from int) int64 {
		return (months[from].CommissionBasisMinor +
			months[from+1].CommissionBasisMinor +
			months[from+2].CommissionBasisMinor) / 3
	}
	return average(3), average(6), average(9)
}

func settlementGrowthBasisPoints(previous, current int64) int64 {
	switch {
	case previous == 0 && current == 0:
		return 0
	case previous == 0:
		return protocol.SettlementMaximumGrowthBasisPoints
	default:
		difference := big.NewInt(current - previous)
		scaled := new(big.Int).Mul(difference, big.NewInt(10_000))
		result := new(big.Int).Quo(scaled, big.NewInt(previous))
		if !result.IsInt64() {
			if result.Sign() < 0 {
				return protocol.SettlementMinimumGrowthBasisPoints
			}
			return protocol.SettlementMaximumGrowthBasisPoints
		}
		return clampInt64(
			result.Int64(),
			protocol.SettlementMinimumGrowthBasisPoints,
			protocol.SettlementMaximumGrowthBasisPoints,
		)
	}
}

func clampInt64(value, minimum, maximum int64) int64 {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func multiplyBasisPoints(value, basisPoints int64) (int64, bool) {
	if value < 0 || basisPoints < 0 {
		return 0, false
	}
	product := new(big.Int).Mul(big.NewInt(value), big.NewInt(basisPoints))
	result := new(big.Int).Quo(product, big.NewInt(10_000))
	return result.Int64(), result.IsInt64()
}

func settlementSourceFingerprint(record store.SettlementRecord) string {
	lines := []string{
		"myscoutee-registry-settlement-source-v1",
		record.Period,
		record.CurrencyCode,
		strconv.FormatInt(record.FractionDigits, 10),
		record.RulesetVersion,
		record.ValuationRulesetVersion,
		strconv.FormatInt(record.CommissionRateBasisPoints, 10),
		strconv.FormatInt(record.BaseValuationMultiplierBasisPoints, 10),
		strconv.FormatInt(record.ThroughLedgerIndex, 10),
		strconv.FormatInt(record.ThroughAuditIndex, 10),
		strconv.FormatInt(record.ThroughReviewIndex, 10),
		strconv.FormatInt(record.ThroughEligibilityIndex, 10),
		record.LedgerHeadHash,
		record.AuditHeadHash,
		record.ReviewHeadHash,
		record.EligibilityHeadHash,
		strconv.Itoa(len(record.RevenueSources)),
	}
	for _, source := range record.RevenueSources {
		lines = append(
			lines,
			strconv.FormatInt(source.SourceOrder, 10),
			source.RevenuePeriod,
			source.DeploymentID,
			source.BatchID,
			strconv.FormatInt(source.LedgerIndex, 10),
			source.EntryHash,
			strconv.FormatInt(source.CommissionBasisMinor, 10),
		)
	}
	lines = append(lines, strconv.Itoa(len(record.TTMMonths)))
	for _, month := range record.TTMMonths {
		lines = append(
			lines,
			month.Period,
			strconv.FormatInt(month.CommissionBasisMinor, 10),
			strconv.FormatInt(month.NetworkCommissionPoolMinor, 10),
		)
	}
	lines = append(lines, strconv.Itoa(len(record.WeightSources)))
	for _, weight := range record.WeightSources {
		lines = append(
			lines,
			weight.BeneficiaryID,
			weight.Label,
			strconv.FormatInt(weight.Weight, 10),
		)
	}
	lines = append(lines, strconv.Itoa(len(record.BeneficiaryDeployments)))
	for _, member := range record.BeneficiaryDeployments {
		lines = append(lines, member.BeneficiaryID, member.DeploymentID)
	}
	return protocol.Digest([]byte(strings.Join(lines, "\n") + "\n"))
}

func latestSettlementTx(
	ctx context.Context,
	tx *sql.Tx,
	period string,
	currencyCode string,
) (store.SettlementRecord, bool, error) {
	var settlementID string
	err := tx.QueryRowContext(ctx, `
		SELECT settlement_id
		FROM settlements
		WHERE period = ? AND currency_code = ?
		ORDER BY revision DESC
		LIMIT 1`,
		period,
		currencyCode,
	).Scan(&settlementID)
	if errors.Is(err, sql.ErrNoRows) {
		return store.SettlementRecord{}, false, nil
	}
	if err != nil {
		return store.SettlementRecord{}, false, fmt.Errorf(
			"read latest settlement revision: %w",
			err,
		)
	}
	record, err := settlementByIDQuery(ctx, tx, settlementID)
	return record, err == nil, err
}

func insertSettlementTx(
	ctx context.Context,
	tx *sql.Tx,
	record store.SettlementRecord,
) error {
	entry := record.LedgerEntry
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ledger_entries (
			ledger_index, protocol_version, registry_scope, entry_type,
			deployment_id, batch_id, kind, period, ruleset_version,
			qualified_mau_count, batch_hash, previous_entry_hash, entry_hash,
			accepted_at
		) VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, 0, ?, ?, ?, ?)`,
		entry.LedgerIndex,
		entry.ProtocolVersion,
		entry.RegistryScope,
		entry.EntryType,
		entry.BatchID,
		entry.Kind,
		entry.Period,
		entry.RulesetVersion,
		entry.BatchHash,
		entry.PreviousEntryHash,
		entry.EntryHash,
		entry.AcceptedAt,
	); err != nil {
		return fmt.Errorf("append settlement ledger entry: %w", err)
	}
	if err := appendMerkleEntryTx(
		ctx,
		tx,
		entry.LedgerIndex,
		entry.EntryHash,
	); err != nil {
		return err
	}
	var supersedes any
	if record.SupersedesSettlementID != "" {
		supersedes = record.SupersedesSettlementID
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO settlements (
			settlement_id, period, currency_code, fraction_digits, revision,
			supersedes_settlement_id, ruleset_version,
			valuation_ruleset_version, commission_rate_basis_points,
			base_valuation_multiplier_basis_points,
			recent_three_month_average_minor,
			prior_three_month_average_minor,
			earlier_three_month_average_minor,
			recent_growth_basis_points, prior_growth_basis_points,
			acceleration_basis_points, valuation_adjustment_basis_points,
			effective_valuation_multiplier_basis_points,
			commission_basis_minor, network_commission_pool_minor,
			ttm_commission_basis_minor, ttm_network_commission_pool_minor,
			indicative_network_value_minor, through_ledger_index,
			through_audit_index, through_review_index,
			through_eligibility_index, ledger_head_hash, audit_head_hash,
			review_head_hash, eligibility_head_hash, source_fingerprint,
			allocation_hash, settlement_hash, accepted_at, ledger_index,
			registry_key_id, receipt_signature
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		)`,
		record.SettlementID,
		record.Period,
		record.CurrencyCode,
		record.FractionDigits,
		record.Revision,
		supersedes,
		record.RulesetVersion,
		record.ValuationRulesetVersion,
		record.CommissionRateBasisPoints,
		record.BaseValuationMultiplierBasisPoints,
		record.RecentThreeMonthAverageMinor,
		record.PriorThreeMonthAverageMinor,
		record.EarlierThreeMonthAverageMinor,
		record.RecentGrowthBasisPoints,
		record.PriorGrowthBasisPoints,
		record.AccelerationBasisPoints,
		record.ValuationAdjustmentBasisPoints,
		record.EffectiveValuationMultiplierBasisPoints,
		record.CommissionBasisMinor,
		record.NetworkCommissionPoolMinor,
		record.TTMCommissionBasisMinor,
		record.TTMNetworkCommissionPoolMinor,
		record.IndicativeNetworkValueMinor,
		record.ThroughLedgerIndex,
		record.ThroughAuditIndex,
		record.ThroughReviewIndex,
		record.ThroughEligibilityIndex,
		record.LedgerHeadHash,
		record.AuditHeadHash,
		record.ReviewHeadHash,
		record.EligibilityHeadHash,
		record.SourceFingerprint,
		record.AllocationHash,
		record.SettlementHash,
		record.AcceptedAt,
		entry.LedgerIndex,
		record.RegistryKeyID,
		record.ReceiptSignature,
	); err != nil {
		return fmt.Errorf("persist settlement source: %w", err)
	}
	for _, source := range record.RevenueSources {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO settlement_revenue_sources (
				settlement_id, source_order, revenue_period, deployment_id,
				batch_id, ledger_index, source_entry_hash,
				commission_basis_minor
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			record.SettlementID,
			source.SourceOrder,
			source.RevenuePeriod,
			source.DeploymentID,
			source.BatchID,
			source.LedgerIndex,
			source.EntryHash,
			source.CommissionBasisMinor,
		); err != nil {
			return fmt.Errorf("persist settlement revenue source: %w", err)
		}
	}
	for _, month := range record.TTMMonths {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO settlement_ttm_months (
				settlement_id, period, commission_basis_minor,
				network_commission_pool_minor
			) VALUES (?, ?, ?, ?)`,
			record.SettlementID,
			month.Period,
			month.CommissionBasisMinor,
			month.NetworkCommissionPoolMinor,
		); err != nil {
			return fmt.Errorf("persist settlement TTM month: %w", err)
		}
	}
	for _, weight := range record.WeightSources {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO settlement_weight_sources (
				settlement_id, beneficiary_id, label, weight
			) VALUES (?, ?, ?, ?)`,
			record.SettlementID,
			weight.BeneficiaryID,
			weight.Label,
			weight.Weight,
		); err != nil {
			return fmt.Errorf("persist settlement weight source: %w", err)
		}
	}
	for _, member := range record.BeneficiaryDeployments {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO settlement_beneficiary_deployments (
				settlement_id, beneficiary_id, deployment_id
			) VALUES (?, ?, ?)`,
			record.SettlementID,
			member.BeneficiaryID,
			member.DeploymentID,
		); err != nil {
			return fmt.Errorf(
				"persist settlement beneficiary deployment: %w",
				err,
			)
		}
	}
	for index, allocation := range record.Allocations {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO settlement_allocations (
				settlement_id, allocation_order, beneficiary_type,
				beneficiary_id, label, share_numerator, share_denominator,
				network_pool_allocation_minor,
				indicative_value_allocation_minor
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			record.SettlementID,
			index,
			allocation.BeneficiaryType,
			allocation.BeneficiaryID,
			allocation.Label,
			allocation.ShareNumerator,
			allocation.ShareDenominator,
			allocation.NetworkPoolAllocationMinor,
			allocation.IndicativeValueAllocationMinor,
		); err != nil {
			return fmt.Errorf("persist settlement allocation: %w", err)
		}
	}
	return nil
}

func (sqliteStore *Store) Settlement(
	ctx context.Context,
	settlementID string,
) (store.SettlementRecord, error) {
	return settlementByIDQuery(ctx, sqliteStore.db, settlementID)
}

type settlementQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func settlementByIDQuery(
	ctx context.Context,
	queryer settlementQueryer,
	settlementID string,
) (store.SettlementRecord, error) {
	var record store.SettlementRecord
	var entry protocol.LedgerEntry
	err := queryer.QueryRowContext(ctx, `
		SELECT
			s.settlement_id, s.period, s.currency_code, s.fraction_digits,
			s.revision, COALESCE(s.supersedes_settlement_id, ''),
			s.ruleset_version, s.valuation_ruleset_version,
			s.commission_rate_basis_points,
			s.base_valuation_multiplier_basis_points,
			s.recent_three_month_average_minor,
			s.prior_three_month_average_minor,
			s.earlier_three_month_average_minor,
			s.recent_growth_basis_points, s.prior_growth_basis_points,
			s.acceleration_basis_points,
			s.valuation_adjustment_basis_points,
			s.effective_valuation_multiplier_basis_points,
			s.commission_basis_minor, s.network_commission_pool_minor,
			s.ttm_commission_basis_minor,
			s.ttm_network_commission_pool_minor,
			s.indicative_network_value_minor, s.through_ledger_index,
			s.through_audit_index, s.through_review_index,
			s.through_eligibility_index, s.ledger_head_hash,
			s.audit_head_hash, s.review_head_hash, s.eligibility_head_hash,
			s.source_fingerprint, s.allocation_hash, s.settlement_hash,
			s.accepted_at, s.registry_key_id, s.receipt_signature,
			l.protocol_version, l.registry_scope, l.ledger_index,
			l.entry_type, l.deployment_id, l.batch_id, l.kind, l.period,
			l.ruleset_version, l.qualified_mau_count, l.batch_hash,
			l.previous_entry_hash, l.entry_hash, l.accepted_at
		FROM settlements s
		JOIN ledger_entries l ON l.ledger_index = s.ledger_index
		WHERE s.settlement_id = ?`,
		settlementID,
	).Scan(
		&record.SettlementID,
		&record.Period,
		&record.CurrencyCode,
		&record.FractionDigits,
		&record.Revision,
		&record.SupersedesSettlementID,
		&record.RulesetVersion,
		&record.ValuationRulesetVersion,
		&record.CommissionRateBasisPoints,
		&record.BaseValuationMultiplierBasisPoints,
		&record.RecentThreeMonthAverageMinor,
		&record.PriorThreeMonthAverageMinor,
		&record.EarlierThreeMonthAverageMinor,
		&record.RecentGrowthBasisPoints,
		&record.PriorGrowthBasisPoints,
		&record.AccelerationBasisPoints,
		&record.ValuationAdjustmentBasisPoints,
		&record.EffectiveValuationMultiplierBasisPoints,
		&record.CommissionBasisMinor,
		&record.NetworkCommissionPoolMinor,
		&record.TTMCommissionBasisMinor,
		&record.TTMNetworkCommissionPoolMinor,
		&record.IndicativeNetworkValueMinor,
		&record.ThroughLedgerIndex,
		&record.ThroughAuditIndex,
		&record.ThroughReviewIndex,
		&record.ThroughEligibilityIndex,
		&record.LedgerHeadHash,
		&record.AuditHeadHash,
		&record.ReviewHeadHash,
		&record.EligibilityHeadHash,
		&record.SourceFingerprint,
		&record.AllocationHash,
		&record.SettlementHash,
		&record.AcceptedAt,
		&record.RegistryKeyID,
		&record.ReceiptSignature,
		&entry.ProtocolVersion,
		&entry.RegistryScope,
		&entry.LedgerIndex,
		&entry.EntryType,
		&entry.DeploymentID,
		&entry.BatchID,
		&entry.Kind,
		&entry.Period,
		&entry.RulesetVersion,
		&entry.QualifiedMAUCount,
		&entry.BatchHash,
		&entry.PreviousEntryHash,
		&entry.EntryHash,
		&entry.AcceptedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return store.SettlementRecord{}, store.ErrNotFound
	}
	if err != nil {
		return store.SettlementRecord{}, fmt.Errorf("read settlement: %w", err)
	}
	record.LedgerEntry = entry
	record.Allocations, err = settlementAllocationsQuery(
		ctx,
		queryer,
		settlementID,
	)
	if err != nil {
		return store.SettlementRecord{}, err
	}
	record.RevenueSources, err = settlementRevenueSourcesQuery(
		ctx,
		queryer,
		settlementID,
	)
	if err != nil {
		return store.SettlementRecord{}, err
	}
	record.TTMMonths, err = settlementTTMMonthsQuery(ctx, queryer, settlementID)
	if err != nil {
		return store.SettlementRecord{}, err
	}
	record.WeightSources, err = settlementWeightSourcesQuery(
		ctx,
		queryer,
		settlementID,
	)
	if err != nil {
		return store.SettlementRecord{}, err
	}
	record.BeneficiaryDeployments, err = settlementMembersQuery(
		ctx,
		queryer,
		settlementID,
	)
	return record, err
}

func settlementAllocationsQuery(
	ctx context.Context,
	queryer settlementQueryer,
	settlementID string,
) ([]protocol.SettlementAllocation, error) {
	rows, err := queryer.QueryContext(ctx, `
		SELECT
			beneficiary_type, beneficiary_id, label, share_numerator,
			share_denominator, network_pool_allocation_minor,
			indicative_value_allocation_minor
		FROM settlement_allocations
		WHERE settlement_id = ?
		ORDER BY allocation_order`,
		settlementID,
	)
	if err != nil {
		return nil, fmt.Errorf("read settlement allocations: %w", err)
	}
	defer rows.Close()
	items := make([]protocol.SettlementAllocation, 0)
	for rows.Next() {
		var item protocol.SettlementAllocation
		if err := rows.Scan(
			&item.BeneficiaryType,
			&item.BeneficiaryID,
			&item.Label,
			&item.ShareNumerator,
			&item.ShareDenominator,
			&item.NetworkPoolAllocationMinor,
			&item.IndicativeValueAllocationMinor,
		); err != nil {
			return nil, fmt.Errorf("scan settlement allocation: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate settlement allocations: %w", err)
	}
	return items, nil
}

func settlementRevenueSourcesQuery(
	ctx context.Context,
	queryer settlementQueryer,
	settlementID string,
) ([]store.SettlementRevenueSource, error) {
	rows, err := queryer.QueryContext(ctx, `
		SELECT
			source_order, revenue_period, deployment_id, batch_id,
			ledger_index, source_entry_hash, commission_basis_minor
		FROM settlement_revenue_sources
		WHERE settlement_id = ?
		ORDER BY source_order`,
		settlementID,
	)
	if err != nil {
		return nil, fmt.Errorf("read persisted settlement revenue sources: %w", err)
	}
	defer rows.Close()
	items := make([]store.SettlementRevenueSource, 0)
	for rows.Next() {
		var item store.SettlementRevenueSource
		if err := rows.Scan(
			&item.SourceOrder,
			&item.RevenuePeriod,
			&item.DeploymentID,
			&item.BatchID,
			&item.LedgerIndex,
			&item.EntryHash,
			&item.CommissionBasisMinor,
		); err != nil {
			return nil, fmt.Errorf("scan persisted settlement revenue source: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate persisted settlement revenue sources: %w", err)
	}
	return items, nil
}

func settlementTTMMonthsQuery(
	ctx context.Context,
	queryer settlementQueryer,
	settlementID string,
) ([]store.SettlementTTMMonth, error) {
	rows, err := queryer.QueryContext(ctx, `
		SELECT period, commission_basis_minor, network_commission_pool_minor
		FROM settlement_ttm_months
		WHERE settlement_id = ?
		ORDER BY period`,
		settlementID,
	)
	if err != nil {
		return nil, fmt.Errorf("read settlement TTM months: %w", err)
	}
	defer rows.Close()
	items := make([]store.SettlementTTMMonth, 0, 12)
	for rows.Next() {
		var item store.SettlementTTMMonth
		if err := rows.Scan(
			&item.Period,
			&item.CommissionBasisMinor,
			&item.NetworkCommissionPoolMinor,
		); err != nil {
			return nil, fmt.Errorf("scan settlement TTM month: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate settlement TTM months: %w", err)
	}
	return items, nil
}

func settlementWeightSourcesQuery(
	ctx context.Context,
	queryer settlementQueryer,
	settlementID string,
) ([]store.SettlementWeightSource, error) {
	rows, err := queryer.QueryContext(ctx, `
		SELECT beneficiary_id, label, weight
		FROM settlement_weight_sources
		WHERE settlement_id = ?
		ORDER BY beneficiary_id`,
		settlementID,
	)
	if err != nil {
		return nil, fmt.Errorf("read settlement weight sources: %w", err)
	}
	defer rows.Close()
	items := make([]store.SettlementWeightSource, 0)
	for rows.Next() {
		var item store.SettlementWeightSource
		if err := rows.Scan(
			&item.BeneficiaryID,
			&item.Label,
			&item.Weight,
		); err != nil {
			return nil, fmt.Errorf("scan settlement weight source: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate settlement weight sources: %w", err)
	}
	return items, nil
}

func settlementMembersQuery(
	ctx context.Context,
	queryer settlementQueryer,
	settlementID string,
) ([]store.SettlementBeneficiaryDeployment, error) {
	rows, err := queryer.QueryContext(ctx, `
		SELECT beneficiary_id, deployment_id
		FROM settlement_beneficiary_deployments
		WHERE settlement_id = ?
		ORDER BY beneficiary_id, deployment_id`,
		settlementID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read settlement beneficiary deployments: %w",
			err,
		)
	}
	defer rows.Close()
	items := make([]store.SettlementBeneficiaryDeployment, 0)
	for rows.Next() {
		var item store.SettlementBeneficiaryDeployment
		if err := rows.Scan(
			&item.BeneficiaryID,
			&item.DeploymentID,
		); err != nil {
			return nil, fmt.Errorf(
				"scan settlement beneficiary deployment: %w",
				err,
			)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate settlement beneficiary deployments: %w",
			err,
		)
	}
	return items, nil
}

func settlementReceipt(
	record store.SettlementRecord,
	registryScope string,
) protocol.SettlementReceipt {
	entry := record.LedgerEntry
	return protocol.SettlementReceipt{
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
		RegistryScope:                      registryScope,
		RegistryKeyID:                      record.RegistryKeyID,
		Allocations:                        append([]protocol.SettlementAllocation(nil), record.Allocations...),
	}
}

func (sqliteStore *Store) SettlementHistory(
	ctx context.Context,
	query store.SettlementHistoryQuery,
) (store.SettlementHistoryPage, error) {
	filters := []string{"1 = 1"}
	arguments := make([]any, 0)
	if query.Period != "" {
		filters = append(filters, "settlement.period = ?")
		arguments = append(arguments, query.Period)
	}
	if query.CurrencyCode != "" {
		filters = append(filters, "settlement.currency_code = ?")
		arguments = append(arguments, query.CurrencyCode)
	}
	if query.FromPeriod != "" {
		filters = append(filters, "settlement.period >= ?")
		arguments = append(arguments, query.FromPeriod)
	}
	if query.ThroughPeriod != "" {
		filters = append(filters, "settlement.period <= ?")
		arguments = append(arguments, query.ThroughPeriod)
	}
	if !query.IncludeSuperseded {
		filters = append(filters, `
			NOT EXISTS (
				SELECT 1
				FROM settlements newer
				WHERE newer.period = settlement.period
				  AND newer.currency_code = settlement.currency_code
				  AND newer.revision > settlement.revision
			)`)
	}
	if query.DeploymentID != "" {
		filters = append(filters, `
			EXISTS (
				SELECT 1
				FROM settlement_beneficiary_deployments member
				WHERE member.settlement_id = settlement.settlement_id
				  AND member.deployment_id = ?
			)`)
		arguments = append(arguments, query.DeploymentID)
	}
	if query.AfterPeriod != "" {
		filters = append(filters, `
			(
				settlement.period < ?
				OR (
					settlement.period = ?
					AND settlement.settlement_id > ?
				)
			)`)
		arguments = append(
			arguments,
			query.AfterPeriod,
			query.AfterPeriod,
			query.AfterSettlementID,
		)
	}
	arguments = append(arguments, query.Limit+1)
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT settlement.settlement_id
		FROM settlements settlement
		WHERE `+strings.Join(filters, " AND ")+`
		ORDER BY settlement.period DESC, settlement.settlement_id
		LIMIT ?`,
		arguments...,
	)
	if err != nil {
		return store.SettlementHistoryPage{}, fmt.Errorf(
			"read settlement history IDs: %w",
			err,
		)
	}
	ids := make([]string, 0, query.Limit+1)
	for rows.Next() {
		var settlementID string
		if err := rows.Scan(&settlementID); err != nil {
			rows.Close()
			return store.SettlementHistoryPage{}, fmt.Errorf(
				"scan settlement history ID: %w",
				err,
			)
		}
		ids = append(ids, settlementID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return store.SettlementHistoryPage{}, fmt.Errorf(
			"iterate settlement history IDs: %w",
			err,
		)
	}
	if err := rows.Close(); err != nil {
		return store.SettlementHistoryPage{}, fmt.Errorf(
			"close settlement history IDs: %w",
			err,
		)
	}
	hasMore := len(ids) > query.Limit
	if hasMore {
		ids = ids[:query.Limit]
	}
	page := store.SettlementHistoryPage{
		Items: make([]protocol.SettlementHistoryItem, 0),
	}
	for _, settlementID := range ids {
		record, err := settlementByIDQuery(ctx, sqliteStore.db, settlementID)
		if err != nil {
			return store.SettlementHistoryPage{}, err
		}
		for _, allocation := range record.Allocations {
			if query.DeploymentID != "" &&
				!settlementAllocationContainsDeployment(
					record,
					allocation.BeneficiaryID,
					query.DeploymentID,
				) {
				continue
			}
			page.Items = append(page.Items, protocol.SettlementHistoryItem{
				SettlementID:                      record.SettlementID,
				Period:                            record.Period,
				CurrencyCode:                      record.CurrencyCode,
				FractionDigits:                    record.FractionDigits,
				Revision:                          record.Revision,
				SupersedesSettlementID:            record.SupersedesSettlementID,
				BeneficiaryType:                   allocation.BeneficiaryType,
				BeneficiaryID:                     allocation.BeneficiaryID,
				ShareNumerator:                    allocation.ShareNumerator,
				ShareDenominator:                  allocation.ShareDenominator,
				NetworkPoolMinor:                  record.NetworkCommissionPoolMinor,
				NetworkPoolAllocationMinor:        allocation.NetworkPoolAllocationMinor,
				TTMCommissionBasisMinor:           record.TTMCommissionBasisMinor,
				TTMNetworkCommissionPoolMinor:     record.TTMNetworkCommissionPoolMinor,
				IndicativeNetworkValueMinor:       record.IndicativeNetworkValueMinor,
				IndicativeValueAllocationMinor:    allocation.IndicativeValueAllocationMinor,
				ValuationRulesetVersion:           record.ValuationRulesetVersion,
				BaseValuationMultiplierBasisPoints: record.BaseValuationMultiplierBasisPoints,
				RecentThreeMonthAverageMinor:      record.RecentThreeMonthAverageMinor,
				PriorThreeMonthAverageMinor:       record.PriorThreeMonthAverageMinor,
				EarlierThreeMonthAverageMinor:     record.EarlierThreeMonthAverageMinor,
				RecentGrowthBasisPoints:           record.RecentGrowthBasisPoints,
				PriorGrowthBasisPoints:            record.PriorGrowthBasisPoints,
				AccelerationBasisPoints:           record.AccelerationBasisPoints,
				ValuationAdjustmentBasisPoints:    record.ValuationAdjustmentBasisPoints,
				EffectiveValuationMultiplierBasisPoints: record.EffectiveValuationMultiplierBasisPoints,
				ValuationIsNonBinding:             true,
				ThroughLedgerIndex:                record.ThroughLedgerIndex,
				ThroughAuditIndex:                 record.ThroughAuditIndex,
				ThroughReviewIndex:                record.ThroughReviewIndex,
				ThroughEligibilityIndex:           record.ThroughEligibilityIndex,
				SourceFingerprint:                 record.SourceFingerprint,
				SettlementHash:                    record.SettlementHash,
				AcceptedAt:                        record.AcceptedAt,
			})
		}
	}
	if hasMore && len(ids) > 0 {
		last, err := settlementByIDQuery(
			ctx,
			sqliteStore.db,
			ids[len(ids)-1],
		)
		if err != nil {
			return store.SettlementHistoryPage{}, err
		}
		page.NextAfterPeriod = last.Period
		page.NextAfterSettlementID = last.SettlementID
	}
	return page, nil
}

func settlementAllocationContainsDeployment(
	record store.SettlementRecord,
	beneficiaryID string,
	deploymentID string,
) bool {
	for _, member := range record.BeneficiaryDeployments {
		if member.BeneficiaryID == beneficiaryID &&
			member.DeploymentID == deploymentID {
			return true
		}
	}
	return false
}
