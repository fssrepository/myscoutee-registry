package sqlite

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func (sqliteStore *Store) VerifySettlements(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	tx, err := sqliteStore.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return inconsistent("begin settlement verification", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `
		SELECT settlement_id
		FROM settlements
		ORDER BY ledger_index`)
	if err != nil {
		return inconsistent("read settlements for verification", err)
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return inconsistent("scan settlement ID for verification", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return inconsistent("iterate settlement IDs for verification", err)
	}
	if err := rows.Close(); err != nil {
		return inconsistent("close settlement IDs for verification", err)
	}
	type revisionState struct {
		revision     int64
		settlementID string
	}
	revisions := make(map[string]revisionState)
	for _, id := range ids {
		record, err := settlementByIDQuery(ctx, tx, id)
		if err != nil {
			return inconsistent("read settlement for verification", err)
		}
		if err := sqliteStore.verifySettlementRecordTx(
			ctx,
			tx,
			record,
			registryPublicKey,
			registryKeyID,
			registryScope,
		); err != nil {
			return err
		}
		key := record.Period + "\x00" + record.CurrencyCode
		previous := revisions[key]
		if record.Revision != previous.revision+1 ||
			(record.Revision == 1 && record.SupersedesSettlementID != "") ||
			(record.Revision > 1 &&
				record.SupersedesSettlementID != previous.settlementID) {
			return inconsistentMessage(
				"settlement %s has an invalid revision chain",
				record.SettlementID,
			)
		}
		revisions[key] = revisionState{
			revision:     record.Revision,
			settlementID: record.SettlementID,
		}
	}
	var ledgerCount int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM ledger_entries
		WHERE entry_type = ?`,
		protocol.SettlementEntryType,
	).Scan(&ledgerCount); err != nil {
		return inconsistent("count settlement ledger entries", err)
	}
	if ledgerCount != len(ids) {
		return inconsistentMessage(
			"settlement ledger/source cardinality mismatch: %d ledger entries and %d settlements",
			ledgerCount,
			len(ids),
		)
	}
	if err := tx.Commit(); err != nil {
		return inconsistent("finish settlement verification", err)
	}
	return nil
}

func (sqliteStore *Store) verifySettlementRecordTx(
	ctx context.Context,
	tx *sql.Tx,
	record store.SettlementRecord,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	entry := record.LedgerEntry
	fractionDigits, supported := protocol.ISO4217FractionDigits(record.CurrencyCode)
	if !validHexID(record.SettlementID, "stl_", 32) ||
		!validSettlementPeriod(record.Period) ||
		!supported ||
		fractionDigits != record.FractionDigits ||
		record.RulesetVersion != protocol.SettlementRulesetVersion ||
		record.ValuationRulesetVersion != protocol.SettlementValuationRulesetVersion ||
		record.CommissionRateBasisPoints != protocol.RevenueCommissionBasisPoints ||
		record.BaseValuationMultiplierBasisPoints <
			protocol.SettlementMinimumBaseValuationMultiplierBasisPoints ||
		record.BaseValuationMultiplierBasisPoints >
			protocol.SettlementMaximumBaseValuationMultiplierBasisPoints ||
		record.RegistryKeyID != registryKeyID ||
		!validPersistedTimestamp(record.AcceptedAt) ||
		entry.ProtocolVersion != protocol.Version ||
		entry.RegistryScope != registryScope ||
		entry.EntryType != protocol.SettlementEntryType ||
		entry.DeploymentID != "" ||
		entry.BatchID != record.SettlementID ||
		entry.Kind != protocol.SettlementKind ||
		entry.Period != record.Period ||
		entry.RulesetVersion != protocol.SettlementRulesetVersion ||
		entry.QualifiedMAUCount != 0 ||
		entry.BatchHash != record.SettlementHash ||
		entry.AcceptedAt != record.AcceptedAt {
		return inconsistentMessage(
			"settlement %s has invalid protocol or ledger metadata",
			record.SettlementID,
		)
	}
	if !settlementRecordHasSafeMinorAmounts(record) {
		return inconsistentMessage(
			"settlement %s exceeds the protocol safe-integer money boundary",
			record.SettlementID,
		)
	}
	if record.AllocationHash != protocol.SettlementAllocationHash(record.Allocations) ||
		record.SourceFingerprint != settlementSourceFingerprint(record) {
		return inconsistentMessage(
			"settlement %s source or allocation hash verification failed",
			record.SettlementID,
		)
	}
	var allocatedPool, allocatedValue int64
	for _, allocation := range record.Allocations {
		var ok bool
		allocatedPool, ok = checkedRevenueAdd(
			allocatedPool,
			allocation.NetworkPoolAllocationMinor,
		)
		if !ok {
			return inconsistentMessage(
				"settlement %s pool allocation total overflows",
				record.SettlementID,
			)
		}
		allocatedValue, ok = checkedRevenueAdd(
			allocatedValue,
			allocation.IndicativeValueAllocationMinor,
		)
		if !ok {
			return inconsistentMessage(
				"settlement %s value allocation total overflows",
				record.SettlementID,
			)
		}
	}
	if allocatedPool != record.NetworkCommissionPoolMinor ||
		allocatedValue != record.IndicativeNetworkValueMinor {
		return inconsistentMessage(
			"settlement %s allocations do not conserve their signed totals",
			record.SettlementID,
		)
	}
	receipt := settlementReceipt(record, registryScope)
	expectedSettlementHash := protocol.Digest(
		protocol.SettlementHashMessage(receipt),
	)
	if record.SettlementHash != expectedSettlementHash ||
		!ed25519.Verify(
			registryPublicKey,
			protocol.SettlementReceiptMessage(receipt),
			record.ReceiptSignature,
		) {
		return inconsistentMessage(
			"settlement %s registry proof verification failed",
			record.SettlementID,
		)
	}

	var sourceLedgerIndex int64
	var sourceLedgerHash string
	err := tx.QueryRowContext(ctx, `
		SELECT ledger_index, entry_hash
		FROM ledger_entries
		WHERE entry_type <> ? AND ledger_index < ?
		ORDER BY ledger_index DESC
		LIMIT 1`,
		protocol.SettlementEntryType,
		entry.LedgerIndex,
	).Scan(&sourceLedgerIndex, &sourceLedgerHash)
	if errors.Is(err, sql.ErrNoRows) {
		sourceLedgerHash = protocol.ZeroHash
	} else if err != nil {
		return inconsistent("read settlement pinned ledger boundary", err)
	}
	if sourceLedgerIndex != record.ThroughLedgerIndex ||
		sourceLedgerHash != record.LedgerHeadHash {
		return inconsistentMessage(
			"settlement %s ledger source boundary is invalid",
			record.SettlementID,
		)
	}
	if err := verifySettlementChainHash(
		ctx,
		tx,
		"operator_audit_events",
		"audit_index",
		"audit_hash",
		record.ThroughAuditIndex,
		record.AuditHeadHash,
		protocol.OperatorAuditZeroHash,
	); err != nil {
		return err
	}
	if err := verifySettlementChainHash(
		ctx,
		tx,
		"operator_claim_reviews",
		"review_index",
		"review_hash",
		record.ThroughReviewIndex,
		record.ReviewHeadHash,
		protocol.OperatorClaimReviewZeroHash,
	); err != nil {
		return err
	}
	if err := verifySettlementChainHash(
		ctx,
		tx,
		"operator_claim_eligibility_events",
		"eligibility_index",
		"eligibility_hash",
		record.ThroughEligibilityIndex,
		record.EligibilityHeadHash,
		protocol.OperatorClaimEligibilityZeroHash,
	); err != nil {
		return err
	}

	periodStart, _ := time.Parse("2006-01", record.Period)
	expectedRevenue, err := settlementRevenueSourcesTx(
		ctx,
		tx,
		record.CurrencyCode,
		periodStart.AddDate(0, -11, 0).Format("2006-01-02"),
		periodStart.AddDate(0, 1, 0).Format("2006-01-02"),
		record.ThroughLedgerIndex,
	)
	if err != nil {
		return err
	}
	transferHead, err := ownershipTransferEventHeadAt(
		ctx,
		tx,
		record.AcceptedAt,
	)
	if err != nil {
		return err
	}
	expectedWeights, expectedMembers, measuredWeight, err :=
		settlementWeightSourcesTx(
			ctx,
			tx,
			periodStart.AddDate(0, -5, 0).Format("2006-01"),
			record.Period,
			store.LeaderboardBoundary{
				LedgerIndex:        record.ThroughLedgerIndex,
				AuditIndex:         record.ThroughAuditIndex,
				ReviewIndex:        record.ThroughReviewIndex,
				EligibilityIndex:   record.ThroughEligibilityIndex,
				TransferEventIndex: transferHead.EventIndex,
			},
			record.AcceptedAt[:len("2006-01-02")],
		)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(record.RevenueSources, expectedRevenue) ||
		!reflect.DeepEqual(record.WeightSources, expectedWeights) ||
		!reflect.DeepEqual(record.BeneficiaryDeployments, expectedMembers) {
		return inconsistentMessage(
			"settlement %s direct source rows do not match the pinned registry state",
			record.SettlementID,
		)
	}
	expected, err := recomputeSettlementDerived(record, measuredWeight)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(record.TTMMonths, expected.TTMMonths) ||
		record.CommissionBasisMinor != expected.CommissionBasisMinor ||
		record.NetworkCommissionPoolMinor != expected.NetworkCommissionPoolMinor ||
		record.TTMCommissionBasisMinor != expected.TTMCommissionBasisMinor ||
		record.TTMNetworkCommissionPoolMinor != expected.TTMNetworkCommissionPoolMinor ||
		record.RecentThreeMonthAverageMinor != expected.RecentThreeMonthAverageMinor ||
		record.PriorThreeMonthAverageMinor != expected.PriorThreeMonthAverageMinor ||
		record.EarlierThreeMonthAverageMinor != expected.EarlierThreeMonthAverageMinor ||
		record.RecentGrowthBasisPoints != expected.RecentGrowthBasisPoints ||
		record.PriorGrowthBasisPoints != expected.PriorGrowthBasisPoints ||
		record.AccelerationBasisPoints != expected.AccelerationBasisPoints ||
		record.ValuationAdjustmentBasisPoints != expected.ValuationAdjustmentBasisPoints ||
		record.EffectiveValuationMultiplierBasisPoints != expected.EffectiveValuationMultiplierBasisPoints ||
		record.IndicativeNetworkValueMinor != expected.IndicativeNetworkValueMinor ||
		!reflect.DeepEqual(record.Allocations, expected.Allocations) {
		return inconsistentMessage(
			"settlement %s derived values do not match its pinned sources",
			record.SettlementID,
		)
	}
	return nil
}

func validSettlementPeriod(value string) bool {
	parsed, err := time.Parse("2006-01", value)
	return err == nil && parsed.Format("2006-01") == value
}

func verifySettlementChainHash(
	ctx context.Context,
	tx *sql.Tx,
	table string,
	indexColumn string,
	hashColumn string,
	index int64,
	hash string,
	zeroHash string,
) error {
	if index == 0 {
		if hash != zeroHash {
			return inconsistentMessage(
				"settlement source boundary %s has an invalid zero hash",
				table,
			)
		}
		return nil
	}
	var persisted string
	statement := fmt.Sprintf(
		"SELECT %s FROM %s WHERE %s = ?",
		hashColumn,
		table,
		indexColumn,
	)
	if err := tx.QueryRowContext(ctx, statement, index).Scan(&persisted); err != nil {
		return inconsistent("read settlement chain source boundary", err)
	}
	if persisted != hash {
		return inconsistentMessage(
			"settlement source boundary %s hash is invalid",
			table,
		)
	}
	return nil
}

func recomputeSettlementDerived(
	record store.SettlementRecord,
	measuredWeight int64,
) (store.SettlementRecord, error) {
	monthlyBasis := make(map[string]int64, 12)
	for _, source := range record.RevenueSources {
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
	periodStart, _ := time.Parse("2006-01", record.Period)
	ttmStart := periodStart.AddDate(0, -11, 0)
	var ttmBasis int64
	record.TTMMonths = make([]store.SettlementTTMMonth, 0, 12)
	for offset := 0; offset < 12; offset++ {
		month := ttmStart.AddDate(0, offset, 0).Format("2006-01")
		basis := monthlyBasis[month]
		pool := protocol.RevenueCommissionMinor(basis)
		var ok bool
		ttmBasis, ok = checkedRevenueAdd(ttmBasis, basis)
		if !ok {
			return store.SettlementRecord{}, store.ErrRevenueAggregateOverflow
		}
		record.TTMMonths = append(record.TTMMonths, store.SettlementTTMMonth{
			Period:                     month,
			CommissionBasisMinor:       basis,
			NetworkCommissionPoolMinor: pool,
		})
	}
	record.CommissionBasisMinor = monthlyBasis[record.Period]
	record.NetworkCommissionPoolMinor = protocol.RevenueCommissionMinor(
		record.CommissionBasisMinor,
	)
	record.TTMCommissionBasisMinor = ttmBasis
	record.TTMNetworkCommissionPoolMinor = protocol.RevenueCommissionMinor(
		ttmBasis,
	)
	earlier, prior, recent := settlementThreeMonthAverages(record.TTMMonths)
	record.EarlierThreeMonthAverageMinor = earlier
	record.PriorThreeMonthAverageMinor = prior
	record.RecentThreeMonthAverageMinor = recent
	record.PriorGrowthBasisPoints = settlementGrowthBasisPoints(earlier, prior)
	record.RecentGrowthBasisPoints = settlementGrowthBasisPoints(prior, recent)
	record.AccelerationBasisPoints = clampInt64(
		record.RecentGrowthBasisPoints-record.PriorGrowthBasisPoints,
		protocol.SettlementMinimumAccelerationBasisPoints,
		protocol.SettlementMaximumAccelerationBasisPoints,
	)
	record.ValuationAdjustmentBasisPoints = clampInt64(
		record.RecentGrowthBasisPoints/
			protocol.SettlementAccelerationAdjustmentDivisor+
			record.AccelerationBasisPoints/
				protocol.SettlementAccelerationAdjustmentDivisor,
		protocol.SettlementMinimumValuationAdjustmentBasisPoints,
		protocol.SettlementMaximumValuationAdjustmentBasisPoints,
	)
	var ok bool
	record.EffectiveValuationMultiplierBasisPoints, ok = multiplyBasisPoints(
		record.BaseValuationMultiplierBasisPoints,
		10_000+record.ValuationAdjustmentBasisPoints,
	)
	if !ok {
		return store.SettlementRecord{}, store.ErrRevenueAggregateOverflow
	}
	record.IndicativeNetworkValueMinor, ok = multiplyBasisPoints(
		record.TTMCommissionBasisMinor,
		record.EffectiveValuationMultiplierBasisPoints,
	)
	if !ok {
		return store.SettlementRecord{}, store.ErrRevenueAggregateOverflow
	}
	ratios, err := settlementRatios(record.WeightSources, measuredWeight)
	if err != nil {
		return store.SettlementRecord{}, err
	}
	record.Allocations, err = allocateSettlementAmounts(
		ratios,
		record.NetworkCommissionPoolMinor,
		record.IndicativeNetworkValueMinor,
	)
	return record, err
}
