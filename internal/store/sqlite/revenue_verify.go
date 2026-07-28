package sqlite

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func (sqliteStore *Store) verifyRevenueBatches(
	ctx context.Context,
	deployments map[string]verifiedDeployment,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) (map[string]verifiedRevenueBatch, error) {
	queryRows, err := sqliteStore.loadRevenueQueryRows(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			b.batch_id,
			b.deployment_id,
			b.idempotency_key,
			b.request_timestamp,
			b.request_nonce,
			b.deployment_signature,
			b.kind,
			b.period,
			b.revision,
			COALESCE(b.supersedes_batch_id, ''),
			b.ruleset_version,
			b.commission_rate_basis_points,
			b.currency_count,
			b.payload_hash,
			b.accepted_at,
			b.receipt_signature,
			l.protocol_version,
			l.registry_scope,
			l.ledger_index,
			l.entry_type,
			l.deployment_id,
			l.batch_id,
			l.kind,
			l.period,
			l.ruleset_version,
			l.qualified_mau_count,
			l.batch_hash,
			l.previous_entry_hash,
			l.entry_hash,
			l.accepted_at
		FROM revenue_batches b
		JOIN ledger_entries l ON l.ledger_index = b.ledger_index
		ORDER BY b.deployment_id, b.period, b.revision`)
	if err != nil {
		return nil, inconsistent("read revenue batches for verification", err)
	}
	defer rows.Close()

	verified := make(map[string]verifiedRevenueBatch)
	type chainState struct {
		revision int64
		batchID  string
	}
	chains := make(map[string]chainState)
	for rows.Next() {
		var batch verifiedRevenueBatch
		var ledgerDeploymentID, ledgerBatchID, ledgerKind, ledgerPeriod string
		var ledgerRuleset, ledgerAcceptedAt string
		entry := protocol.LedgerEntry{}
		if err := rows.Scan(
			&batch.record.BatchID,
			&batch.record.DeploymentID,
			&batch.record.IdempotencyKey,
			&batch.requestTimestamp,
			&batch.requestNonce,
			&batch.requestSignature,
			&batch.record.Kind,
			&batch.record.Period,
			&batch.record.Revision,
			&batch.record.SupersedesBatchID,
			&batch.record.RulesetVersion,
			&batch.record.CommissionRateBasisPoints,
			&batch.record.CurrencyCount,
			&batch.record.PayloadHash,
			&batch.record.AcceptedAt,
			&batch.record.ReceiptSignature,
			&entry.ProtocolVersion,
			&entry.RegistryScope,
			&entry.LedgerIndex,
			&entry.EntryType,
			&ledgerDeploymentID,
			&ledgerBatchID,
			&ledgerKind,
			&ledgerPeriod,
			&ledgerRuleset,
			&entry.QualifiedMAUCount,
			&entry.BatchHash,
			&entry.PreviousEntryHash,
			&entry.EntryHash,
			&ledgerAcceptedAt,
		); err != nil {
			return nil, inconsistent("scan revenue batch for verification", err)
		}
		entry.DeploymentID = ledgerDeploymentID
		entry.BatchID = ledgerBatchID
		entry.Kind = ledgerKind
		entry.Period = ledgerPeriod
		entry.RulesetVersion = ledgerRuleset
		entry.AcceptedAt = ledgerAcceptedAt
		batch.record.LedgerEntry = entry

		deployment, ok := deployments[batch.record.DeploymentID]
		if !ok {
			return nil, inconsistentMessage(
				"revenue batch %s references an unknown deployment",
				batch.record.BatchID,
			)
		}
		if !validHexID(batch.record.BatchID, "revbatch_", 32) ||
			entry.ProtocolVersion != protocol.Version ||
			entry.RegistryScope != registryScope ||
			entry.EntryType != protocol.RevenueEntryType ||
			entry.DeploymentID != batch.record.DeploymentID ||
			entry.BatchID != batch.record.BatchID ||
			entry.Kind != batch.record.Kind ||
			entry.Period != batch.record.Period ||
			entry.RulesetVersion != batch.record.RulesetVersion ||
			entry.QualifiedMAUCount != 0 ||
			entry.BatchHash != batch.record.PayloadHash ||
			entry.AcceptedAt != batch.record.AcceptedAt {
			return nil, inconsistentMessage(
				"revenue batch %s does not match its ledger entry",
				batch.record.BatchID,
			)
		}
		if batch.record.Kind != protocol.RevenueKind ||
			batch.record.RulesetVersion != protocol.RevenueRulesetVersion ||
			batch.record.CommissionRateBasisPoints != protocol.RevenueCommissionBasisPoints ||
			!validRevenuePeriod(batch.record.Period) ||
			batch.record.Revision < 1 ||
			batch.record.CurrencyCount < 0 ||
			batch.record.CurrencyCount > protocol.MaximumRevenueCurrencyRows {
			return nil, inconsistentMessage(
				"revenue batch %s has invalid protocol metadata",
				batch.record.BatchID,
			)
		}
		chainKey := batch.record.DeploymentID + "\x00" + batch.record.Period
		previous := chains[chainKey]
		if batch.record.Revision != previous.revision+1 {
			return nil, inconsistentMessage(
				"revenue batch %s has a non-monotonic revision",
				batch.record.BatchID,
			)
		}
		if batch.record.Revision == 1 {
			if batch.record.SupersedesBatchID != "" {
				return nil, inconsistentMessage(
					"initial revenue batch %s supersedes another batch",
					batch.record.BatchID,
				)
			}
		} else if batch.record.SupersedesBatchID != previous.batchID {
			return nil, inconsistentMessage(
				"revenue batch %s does not supersede the active prior revision",
				batch.record.BatchID,
			)
		}
		chains[chainKey] = chainState{
			revision: batch.record.Revision,
			batchID:  batch.record.BatchID,
		}

		currencies, err := sqliteStore.verifyRevenueQueryRows(
			batch.record,
			queryRows[batch.record.BatchID],
		)
		if err != nil {
			return nil, err
		}
		batch.record.Currencies = currencies
		if int64(len(currencies)) != batch.record.CurrencyCount {
			return nil, inconsistentMessage(
				"revenue batch %s currency count does not match its query rows",
				batch.record.BatchID,
			)
		}
		expectedPayloadHash := protocol.Digest(protocol.RevenuePayload(
			batch.record.Kind,
			batch.record.Period,
			batch.record.Revision,
			batch.record.SupersedesBatchID,
			batch.record.RulesetVersion,
			batch.record.CommissionRateBasisPoints,
			currencies,
		))
		if batch.record.PayloadHash != expectedPayloadHash {
			return nil, inconsistentMessage(
				"revenue batch %s payload hash verification failed",
				batch.record.BatchID,
			)
		}
		if !validPersistedTimestamp(batch.requestTimestamp) ||
			!validPersistedTimestamp(batch.record.AcceptedAt) {
			return nil, inconsistentMessage(
				"revenue batch %s has an invalid timestamp",
				batch.record.BatchID,
			)
		}
		requestMessage := protocol.CanonicalRequest(
			"POST",
			protocol.RevenueBatchPath,
			protocol.Version,
			registryScope,
			batch.record.DeploymentID,
			batch.requestTimestamp,
			batch.requestNonce,
			batch.record.IdempotencyKey,
			batch.record.PayloadHash,
		)
		if !ed25519.Verify(
			deployment.publicKey,
			requestMessage,
			batch.requestSignature,
		) {
			return nil, inconsistentMessage(
				"revenue batch %s deployment proof verification failed",
				batch.record.BatchID,
			)
		}
		receiptMessage := protocol.RevenueReceiptMessage(
			protocol.Version,
			registryScope,
			batch.record.BatchID,
			batch.record.DeploymentID,
			entry.LedgerIndex,
			entry.EntryHash,
			entry.PreviousEntryHash,
			entry.BatchHash,
			batch.record.Kind,
			batch.record.Period,
			batch.record.Revision,
			batch.record.SupersedesBatchID,
			batch.record.RulesetVersion,
			batch.record.CommissionRateBasisPoints,
			batch.record.CurrencyCount,
			batch.record.AcceptedAt,
			batch.record.AcceptedAt[:len("2006-01-02")],
			registryKeyID,
		)
		if !ed25519.Verify(
			registryPublicKey,
			receiptMessage,
			batch.record.ReceiptSignature,
		) {
			return nil, inconsistentMessage(
				"revenue batch %s central receipt verification failed",
				batch.record.BatchID,
			)
		}
		verified[batch.record.BatchID] = batch
		delete(queryRows, batch.record.BatchID)
	}
	if err := rows.Err(); err != nil {
		return nil, inconsistent("iterate revenue batches for verification", err)
	}
	if err := rows.Close(); err != nil {
		return nil, inconsistent("close revenue batch verification rows", err)
	}

	var ledgerCount int
	if err := sqliteStore.db.QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM ledger_entries WHERE entry_type = ?",
		protocol.RevenueEntryType,
	).Scan(&ledgerCount); err != nil {
		return nil, inconsistent("count revenue ledger entries", err)
	}
	if ledgerCount != len(verified) {
		return nil, inconsistentMessage(
			"revenue ledger/batch cardinality mismatch: %d ledger entries and %d batches",
			ledgerCount,
			len(verified),
		)
	}
	if len(queryRows) != 0 {
		return nil, inconsistentMessage(
			"revenue query table contains rows for %d unknown batches",
			len(queryRows),
		)
	}
	if err := sqliteStore.verifyRevenueAggregates(ctx); err != nil {
		return nil, err
	}
	return verified, nil
}

func (sqliteStore *Store) verifyRevenueAggregates(ctx context.Context) error {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			row.period,
			row.currency_code,
			row.fraction_digits,
			row.captured_minor,
			row.refunded_minor,
			row.net_minor,
			row.commission_basis_minor,
			row.estimated_commission_minor,
			row.payment_count
		FROM revenue_query_rows row
		WHERE NOT EXISTS (
			SELECT 1
			FROM revenue_batches newer
			WHERE newer.deployment_id = row.deployment_id
			  AND newer.period = row.period
			  AND newer.revision > row.revision
		)
		ORDER BY row.period, row.currency_code, row.deployment_id`)
	if err != nil {
		return inconsistent("read active revenue aggregates for verification", err)
	}
	defer rows.Close()
	currentKey := ""
	currentFractionDigits := int64(-1)
	totals := [6]int64{}
	for rows.Next() {
		var period, currencyCode string
		var fractionDigits int64
		values := [6]int64{}
		if err := rows.Scan(
			&period,
			&currencyCode,
			&fractionDigits,
			&values[0],
			&values[1],
			&values[2],
			&values[3],
			&values[4],
			&values[5],
		); err != nil {
			return inconsistent("scan active revenue aggregate", err)
		}
		key := period + "\x00" + currencyCode
		if key != currentKey {
			currentKey = key
			currentFractionDigits = fractionDigits
			totals = [6]int64{}
		} else if currentFractionDigits != fractionDigits {
			return inconsistentMessage(
				"active revenue rows for %s/%s disagree on fraction digits",
				period,
				currencyCode,
			)
		}
		for index := range totals {
			next, ok := checkedRevenueAdd(totals[index], values[index])
			if !ok {
				return inconsistentMessage(
					"active revenue aggregate for %s/%s overflows int64",
					period,
					currencyCode,
				)
			}
			totals[index] = next
		}
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate active revenue aggregates", err)
	}
	return nil
}

type persistedRevenueQueryRow struct {
	batchID           string
	index             int64
	ledgerIndex       int64
	deploymentID      string
	period            string
	revision          int64
	supersedesBatchID string
	currency          protocol.RevenueCurrency
	acceptedAt        string
	sourceEntryHash   string
}

func (sqliteStore *Store) loadRevenueQueryRows(
	ctx context.Context,
) (map[string][]persistedRevenueQueryRow, error) {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			batch_id,
			currency_index,
			ledger_index,
			deployment_id,
			period,
			revision,
			supersedes_batch_id,
			currency_code,
			fraction_digits,
			captured_minor,
			refunded_minor,
			net_minor,
			commission_basis_minor,
			estimated_commission_minor,
			payment_count,
			accepted_at,
			source_entry_hash
		FROM revenue_query_rows
		ORDER BY batch_id, currency_index`)
	if err != nil {
		return nil, inconsistent("read revenue query rows for verification", err)
	}
	defer rows.Close()
	records := make(map[string][]persistedRevenueQueryRow)
	for rows.Next() {
		var row persistedRevenueQueryRow
		if err := rows.Scan(
			&row.batchID,
			&row.index,
			&row.ledgerIndex,
			&row.deploymentID,
			&row.period,
			&row.revision,
			&row.supersedesBatchID,
			&row.currency.CurrencyCode,
			&row.currency.FractionDigits,
			&row.currency.CapturedMinor,
			&row.currency.RefundedMinor,
			&row.currency.NetMinor,
			&row.currency.CommissionBasisMinor,
			&row.currency.EstimatedCommissionMinor,
			&row.currency.PaymentCount,
			&row.acceptedAt,
			&row.sourceEntryHash,
		); err != nil {
			return nil, inconsistent("scan revenue query row for verification", err)
		}
		records[row.batchID] = append(records[row.batchID], row)
	}
	if err := rows.Err(); err != nil {
		return nil, inconsistent("iterate revenue query rows for verification", err)
	}
	return records, nil
}

func (sqliteStore *Store) verifyRevenueQueryRows(
	record store.RevenueBatchRecord,
	rows []persistedRevenueQueryRow,
) ([]protocol.RevenueCurrency, error) {
	currencies := make([]protocol.RevenueCurrency, 0, record.CurrencyCount)
	previousCode := ""
	for _, row := range rows {
		if row.index != int64(len(currencies)) ||
			row.ledgerIndex != record.LedgerEntry.LedgerIndex ||
			row.deploymentID != record.DeploymentID ||
			row.period != record.Period ||
			row.revision != record.Revision ||
			row.supersedesBatchID != record.SupersedesBatchID ||
			row.acceptedAt != record.AcceptedAt ||
			row.sourceEntryHash != record.LedgerEntry.EntryHash {
			return nil, inconsistentMessage(
				"revenue batch %s has a mismatched direct query row",
				record.BatchID,
			)
		}
		if row.currency.CurrencyCode <= previousCode ||
			!validRevenueCurrency(row.currency) {
			return nil, inconsistentMessage(
				"revenue batch %s has an invalid currency query row",
				record.BatchID,
			)
		}
		previousCode = row.currency.CurrencyCode
		currencies = append(currencies, row.currency)
	}
	return currencies, nil
}

func validRevenueCurrency(currency protocol.RevenueCurrency) bool {
	fractionDigits, ok := protocol.ISO4217FractionDigits(currency.CurrencyCode)
	return ok &&
		fractionDigits == currency.FractionDigits &&
		currency.CapturedMinor >= 0 &&
		currency.CapturedMinor <= protocol.MaximumRevenueMinor &&
		currency.RefundedMinor >= 0 &&
		currency.RefundedMinor <= currency.CapturedMinor &&
		currency.NetMinor == currency.CapturedMinor-currency.RefundedMinor &&
		currency.NetMinor <= protocol.MaximumRevenueMinor &&
		currency.CommissionBasisMinor == currency.NetMinor &&
		currency.EstimatedCommissionMinor ==
			protocol.RevenueCommissionMinor(currency.CommissionBasisMinor) &&
		currency.PaymentCount >= 0 &&
		currency.PaymentCount <= protocol.MaximumRevenuePaymentCount
}

func validRevenuePeriod(value string) bool {
	if len(value) != len("2006-01-02") {
		return false
	}
	parsed, err := time.Parse("2006-01-02", value)
	return err == nil && parsed.Format("2006-01-02") == value
}
