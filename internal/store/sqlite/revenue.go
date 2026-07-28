package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func (sqliteStore *Store) AcceptRevenueBatch(
	ctx context.Context,
	input store.RevenueBatchInput,
	signReceipt store.RevenueReceiptSigner,
) (store.RevenueBatchRecord, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.RevenueBatchRecord{}, false, fmt.Errorf(
			"begin revenue batch acceptance: %w",
			err,
		)
	}
	defer tx.Rollback()

	nonceUsed, err := nonceState(
		ctx,
		tx,
		input.Signer,
		input.Nonce,
		input.RequestHash,
	)
	if err != nil {
		return store.RevenueBatchRecord{}, false, err
	}
	idempotency, err := readIdempotency(
		ctx,
		tx,
		input.Signer,
		input.IdempotencyKey,
	)
	if err != nil {
		return store.RevenueBatchRecord{}, false, err
	}
	if idempotency != nil {
		if idempotency.PayloadHash != input.PayloadHash {
			return store.RevenueBatchRecord{}, false, store.ErrIdempotencyConflict
		}
		if idempotency.ResultType != "batch" {
			return store.RevenueBatchRecord{}, false, store.ErrInconsistentState
		}
		record, err := revenueBatchRecordByIDTx(
			ctx,
			tx,
			idempotency.ResultID,
		)
		if err != nil {
			return store.RevenueBatchRecord{}, false, err
		}
		if !nonceUsed {
			if err := insertNonce(
				ctx,
				tx,
				revenueBatchNonce(input, record.BatchID),
			); err != nil {
				return store.RevenueBatchRecord{}, false, err
			}
		}
		if err := tx.Commit(); err != nil {
			return store.RevenueBatchRecord{}, false, fmt.Errorf(
				"commit duplicate revenue batch: %w",
				err,
			)
		}
		return record, true, nil
	}
	if nonceUsed {
		return store.RevenueBatchRecord{}, false, store.ErrInconsistentState
	}
	if err := ensureAcceptedAtAfterRegistryCreation(
		ctx,
		tx,
		input.AcceptedAt,
	); err != nil {
		return store.RevenueBatchRecord{}, false, err
	}
	if err := ensureAcceptedAtAfterCheckpoint(ctx, tx, input.AcceptedAt); err != nil {
		return store.RevenueBatchRecord{}, false, err
	}
	if err := ensureRevenueRevision(ctx, tx, input); err != nil {
		return store.RevenueBatchRecord{}, false, err
	}
	if err := ensureRevenueAggregateCapacity(ctx, tx, input); err != nil {
		return store.RevenueBatchRecord{}, false, err
	}

	head, err := ledgerHeadTx(ctx, tx)
	if err != nil {
		return store.RevenueBatchRecord{}, false, err
	}
	if err := ensureAcceptedAtNotBeforeHead(input.AcceptedAt, head.AcceptedAt); err != nil {
		return store.RevenueBatchRecord{}, false, err
	}
	entry := protocol.LedgerEntry{
		ProtocolVersion:   protocol.Version,
		RegistryScope:     input.RegistryScope,
		LedgerIndex:       head.LedgerIndex + 1,
		EntryType:         protocol.RevenueEntryType,
		DeploymentID:      input.DeploymentID,
		BatchID:           input.CandidateBatchID,
		Kind:              input.Kind,
		Period:            input.Period,
		RulesetVersion:    input.RulesetVersion,
		QualifiedMAUCount: 0,
		BatchHash:         input.PayloadHash,
		PreviousEntryHash: head.EntryHash,
		AcceptedAt:        input.AcceptedAt,
	}
	entry.EntryHash = protocol.Digest(protocol.LedgerEntryMessage(entry))
	currencyCount := int64(len(input.Currencies))
	receiptSignature, err := signReceipt(
		entry,
		input,
		currencyCount,
		input.CheckpointDate,
	)
	if err != nil {
		return store.RevenueBatchRecord{}, false, fmt.Errorf(
			"sign revenue batch receipt: %w",
			err,
		)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ledger_entries (
			ledger_index,
			protocol_version,
			registry_scope,
			entry_type,
			deployment_id,
			batch_id,
			kind,
			period,
			ruleset_version,
			qualified_mau_count,
			batch_hash,
			previous_entry_hash,
			entry_hash,
			accepted_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`,
		entry.LedgerIndex,
		entry.ProtocolVersion,
		entry.RegistryScope,
		entry.EntryType,
		entry.DeploymentID,
		entry.BatchID,
		entry.Kind,
		entry.Period,
		entry.RulesetVersion,
		entry.BatchHash,
		entry.PreviousEntryHash,
		entry.EntryHash,
		entry.AcceptedAt,
	); err != nil {
		return store.RevenueBatchRecord{}, false, fmt.Errorf(
			"append revenue ledger entry: %w",
			err,
		)
	}

	var supersedes any
	if input.SupersedesBatchID != "" {
		supersedes = input.SupersedesBatchID
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO revenue_batches (
			batch_id,
			deployment_id,
			idempotency_key,
			request_timestamp,
			request_nonce,
			deployment_signature,
			kind,
			period,
			revision,
			supersedes_batch_id,
			ruleset_version,
			commission_rate_basis_points,
			currency_count,
			payload_hash,
			accepted_at,
			ledger_index,
			receipt_signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		input.CandidateBatchID,
		input.DeploymentID,
		input.IdempotencyKey,
		input.RequestTimestamp,
		input.Nonce,
		input.DeploymentSignature,
		input.Kind,
		input.Period,
		input.Revision,
		supersedes,
		input.RulesetVersion,
		input.CommissionRateBasisPoints,
		currencyCount,
		input.PayloadHash,
		input.AcceptedAt,
		entry.LedgerIndex,
		receiptSignature,
	); err != nil {
		return store.RevenueBatchRecord{}, false, fmt.Errorf(
			"persist accepted revenue batch: %w",
			err,
		)
	}
	for index, currency := range input.Currencies {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO revenue_query_rows (
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
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			input.CandidateBatchID,
			index,
			entry.LedgerIndex,
			input.DeploymentID,
			input.Period,
			input.Revision,
			input.SupersedesBatchID,
			currency.CurrencyCode,
			currency.FractionDigits,
			currency.CapturedMinor,
			currency.RefundedMinor,
			currency.NetMinor,
			currency.CommissionBasisMinor,
			currency.EstimatedCommissionMinor,
			currency.PaymentCount,
			input.AcceptedAt,
			entry.EntryHash,
		); err != nil {
			return store.RevenueBatchRecord{}, false, fmt.Errorf(
				"append revenue query row %d: %w",
				index,
				err,
			)
		}
	}
	if err := insertNonce(
		ctx,
		tx,
		revenueBatchNonce(input, input.CandidateBatchID),
	); err != nil {
		return store.RevenueBatchRecord{}, false, err
	}
	if err := insertIdempotency(
		ctx,
		tx,
		input.Signer,
		input.IdempotencyKey,
		input.PayloadHash,
		"batch",
		input.CandidateBatchID,
		input.AcceptedAt,
	); err != nil {
		return store.RevenueBatchRecord{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return store.RevenueBatchRecord{}, false, fmt.Errorf(
			"commit revenue batch acceptance: %w",
			err,
		)
	}
	return store.RevenueBatchRecord{
		BatchID:                   input.CandidateBatchID,
		DeploymentID:              input.DeploymentID,
		IdempotencyKey:            input.IdempotencyKey,
		Kind:                      input.Kind,
		Period:                    input.Period,
		Revision:                  input.Revision,
		SupersedesBatchID:         input.SupersedesBatchID,
		RulesetVersion:            input.RulesetVersion,
		CommissionRateBasisPoints: input.CommissionRateBasisPoints,
		CurrencyCount:             currencyCount,
		Currencies:                cloneRevenueCurrencies(input.Currencies),
		PayloadHash:               input.PayloadHash,
		AcceptedAt:                 input.AcceptedAt,
		LedgerEntry:               entry,
		ReceiptSignature:           append([]byte(nil), receiptSignature...),
	}, false, nil
}

func ensureRevenueAggregateCapacity(
	ctx context.Context,
	tx *sql.Tx,
	input store.RevenueBatchInput,
) error {
	for _, incoming := range input.Currencies {
		rows, err := tx.QueryContext(ctx, `
			SELECT
				row.fraction_digits,
				row.captured_minor,
				row.refunded_minor,
				row.net_minor,
				row.commission_basis_minor,
				row.estimated_commission_minor,
				row.payment_count
			FROM revenue_query_rows row
			WHERE row.period = ?
			  AND row.currency_code = ?
			  AND row.deployment_id <> ?
			  AND NOT EXISTS (
				SELECT 1
				FROM revenue_batches newer
				WHERE newer.deployment_id = row.deployment_id
				  AND newer.period = row.period
				  AND newer.revision > row.revision
			  )`,
			input.Period,
			incoming.CurrencyCode,
			input.DeploymentID,
		)
		if err != nil {
			return fmt.Errorf("read active revenue aggregate rows: %w", err)
		}
		totals := [6]int64{}
		for rows.Next() {
			var fractionDigits int64
			values := [6]int64{}
			if err := rows.Scan(
				&fractionDigits,
				&values[0],
				&values[1],
				&values[2],
				&values[3],
				&values[4],
				&values[5],
			); err != nil {
				rows.Close()
				return fmt.Errorf("scan active revenue aggregate row: %w", err)
			}
			if fractionDigits != incoming.FractionDigits {
				rows.Close()
				return store.ErrInconsistentState
			}
			for index := range totals {
				next, ok := checkedRevenueAdd(totals[index], values[index])
				if !ok {
					rows.Close()
					return store.ErrInconsistentState
				}
				totals[index] = next
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate active revenue aggregate rows: %w", err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close active revenue aggregate rows: %w", err)
		}
		incomingValues := [6]int64{
			incoming.CapturedMinor,
			incoming.RefundedMinor,
			incoming.NetMinor,
			incoming.CommissionBasisMinor,
			incoming.EstimatedCommissionMinor,
			incoming.PaymentCount,
		}
		for index := range totals {
			if _, ok := checkedRevenueAdd(totals[index], incomingValues[index]); !ok {
				return store.ErrRevenueAggregateOverflow
			}
		}
	}
	return nil
}

func checkedRevenueAdd(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || right > int64(^uint64(0)>>1)-left {
		return 0, false
	}
	return left + right, true
}

func ensureRevenueRevision(
	ctx context.Context,
	tx *sql.Tx,
	input store.RevenueBatchInput,
) error {
	var latestBatchID string
	var latestRevision int64
	err := tx.QueryRowContext(ctx, `
		SELECT batch_id, revision
		FROM revenue_batches
		WHERE deployment_id = ? AND period = ?
		ORDER BY revision DESC
		LIMIT 1`,
		input.DeploymentID,
		input.Period,
	).Scan(&latestBatchID, &latestRevision)
	if errors.Is(err, sql.ErrNoRows) {
		if input.Revision != 1 || input.SupersedesBatchID != "" {
			return store.ErrRevenueRevisionConflict
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read current revenue revision: %w", err)
	}
	if input.Revision != latestRevision+1 ||
		input.SupersedesBatchID != latestBatchID {
		return store.ErrRevenueRevisionConflict
	}
	return nil
}

func revenueBatchNonce(
	input store.RevenueBatchInput,
	batchID string,
) acceptedNonce {
	return acceptedNonce{
		Signer:           input.Signer,
		Nonce:            input.Nonce,
		RequestHash:      input.RequestHash,
		IdempotencyKey:   input.IdempotencyKey,
		PayloadHash:      input.PayloadHash,
		RequestTimestamp: input.RequestTimestamp,
		RequestSignature: input.DeploymentSignature,
		ResultType:       "batch",
		ResultID:         batchID,
		AcceptedAt:       input.AcceptedAt,
	}
}

func (sqliteStore *Store) RevenueBatchReceipt(
	ctx context.Context,
	batchID string,
) (store.RevenueBatchRecord, error) {
	return revenueBatchRecordByIDQuery(ctx, sqliteStore.db, batchID)
}

func revenueBatchRecordByIDTx(
	ctx context.Context,
	tx *sql.Tx,
	batchID string,
) (store.RevenueBatchRecord, error) {
	return revenueBatchRecordByIDQuery(ctx, tx, batchID)
}

type revenueQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func revenueBatchRecordByIDQuery(
	ctx context.Context,
	queryer revenueQueryer,
	batchID string,
) (store.RevenueBatchRecord, error) {
	row := queryer.QueryRowContext(ctx, `
		SELECT
			b.batch_id,
			b.deployment_id,
			b.idempotency_key,
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
			l.batch_hash,
			l.previous_entry_hash,
			l.entry_hash
		FROM revenue_batches b
		JOIN ledger_entries l ON l.ledger_index = b.ledger_index
		WHERE b.batch_id = ?`,
		batchID,
	)
	var record store.RevenueBatchRecord
	var entry protocol.LedgerEntry
	if err := row.Scan(
		&record.BatchID,
		&record.DeploymentID,
		&record.IdempotencyKey,
		&record.Kind,
		&record.Period,
		&record.Revision,
		&record.SupersedesBatchID,
		&record.RulesetVersion,
		&record.CommissionRateBasisPoints,
		&record.CurrencyCount,
		&record.PayloadHash,
		&record.AcceptedAt,
		&record.ReceiptSignature,
		&entry.ProtocolVersion,
		&entry.RegistryScope,
		&entry.LedgerIndex,
		&entry.EntryType,
		&entry.BatchHash,
		&entry.PreviousEntryHash,
		&entry.EntryHash,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.RevenueBatchRecord{}, store.ErrNotFound
		}
		return store.RevenueBatchRecord{}, fmt.Errorf(
			"read revenue batch receipt: %w",
			err,
		)
	}
	entry.DeploymentID = record.DeploymentID
	entry.BatchID = record.BatchID
	entry.Kind = record.Kind
	entry.Period = record.Period
	entry.RulesetVersion = record.RulesetVersion
	entry.AcceptedAt = record.AcceptedAt
	record.LedgerEntry = entry
	currencies, err := revenueCurrenciesByBatch(ctx, queryer, batchID)
	if err != nil {
		return store.RevenueBatchRecord{}, err
	}
	record.Currencies = currencies
	return record, nil
}

func revenueCurrenciesByBatch(
	ctx context.Context,
	queryer revenueQueryer,
	batchID string,
) ([]protocol.RevenueCurrency, error) {
	rows, err := queryer.QueryContext(ctx, `
		SELECT
			currency_code,
			fraction_digits,
			captured_minor,
			refunded_minor,
			net_minor,
			commission_basis_minor,
			estimated_commission_minor,
			payment_count
		FROM revenue_query_rows
		WHERE batch_id = ?
		ORDER BY currency_index`,
		batchID,
	)
	if err != nil {
		return nil, fmt.Errorf("read revenue currency rows: %w", err)
	}
	defer rows.Close()
	currencies := make([]protocol.RevenueCurrency, 0)
	for rows.Next() {
		var currency protocol.RevenueCurrency
		if err := rows.Scan(
			&currency.CurrencyCode,
			&currency.FractionDigits,
			&currency.CapturedMinor,
			&currency.RefundedMinor,
			&currency.NetMinor,
			&currency.CommissionBasisMinor,
			&currency.EstimatedCommissionMinor,
			&currency.PaymentCount,
		); err != nil {
			return nil, fmt.Errorf("scan revenue currency row: %w", err)
		}
		currencies = append(currencies, currency)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate revenue currency rows: %w", err)
	}
	return currencies, nil
}

func cloneRevenueCurrencies(
	currencies []protocol.RevenueCurrency,
) []protocol.RevenueCurrency {
	return append([]protocol.RevenueCurrency(nil), currencies...)
}

func (sqliteStore *Store) RevenueSummary(
	ctx context.Context,
	query store.RevenueQuery,
) (protocol.RevenueSummary, error) {
	deploymentFilter := ""
	arguments := []any{query.Period, query.CurrencyCode}
	if query.DeploymentID != "" {
		deploymentFilter = " AND row.deployment_id = ?"
		arguments = append(arguments, query.DeploymentID)
	}
	statement := `
		WITH active_rows AS (
			SELECT row.*
			FROM revenue_query_rows row
			WHERE row.period = ?
			  AND row.currency_code = ?` + deploymentFilter + `
			  AND NOT EXISTS (
				SELECT 1
				FROM revenue_batches newer
				WHERE newer.deployment_id = row.deployment_id
				  AND newer.period = row.period
				  AND newer.revision > row.revision
			  )
		)
		SELECT
			COALESCE(MIN(fraction_digits), 0),
			COALESCE(MAX(fraction_digits), 0),
			COUNT(DISTINCT deployment_id),
			COUNT(DISTINCT batch_id),
			COALESCE(SUM(captured_minor), 0),
			COALESCE(SUM(refunded_minor), 0),
			COALESCE(SUM(net_minor), 0),
			COALESCE(SUM(commission_basis_minor), 0),
			COALESCE(SUM(estimated_commission_minor), 0),
			COALESCE(SUM(payment_count), 0)
		FROM active_rows`
	var summary protocol.RevenueSummary
	var minimumFractionDigits, maximumFractionDigits int64
	if err := sqliteStore.db.QueryRowContext(
		ctx,
		statement,
		arguments...,
	).Scan(
		&minimumFractionDigits,
		&maximumFractionDigits,
		&summary.DeploymentCount,
		&summary.CurrencyBatchCount,
		&summary.CapturedMinor,
		&summary.RefundedMinor,
		&summary.NetMinor,
		&summary.CommissionBasisMinor,
		&summary.ReportedEstimatedCommissionMinor,
		&summary.PaymentCount,
	); err != nil {
		return protocol.RevenueSummary{}, fmt.Errorf(
			"query active revenue rows: %w",
			err,
		)
	}
	if minimumFractionDigits != maximumFractionDigits {
		return protocol.RevenueSummary{}, store.ErrInconsistentState
	}
	summary.Period = query.Period
	summary.CurrencyCode = query.CurrencyCode
	summary.FractionDigits = query.FractionDigits
	if summary.CurrencyBatchCount > 0 {
		summary.FractionDigits = minimumFractionDigits
	}
	summary.DeploymentID = query.DeploymentID
	summary.RulesetVersion = protocol.RevenueRulesetVersion
	summary.CommissionRateBasisPoints = protocol.RevenueCommissionBasisPoints
	summary.NetworkCommissionPoolMinor = protocol.RevenueCommissionMinor(
		summary.CommissionBasisMinor,
	)

	activeArguments := []any{query.Period}
	activeDeploymentFilter := ""
	if query.DeploymentID != "" {
		activeDeploymentFilter = " AND batch.deployment_id = ?"
		activeArguments = append(activeArguments, query.DeploymentID)
	}
	if err := sqliteStore.db.QueryRowContext(
		ctx,
		`
		SELECT COUNT(*), COUNT(DISTINCT batch.deployment_id)
		FROM revenue_batches batch
		WHERE batch.period = ?`+activeDeploymentFilter+`
		  AND NOT EXISTS (
			SELECT 1
			FROM revenue_batches newer
			WHERE newer.deployment_id = batch.deployment_id
			  AND newer.period = batch.period
			  AND newer.revision > batch.revision
		  )`,
		activeArguments...,
	).Scan(
		&summary.ActiveBatchCount,
		&summary.DeploymentCount,
	); err != nil {
		return protocol.RevenueSummary{}, fmt.Errorf(
			"count active revenue batches: %w",
			err,
		)
	}
	return summary, nil
}
