package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const registryCaseEventSelect = `
	SELECT
		event_index,
		event_id,
		case_id,
		action,
		subject_type,
		subject_id,
		category,
		severity,
		evidence_hash,
		reference,
		actor_id,
		idempotency_key,
		payload_hash,
		accepted_at,
		previous_event_hash,
		event_hash,
		registry_scope,
		registry_key_id,
		signature
	FROM registry_case_events`

const registryCaseSelect = `
	SELECT
		case_id,
		status,
		subject_type,
		subject_id,
		category,
		severity,
		flag_evidence_hash,
		flag_reference,
		flag_actor_id,
		flagged_at,
		flag_event_index,
		flag_event_hash,
		clear_evidence_hash,
		clear_reference,
		clear_actor_id,
		cleared_at,
		clear_event_index,
		clear_event_hash,
		latest_event_index,
		latest_event_hash
	FROM registry_cases`

type registryCaseQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (sqliteStore *Store) AppendRegistryCaseEvent(
	ctx context.Context,
	input store.RegistryCaseEventInput,
	signEvent store.RegistryCaseEventSigner,
) (store.RegistryCaseEvent, store.RegistryCase, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.RegistryCaseEvent{}, store.RegistryCase{}, false,
			fmt.Errorf("begin registry case event: %w", err)
	}
	defer tx.Rollback()

	existing, err := registryCaseEventByIdempotency(
		ctx,
		tx,
		input.IdempotencyKey,
	)
	if err == nil {
		caseConflict := input.Action == protocol.RegistryCaseActionClear &&
			existing.CaseID != input.CaseID
		if existing.PayloadHash != input.PayloadHash ||
			existing.Action != input.Action ||
			caseConflict {
			return store.RegistryCaseEvent{}, store.RegistryCase{}, false,
				store.ErrIdempotencyConflict
		}
		current, currentErr := registryCaseByID(ctx, tx, existing.CaseID)
		if currentErr != nil {
			return store.RegistryCaseEvent{}, store.RegistryCase{}, false,
				fmt.Errorf("read duplicate registry case state: %w", currentErr)
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return store.RegistryCaseEvent{}, store.RegistryCase{}, false,
				fmt.Errorf("commit duplicate registry case event: %w", commitErr)
		}
		return existing, current, true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.RegistryCaseEvent{}, store.RegistryCase{}, false, err
	}

	if err := ensureAcceptedAtAfterRegistryCreation(
		ctx,
		tx,
		input.AcceptedAt,
	); err != nil {
		return store.RegistryCaseEvent{}, store.RegistryCase{}, false, err
	}
	head, err := registryCaseEventHead(ctx, tx)
	if err != nil {
		return store.RegistryCaseEvent{}, store.RegistryCase{}, false, err
	}
	if head.AcceptedAt != "" {
		acceptedAt, parseErr := time.Parse(time.RFC3339, input.AcceptedAt)
		headAt, headParseErr := time.Parse(time.RFC3339, head.AcceptedAt)
		if parseErr != nil || headParseErr != nil || acceptedAt.Before(headAt) {
			return store.RegistryCaseEvent{}, store.RegistryCase{}, false,
				store.ErrRegistryCaseClockBeforeHead
		}
	}

	var current store.RegistryCase
	switch input.Action {
	case protocol.RegistryCaseActionFlag:
		if _, lookupErr := registryCaseByID(ctx, tx, input.CaseID); lookupErr == nil {
			return store.RegistryCaseEvent{}, store.RegistryCase{}, false,
				store.ErrIdempotencyConflict
		} else if !errors.Is(lookupErr, store.ErrNotFound) {
			return store.RegistryCaseEvent{}, store.RegistryCase{}, false, lookupErr
		}
		exists, lookupErr := registryCaseSubjectExists(
			ctx,
			tx,
			input.SubjectType,
			input.SubjectID,
		)
		if lookupErr != nil {
			return store.RegistryCaseEvent{}, store.RegistryCase{}, false, lookupErr
		}
		if !exists {
			return store.RegistryCaseEvent{}, store.RegistryCase{}, false,
				store.ErrNotFound
		}
	case protocol.RegistryCaseActionClear:
		current, err = registryCaseByID(ctx, tx, input.CaseID)
		if err != nil {
			return store.RegistryCaseEvent{}, store.RegistryCase{}, false, err
		}
		if current.Status != protocol.RegistryCaseStatusOpen {
			return store.RegistryCaseEvent{}, store.RegistryCase{}, false,
				store.ErrRegistryCaseAlreadyCleared
		}
		if current.SubjectType != input.SubjectType ||
			current.SubjectID != input.SubjectID ||
			current.Category != input.Category ||
			current.Severity != input.Severity {
			return store.RegistryCaseEvent{}, store.RegistryCase{}, false,
				store.ErrInconsistentState
		}
	default:
		return store.RegistryCaseEvent{}, store.RegistryCase{}, false,
			store.ErrInconsistentState
	}

	event := store.RegistryCaseEvent{
		EventIndex:        head.EventIndex + 1,
		EventID:           input.CandidateEventID,
		CaseID:            input.CaseID,
		Action:            input.Action,
		SubjectType:       input.SubjectType,
		SubjectID:         input.SubjectID,
		Category:          input.Category,
		Severity:          input.Severity,
		EvidenceHash:      input.EvidenceHash,
		Reference:         input.Reference,
		ActorID:           input.ActorID,
		IdempotencyKey:    input.IdempotencyKey,
		PayloadHash:       input.PayloadHash,
		AcceptedAt:        input.AcceptedAt,
		PreviousEventHash: head.EventHash,
		RegistryScope:     input.RegistryScope,
		RegistryKeyID:     input.RegistryKeyID,
	}
	event.EventHash = protocol.Digest(
		protocol.RegistryCaseEventHashMessage(registryCaseProtocolEvent(event)),
	)
	event.Signature, err = signEvent(event)
	if err != nil {
		return store.RegistryCaseEvent{}, store.RegistryCase{}, false,
			fmt.Errorf("sign registry case event: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO registry_case_events (
			event_index,
			event_id,
			case_id,
			action,
			subject_type,
			subject_id,
			category,
			severity,
			evidence_hash,
			reference,
			actor_id,
			idempotency_key,
			payload_hash,
			accepted_at,
			previous_event_hash,
			event_hash,
			registry_scope,
			registry_key_id,
			signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.EventIndex,
		event.EventID,
		event.CaseID,
		event.Action,
		event.SubjectType,
		event.SubjectID,
		event.Category,
		event.Severity,
		event.EvidenceHash,
		event.Reference,
		event.ActorID,
		event.IdempotencyKey,
		event.PayloadHash,
		event.AcceptedAt,
		event.PreviousEventHash,
		event.EventHash,
		event.RegistryScope,
		event.RegistryKeyID,
		event.Signature,
	); err != nil {
		return store.RegistryCaseEvent{}, store.RegistryCase{}, false,
			fmt.Errorf("append registry case event: %w", err)
	}

	switch event.Action {
	case protocol.RegistryCaseActionFlag:
		current = store.RegistryCase{
			CaseID:           event.CaseID,
			Status:           protocol.RegistryCaseStatusOpen,
			SubjectType:      event.SubjectType,
			SubjectID:        event.SubjectID,
			Category:         event.Category,
			Severity:         event.Severity,
			FlagEvidenceHash: event.EvidenceHash,
			FlagReference:    event.Reference,
			FlagActorID:      event.ActorID,
			FlaggedAt:        event.AcceptedAt,
			FlagEventIndex:   event.EventIndex,
			FlagEventHash:    event.EventHash,
			LatestEventIndex: event.EventIndex,
			LatestEventHash:  event.EventHash,
		}
		if err := insertRegistryCase(ctx, tx, current); err != nil {
			return store.RegistryCaseEvent{}, store.RegistryCase{}, false, err
		}
	case protocol.RegistryCaseActionClear:
		result, updateErr := tx.ExecContext(ctx, `
			UPDATE registry_cases
			SET status = ?,
			    clear_evidence_hash = ?,
			    clear_reference = ?,
			    clear_actor_id = ?,
			    cleared_at = ?,
			    clear_event_index = ?,
			    clear_event_hash = ?,
			    latest_event_index = ?,
			    latest_event_hash = ?
			WHERE case_id = ? AND status = ?`,
			protocol.RegistryCaseStatusCleared,
			event.EvidenceHash,
			event.Reference,
			event.ActorID,
			event.AcceptedAt,
			event.EventIndex,
			event.EventHash,
			event.EventIndex,
			event.EventHash,
			event.CaseID,
			protocol.RegistryCaseStatusOpen,
		)
		if updateErr != nil {
			return store.RegistryCaseEvent{}, store.RegistryCase{}, false,
				fmt.Errorf("update cleared registry case: %w", updateErr)
		}
		affected, rowsErr := result.RowsAffected()
		if rowsErr != nil || affected != 1 {
			return store.RegistryCaseEvent{}, store.RegistryCase{}, false,
				store.ErrRegistryCaseAlreadyCleared
		}
		current, err = registryCaseByID(ctx, tx, event.CaseID)
		if err != nil {
			return store.RegistryCaseEvent{}, store.RegistryCase{}, false, err
		}
	}

	if err := tx.Commit(); err != nil {
		return store.RegistryCaseEvent{}, store.RegistryCase{}, false,
			fmt.Errorf("commit registry case event: %w", err)
	}
	return event, current, false, nil
}

func (sqliteStore *Store) RegistryCase(
	ctx context.Context,
	caseID string,
) (store.RegistryCase, error) {
	return registryCaseByID(ctx, sqliteStore.db, caseID)
}

func (sqliteStore *Store) RegistryCases(
	ctx context.Context,
	query store.RegistryCaseQuery,
) (store.RegistryCasePage, error) {
	arguments := make([]any, 0, 3)
	where := " WHERE 1 = 1"
	if query.Status != "" {
		where += " AND status = ?"
		arguments = append(arguments, query.Status)
	}
	if query.BeforeEventIndex > 0 {
		where += " AND flag_event_index < ?"
		arguments = append(arguments, query.BeforeEventIndex)
	}
	arguments = append(arguments, query.Limit+1)
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		registryCaseSelect+where+
			" ORDER BY flag_event_index DESC LIMIT ?",
		arguments...,
	)
	if err != nil {
		return store.RegistryCasePage{}, fmt.Errorf("list registry cases: %w", err)
	}
	defer rows.Close()
	items := make([]store.RegistryCase, 0, query.Limit)
	for rows.Next() {
		item, scanErr := scanRegistryCase(rows)
		if scanErr != nil {
			return store.RegistryCasePage{}, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return store.RegistryCasePage{}, fmt.Errorf("iterate registry cases: %w", err)
	}
	page := store.RegistryCasePage{}
	if len(items) > query.Limit {
		page.NextEventIndex = items[query.Limit-1].FlagEventIndex
		items = items[:query.Limit]
	}
	page.Items = items
	return page, nil
}

func registryCaseEventByIdempotency(
	ctx context.Context,
	queryer registryCaseQueryer,
	idempotencyKey string,
) (store.RegistryCaseEvent, error) {
	return scanRegistryCaseEvent(queryer.QueryRowContext(
		ctx,
		registryCaseEventSelect+" WHERE idempotency_key = ?",
		idempotencyKey,
	))
}

func registryCaseEventHead(
	ctx context.Context,
	queryer registryCaseQueryer,
) (store.RegistryCaseEvent, error) {
	event, err := scanRegistryCaseEvent(queryer.QueryRowContext(
		ctx,
		registryCaseEventSelect+" ORDER BY event_index DESC LIMIT 1",
	))
	if errors.Is(err, store.ErrNotFound) {
		return store.RegistryCaseEvent{
			EventHash: protocol.RegistryCaseZeroHash,
		}, nil
	}
	return event, err
}

func registryCaseByID(
	ctx context.Context,
	queryer registryCaseQueryer,
	caseID string,
) (store.RegistryCase, error) {
	return scanRegistryCase(queryer.QueryRowContext(
		ctx,
		registryCaseSelect+" WHERE case_id = ?",
		caseID,
	))
}

func insertRegistryCase(
	ctx context.Context,
	tx *sql.Tx,
	item store.RegistryCase,
) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO registry_cases (
			case_id,
			status,
			subject_type,
			subject_id,
			category,
			severity,
			flag_evidence_hash,
			flag_reference,
			flag_actor_id,
			flagged_at,
			flag_event_index,
			flag_event_hash,
			latest_event_index,
			latest_event_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.CaseID,
		item.Status,
		item.SubjectType,
		item.SubjectID,
		item.Category,
		item.Severity,
		item.FlagEvidenceHash,
		item.FlagReference,
		item.FlagActorID,
		item.FlaggedAt,
		item.FlagEventIndex,
		item.FlagEventHash,
		item.LatestEventIndex,
		item.LatestEventHash,
	); err != nil {
		return fmt.Errorf("insert registry case query row: %w", err)
	}
	return nil
}

func registryCaseSubjectExists(
	ctx context.Context,
	queryer registryCaseQueryer,
	subjectType string,
	subjectID string,
) (bool, error) {
	var query string
	arguments := []any{subjectID}
	switch subjectType {
	case protocol.RegistryCaseSubjectDeployment:
		query = "SELECT COUNT(*) FROM deployments WHERE deployment_id = ?"
	case protocol.RegistryCaseSubjectClaim:
		query = `
			SELECT COUNT(*)
			FROM operator_audit_events
			WHERE action_id = ?
			  AND (
			      action_type = 'claim'
			      OR (
			          action_type = 'redeem-client-token'
			          AND claim_state = 'pending-review'
			          AND operator_name <> ''
			          AND link_id = ''
			      )
			  )`
	case protocol.RegistryCaseSubjectGroup:
		query = `
			SELECT COUNT(*)
			FROM operator_network_state_rows
			WHERE claim_group_id = ? OR effective_group_id = ?`
		arguments = append(arguments, subjectID)
	case protocol.RegistryCaseSubjectQMAU:
		query = "SELECT COUNT(*) FROM mau_batches WHERE batch_id = ? AND kind = 'monthly-qmau'"
	case protocol.RegistryCaseSubjectRevenue:
		query = "SELECT COUNT(*) FROM revenue_batches WHERE batch_id = ?"
	case protocol.RegistryCaseSubjectLedger:
		query = "SELECT COUNT(*) FROM ledger_entries WHERE ledger_index = ?"
	default:
		return false, store.ErrInconsistentState
	}
	var count int
	if err := queryer.QueryRowContext(ctx, query, arguments...).Scan(&count); err != nil {
		return false, fmt.Errorf("verify registry case subject: %w", err)
	}
	return count > 0, nil
}

func scanRegistryCaseEvent(scanner rowScanner) (store.RegistryCaseEvent, error) {
	var event store.RegistryCaseEvent
	if err := scanner.Scan(
		&event.EventIndex,
		&event.EventID,
		&event.CaseID,
		&event.Action,
		&event.SubjectType,
		&event.SubjectID,
		&event.Category,
		&event.Severity,
		&event.EvidenceHash,
		&event.Reference,
		&event.ActorID,
		&event.IdempotencyKey,
		&event.PayloadHash,
		&event.AcceptedAt,
		&event.PreviousEventHash,
		&event.EventHash,
		&event.RegistryScope,
		&event.RegistryKeyID,
		&event.Signature,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.RegistryCaseEvent{}, store.ErrNotFound
		}
		return store.RegistryCaseEvent{}, fmt.Errorf(
			"scan registry case event: %w",
			err,
		)
	}
	return event, nil
}

func scanRegistryCase(scanner rowScanner) (store.RegistryCase, error) {
	var item store.RegistryCase
	if err := scanner.Scan(
		&item.CaseID,
		&item.Status,
		&item.SubjectType,
		&item.SubjectID,
		&item.Category,
		&item.Severity,
		&item.FlagEvidenceHash,
		&item.FlagReference,
		&item.FlagActorID,
		&item.FlaggedAt,
		&item.FlagEventIndex,
		&item.FlagEventHash,
		&item.ClearEvidenceHash,
		&item.ClearReference,
		&item.ClearActorID,
		&item.ClearedAt,
		&item.ClearEventIndex,
		&item.ClearEventHash,
		&item.LatestEventIndex,
		&item.LatestEventHash,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.RegistryCase{}, store.ErrNotFound
		}
		return store.RegistryCase{}, fmt.Errorf("scan registry case: %w", err)
	}
	return item, nil
}

func registryCaseProtocolEvent(
	event store.RegistryCaseEvent,
) protocol.RegistryCaseEvent {
	return protocol.RegistryCaseEvent{
		EventIndex:        event.EventIndex,
		EventID:           event.EventID,
		CaseID:            event.CaseID,
		Action:            event.Action,
		SubjectType:       event.SubjectType,
		SubjectID:         event.SubjectID,
		Category:          event.Category,
		Severity:          event.Severity,
		EvidenceHash:      event.EvidenceHash,
		Reference:         event.Reference,
		ActorID:           event.ActorID,
		IdempotencyKey:    event.IdempotencyKey,
		PayloadHash:       event.PayloadHash,
		AcceptedAt:        event.AcceptedAt,
		PreviousEventHash: event.PreviousEventHash,
		EventHash:         event.EventHash,
		RegistryScope:     event.RegistryScope,
		RegistryKeyID:     event.RegistryKeyID,
	}
}
