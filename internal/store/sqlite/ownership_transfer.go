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

const ownershipTransferRecordSelect = `
	SELECT
		transfer_id,
		ruleset_version,
		exit_review_id,
		target_deployment_id,
		claim_action_id,
		source_group_id,
		target_group_id,
		legal_name,
		exit_record_hash,
		exit_verification_event_index,
		exit_verification_event_hash,
		exit_evidence_hash,
		prepared_at,
		record_hash,
		registry_scope,
		registry_key_id
	FROM ownership_transfers`

const ownershipTransferEventSelect = `
	SELECT
		event_index,
		event_id,
		transfer_id,
		action,
		resulting_status,
		effective_date,
		actor_role,
		actor_id,
		reference,
		evidence_hash,
		reason_code,
		idempotency_key,
		payload_hash,
		record_hash,
		accepted_at,
		previous_event_hash,
		previous_transfer_event_hash,
		event_hash,
		registry_scope,
		registry_key_id,
		signature
	FROM ownership_transfer_events`

const ownershipTransferStateSelect = `
	SELECT
		event_index,
		event_hash,
		transfer_id,
		status,
		target_deployment_id,
		claim_action_id,
		source_group_id,
		target_group_id,
		legal_name,
		exit_review_id,
		exit_record_hash,
		exit_verification_event_index,
		exit_verification_event_hash,
		exit_evidence_hash,
		record_hash,
		latest_action,
		latest_effective_date,
		latest_actor_role,
		latest_actor_id,
		latest_reference,
		latest_evidence_hash,
		latest_reason_code,
		latest_accepted_at
	FROM ownership_transfer_state_rows`

const ownershipTransferMembershipSelect = `
	SELECT
		transfer_id,
		completion_event_index,
		completion_event_hash,
		target_deployment_id,
		claim_action_id,
		source_group_id,
		target_group_id,
		effective_date,
		through_audit_index,
		audit_head_hash,
		completed_at,
		membership_hash
	FROM ownership_transfer_memberships`

type ownershipTransferState struct {
	EventIndex                 int64
	EventHash                  string
	TransferID                 string
	Status                     string
	TargetDeploymentID         string
	ClaimActionID              string
	SourceGroupID              string
	TargetGroupID              string
	LegalName                  string
	ExitReviewID               string
	ExitRecordHash             string
	ExitVerificationEventIndex int64
	ExitVerificationEventHash  string
	ExitEvidenceHash           string
	RecordHash                 string
	LatestAction               string
	LatestEffectiveDate        string
	LatestActorRole            string
	LatestActorID              string
	LatestReference            string
	LatestEvidenceHash         string
	LatestReasonCode           string
	LatestAcceptedAt           string
}

type ownershipTransferQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (sqliteStore *Store) PrepareOwnershipTransfer(
	ctx context.Context,
	input store.OwnershipTransferPrepareInput,
	signEvent store.OwnershipTransferEventSigner,
) (store.OwnershipTransferEvent, store.OwnershipTransfer, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false,
			fmt.Errorf("begin ownership transfer prepare: %w", err)
	}
	defer tx.Rollback()

	existing, err := ownershipTransferEventByIdempotency(
		ctx,
		tx,
		input.IdempotencyKey,
	)
	if err == nil {
		current, readErr := ownershipTransferByIDQuery(
			ctx,
			tx,
			existing.TransferID,
		)
		if readErr != nil {
			return store.OwnershipTransferEvent{},
				store.OwnershipTransfer{}, false, readErr
		}
		if existing.Action != protocol.OwnershipTransferActionPrepare ||
			current.Record.ExitReviewID != input.ExitReviewID ||
			current.Record.TargetDeploymentID != input.TargetDeploymentID ||
			current.Record.ClaimActionID != input.ClaimActionID ||
			current.Record.SourceGroupID != input.SourceGroupID ||
			current.Record.TargetGroupID != input.TargetGroupID ||
			current.Record.ExitVerificationEventHash !=
				input.ExitVerificationEventHash ||
			existing.ActorID != input.ActorID ||
			existing.Reference != input.Reference ||
			existing.EvidenceHash != input.EvidenceHash {
			return store.OwnershipTransferEvent{},
				store.OwnershipTransfer{}, false,
				store.ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return store.OwnershipTransferEvent{},
				store.OwnershipTransfer{}, false,
				fmt.Errorf("commit duplicate ownership transfer prepare: %w", err)
		}
		return existing, current, true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	if err := ensureAcceptedAtAfterRegistryCreation(
		ctx,
		tx,
		input.AcceptedAt,
	); err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	head, err := ownershipTransferEventHeadQuery(ctx, tx)
	if err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	if err := ensureOwnershipTransferAcceptedAt(
		head.AcceptedAt,
		input.AcceptedAt,
	); err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	if input.SourceGroupID == input.TargetGroupID {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false,
			store.ErrOwnershipTransferTargetGroup
	}
	if active, activeErr := activeOwnershipTransferForClaimTx(
		ctx,
		tx,
		input.TargetDeploymentID,
		input.ClaimActionID,
	); activeErr != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false,
			activeErr
	} else if active {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false,
			store.ErrOwnershipTransferConflict
	}
	var finalAllocationID string
	allocationErr := tx.QueryRowContext(ctx, `
		SELECT allocation_id
		FROM exit_allocations
		WHERE exit_review_id = ?`,
		input.ExitReviewID,
	).Scan(&finalAllocationID)
	if allocationErr == nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false,
			store.ErrOwnershipTransferConflict
	}
	if !errors.Is(allocationErr, sql.ErrNoRows) {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false,
			fmt.Errorf(
				"inspect final exit allocation before transfer prepare: %w",
				allocationErr,
			)
	}
	legalName, err := currentOwnershipTransferClaimTx(
		ctx,
		tx,
		input.TargetDeploymentID,
		input.ClaimActionID,
		input.SourceGroupID,
	)
	if err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	exitReview, exitEvent, err := exactVerifiedExitReviewTx(
		ctx,
		tx,
		input.ExitReviewID,
		input.TargetDeploymentID,
		input.ClaimActionID,
		input.SourceGroupID,
		input.ExitVerificationEventHash,
	)
	if err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	eligible, err := targetGroupHasEligibleClaimTx(
		ctx,
		tx,
		input.TargetGroupID,
	)
	if err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	if !eligible {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false,
			store.ErrOwnershipTransferTargetGroup
	}

	record := store.OwnershipTransferRecord{
		TransferID:                 input.CandidateTransferID,
		RulesetVersion:             protocol.OwnershipTransferRulesetVersion,
		ExitReviewID:               input.ExitReviewID,
		TargetDeploymentID:         input.TargetDeploymentID,
		ClaimActionID:              input.ClaimActionID,
		SourceGroupID:              input.SourceGroupID,
		TargetGroupID:              input.TargetGroupID,
		LegalName:                  legalName,
		ExitRecordHash:             exitReview.Record.RecordHash,
		ExitVerificationEventIndex: exitEvent.EventIndex,
		ExitVerificationEventHash:  exitEvent.EventHash,
		ExitEvidenceHash:           exitEvent.EvidenceHash,
		PreparedAt:                 input.AcceptedAt,
		RegistryScope:              input.RegistryScope,
		RegistryKeyID:              input.RegistryKeyID,
	}
	record.RecordHash = protocol.Digest(
		protocol.OwnershipTransferRecordHashMessage(
			ownershipTransferProtocolRecord(record),
		),
	)
	if err := insertOwnershipTransferRecordTx(ctx, tx, record); err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	event := store.OwnershipTransferEvent{
		EventIndex:                head.EventIndex + 1,
		EventID:                   input.CandidateEventID,
		TransferID:                record.TransferID,
		Action:                    protocol.OwnershipTransferActionPrepare,
		ResultingStatus:           protocol.OwnershipTransferStatusPrepared,
		EffectiveDate:             input.AcceptedAt[:len("2006-01-02")],
		ActorRole:                 protocol.OwnershipTransferActorRequester,
		ActorID:                   input.ActorID,
		Reference:                 input.Reference,
		EvidenceHash:              input.EvidenceHash,
		IdempotencyKey:            input.IdempotencyKey,
		RecordHash:                record.RecordHash,
		AcceptedAt:                input.AcceptedAt,
		PreviousEventHash:         head.EventHash,
		PreviousTransferEventHash: protocol.OwnershipTransferZeroHash,
		RegistryScope:             input.RegistryScope,
		RegistryKeyID:             input.RegistryKeyID,
	}
	event.PayloadHash = protocol.Digest(
		protocol.OwnershipTransferEventPayloadMessage(
			ownershipTransferProtocolEvent(event),
		),
	)
	event.EventHash = protocol.Digest(
		protocol.OwnershipTransferEventHashMessage(
			ownershipTransferProtocolEvent(event),
		),
	)
	event.Signature, err = signEvent(event)
	if err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false,
			fmt.Errorf("sign ownership transfer prepare event: %w", err)
	}
	if err := insertOwnershipTransferEventTx(ctx, tx, event); err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	if err := insertOwnershipTransferStateTx(
		ctx,
		tx,
		ownershipTransferStateFromEvent(record, event),
	); err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false,
			fmt.Errorf("commit ownership transfer prepare: %w", err)
	}
	transfer, err := sqliteStore.OwnershipTransfer(ctx, record.TransferID)
	if err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	return event, transfer, false, nil
}

func (sqliteStore *Store) AppendOwnershipTransferEvent(
	ctx context.Context,
	input store.OwnershipTransferMutationInput,
	signEvent store.OwnershipTransferEventSigner,
) (store.OwnershipTransferEvent, store.OwnershipTransfer, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false,
			fmt.Errorf("begin ownership transfer mutation: %w", err)
	}
	defer tx.Rollback()

	existing, err := ownershipTransferEventByIdempotency(
		ctx,
		tx,
		input.IdempotencyKey,
	)
	if err == nil {
		current, readErr := ownershipTransferByIDQuery(
			ctx,
			tx,
			existing.TransferID,
		)
		if readErr != nil {
			return store.OwnershipTransferEvent{},
				store.OwnershipTransfer{}, false, readErr
		}
		if existing.TransferID != input.TransferID ||
			existing.Action != input.Action ||
			existing.ResultingStatus != input.ResultingStatus ||
			existing.EffectiveDate != input.EffectiveDate ||
			existing.ActorID != input.ActorID ||
			existing.Reference != input.Reference ||
			existing.EvidenceHash != input.EvidenceHash ||
			existing.ReasonCode != input.ReasonCode ||
			existing.PayloadHash != input.PayloadHash {
			return store.OwnershipTransferEvent{},
				store.OwnershipTransfer{}, false,
				store.ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return store.OwnershipTransferEvent{},
				store.OwnershipTransfer{}, false,
				fmt.Errorf("commit duplicate ownership transfer mutation: %w", err)
		}
		return existing, current, true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	if err := ensureAcceptedAtAfterRegistryCreation(
		ctx,
		tx,
		input.AcceptedAt,
	); err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	head, err := ownershipTransferEventHeadQuery(ctx, tx)
	if err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	if err := ensureOwnershipTransferAcceptedAt(
		head.AcceptedAt,
		input.AcceptedAt,
	); err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	current, err := ownershipTransferByIDQuery(ctx, tx, input.TransferID)
	if err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	if !validOwnershipTransferTransition(
		current.Status,
		input.Action,
		input.ResultingStatus,
	) {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false,
			store.ErrOwnershipTransferTransition
	}
	if input.EffectiveDate < current.Record.PreparedAt[:len("2006-01-02")] ||
		input.EffectiveDate < current.LatestEffectiveDate {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false,
			store.ErrOwnershipTransferTransition
	}
	if input.Action == protocol.OwnershipTransferActionComplete {
		if input.EffectiveDate != input.AcceptedAt[:len("2006-01-02")] {
			return store.OwnershipTransferEvent{},
				store.OwnershipTransfer{}, false,
				store.ErrOwnershipTransferTransition
		}
		if _, err := currentOwnershipTransferClaimTx(
			ctx,
			tx,
			current.Record.TargetDeploymentID,
			current.Record.ClaimActionID,
			current.Record.SourceGroupID,
		); err != nil {
			return store.OwnershipTransferEvent{},
				store.OwnershipTransfer{}, false, err
		}
		if _, _, err := exactVerifiedExitReviewTx(
			ctx,
			tx,
			current.Record.ExitReviewID,
			current.Record.TargetDeploymentID,
			current.Record.ClaimActionID,
			current.Record.SourceGroupID,
			current.Record.ExitVerificationEventHash,
		); err != nil {
			return store.OwnershipTransferEvent{},
				store.OwnershipTransfer{}, false, err
		}
		eligible, err := targetGroupHasEligibleClaimTx(
			ctx,
			tx,
			current.Record.TargetGroupID,
		)
		if err != nil {
			return store.OwnershipTransferEvent{},
				store.OwnershipTransfer{}, false, err
		}
		if !eligible {
			return store.OwnershipTransferEvent{},
				store.OwnershipTransfer{}, false,
				store.ErrOwnershipTransferTargetGroup
		}
		if err := ensureTransferCompletionAfterLedgerHead(
			ctx,
			tx,
			input.AcceptedAt,
		); err != nil {
			return store.OwnershipTransferEvent{},
				store.OwnershipTransfer{}, false, err
		}
		if err := ensureTransferCompletionAfterOperatorHead(
			ctx,
			tx,
			input.AcceptedAt,
		); err != nil {
			return store.OwnershipTransferEvent{},
				store.OwnershipTransfer{}, false, err
		}
	}

	event := store.OwnershipTransferEvent{
		EventIndex:                head.EventIndex + 1,
		EventID:                   input.CandidateEventID,
		TransferID:                input.TransferID,
		Action:                    input.Action,
		ResultingStatus:           input.ResultingStatus,
		EffectiveDate:             input.EffectiveDate,
		ActorRole:                 protocol.OwnershipTransferActorManager,
		ActorID:                   input.ActorID,
		Reference:                 input.Reference,
		EvidenceHash:              input.EvidenceHash,
		ReasonCode:                input.ReasonCode,
		IdempotencyKey:            input.IdempotencyKey,
		PayloadHash:               input.PayloadHash,
		RecordHash:                current.Record.RecordHash,
		AcceptedAt:                input.AcceptedAt,
		PreviousEventHash:         head.EventHash,
		PreviousTransferEventHash: current.LatestEventHash,
		RegistryScope:             input.RegistryScope,
		RegistryKeyID:             input.RegistryKeyID,
	}
	event.EventHash = protocol.Digest(
		protocol.OwnershipTransferEventHashMessage(
			ownershipTransferProtocolEvent(event),
		),
	)
	event.Signature, err = signEvent(event)
	if err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false,
			fmt.Errorf("sign ownership transfer event: %w", err)
	}
	if err := insertOwnershipTransferEventTx(ctx, tx, event); err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	if err := insertOwnershipTransferStateTx(
		ctx,
		tx,
		ownershipTransferStateFromEvent(current.Record, event),
	); err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	if event.Action == protocol.OwnershipTransferActionComplete {
		auditHead, err := operatorAuditHeadTx(ctx, tx)
		if err != nil {
			return store.OwnershipTransferEvent{},
				store.OwnershipTransfer{}, false, err
		}
		membership := store.OwnershipTransferMembership{
			TransferID:           current.Record.TransferID,
			CompletionEventIndex: event.EventIndex,
			CompletionEventHash:  event.EventHash,
			TargetDeploymentID:   current.Record.TargetDeploymentID,
			ClaimActionID:        current.Record.ClaimActionID,
			SourceGroupID:        current.Record.SourceGroupID,
			TargetGroupID:        current.Record.TargetGroupID,
			EffectiveDate:        event.EffectiveDate,
			ThroughAuditIndex:    auditHead.AuditIndex,
			AuditHeadHash:        auditHead.AuditHash,
			CompletedAt:          event.AcceptedAt,
		}
		membership.MembershipHash = protocol.Digest(
			protocol.OwnershipTransferMembershipHashMessage(
				ownershipTransferProtocolMembership(membership),
			),
		)
		if err := insertOwnershipTransferMembershipTx(
			ctx,
			tx,
			membership,
		); err != nil {
			return store.OwnershipTransferEvent{},
				store.OwnershipTransfer{}, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false,
			fmt.Errorf("commit ownership transfer mutation: %w", err)
	}
	transfer, err := sqliteStore.OwnershipTransfer(ctx, input.TransferID)
	if err != nil {
		return store.OwnershipTransferEvent{}, store.OwnershipTransfer{}, false, err
	}
	return event, transfer, false, nil
}

func (sqliteStore *Store) OwnershipTransfer(
	ctx context.Context,
	transferID string,
) (store.OwnershipTransfer, error) {
	return ownershipTransferByIDQuery(ctx, sqliteStore.db, transferID)
}

func (sqliteStore *Store) OwnershipTransfers(
	ctx context.Context,
	query store.OwnershipTransferQuery,
) (store.OwnershipTransferPage, error) {
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		ownershipTransferStateSelect+`
		WHERE event_index = (
			SELECT MAX(latest.event_index)
			FROM ownership_transfer_state_rows latest
			WHERE latest.transfer_id =
				ownership_transfer_state_rows.transfer_id
		)
		  AND (? = '' OR status = ?)
		  AND (? = 0 OR event_index < ?)
		ORDER BY event_index DESC
		LIMIT ?`,
		query.Status,
		query.Status,
		query.BeforeEventIndex,
		query.BeforeEventIndex,
		query.Limit+1,
	)
	if err != nil {
		return store.OwnershipTransferPage{},
			fmt.Errorf("list ownership transfer state rows: %w", err)
	}
	defer rows.Close()
	states := make([]ownershipTransferState, 0, query.Limit+1)
	for rows.Next() {
		state, scanErr := scanOwnershipTransferState(rows)
		if scanErr != nil {
			return store.OwnershipTransferPage{}, scanErr
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return store.OwnershipTransferPage{},
			fmt.Errorf("iterate ownership transfer state rows: %w", err)
	}
	page := store.OwnershipTransferPage{}
	for index, state := range states {
		if index == query.Limit {
			page.NextEventIndex = states[index-1].EventIndex
			break
		}
		record, err := ownershipTransferRecordByID(
			ctx,
			sqliteStore.db,
			state.TransferID,
		)
		if err != nil {
			return store.OwnershipTransferPage{}, err
		}
		item := ownershipTransferFromState(record, state)
		membership, found, err := ownershipTransferMembershipByTransfer(
			ctx,
			sqliteStore.db,
			state.TransferID,
		)
		if err != nil {
			return store.OwnershipTransferPage{}, err
		}
		if found {
			item.Membership = &membership
		}
		page.Items = append(page.Items, item)
	}
	return page, nil
}

func (sqliteStore *Store) OwnershipTransferHead(
	ctx context.Context,
) (store.OwnershipTransferEvent, error) {
	return ownershipTransferEventHeadQuery(ctx, sqliteStore.db)
}

func ownershipTransferByIDQuery(
	ctx context.Context,
	queryer ownershipTransferQueryer,
	transferID string,
) (store.OwnershipTransfer, error) {
	record, err := ownershipTransferRecordByID(ctx, queryer, transferID)
	if err != nil {
		return store.OwnershipTransfer{}, err
	}
	state, err := scanOwnershipTransferState(queryer.QueryRowContext(
		ctx,
		ownershipTransferStateSelect+`
		WHERE transfer_id = ?
		ORDER BY event_index DESC
		LIMIT 1`,
		transferID,
	))
	if err != nil {
		return store.OwnershipTransfer{}, err
	}
	result := ownershipTransferFromState(record, state)
	result.Events, err = ownershipTransferEventsByTransfer(
		ctx,
		queryer,
		transferID,
	)
	if err != nil {
		return store.OwnershipTransfer{}, err
	}
	membership, found, err := ownershipTransferMembershipByTransfer(
		ctx,
		queryer,
		transferID,
	)
	if err != nil {
		return store.OwnershipTransfer{}, err
	}
	if found {
		result.Membership = &membership
	}
	return result, nil
}

func ownershipTransferRecordByID(
	ctx context.Context,
	queryer ownershipTransferQueryer,
	transferID string,
) (store.OwnershipTransferRecord, error) {
	return scanOwnershipTransferRecord(queryer.QueryRowContext(
		ctx,
		ownershipTransferRecordSelect+" WHERE transfer_id = ?",
		transferID,
	))
}

func ownershipTransferEventHeadQuery(
	ctx context.Context,
	queryer ownershipTransferQueryer,
) (store.OwnershipTransferEvent, error) {
	event, err := scanOwnershipTransferEvent(queryer.QueryRowContext(
		ctx,
		ownershipTransferEventSelect+`
		ORDER BY event_index DESC
		LIMIT 1`,
	))
	if errors.Is(err, store.ErrNotFound) {
		return store.OwnershipTransferEvent{
			EventHash: protocol.OwnershipTransferZeroHash,
		}, nil
	}
	return event, err
}

func ownershipTransferEventHeadAt(
	ctx context.Context,
	queryer ownershipTransferQueryer,
	acceptedAt string,
) (store.OwnershipTransferEvent, error) {
	event, err := scanOwnershipTransferEvent(queryer.QueryRowContext(
		ctx,
		ownershipTransferEventSelect+`
		WHERE accepted_at <= ?
		ORDER BY event_index DESC
		LIMIT 1`,
		acceptedAt,
	))
	if errors.Is(err, store.ErrNotFound) {
		return store.OwnershipTransferEvent{
			EventHash: protocol.OwnershipTransferZeroHash,
		}, nil
	}
	return event, err
}

func ownershipTransferEventByIdempotency(
	ctx context.Context,
	queryer ownershipTransferQueryer,
	idempotencyKey string,
) (store.OwnershipTransferEvent, error) {
	return scanOwnershipTransferEvent(queryer.QueryRowContext(
		ctx,
		ownershipTransferEventSelect+" WHERE idempotency_key = ?",
		idempotencyKey,
	))
}

func ownershipTransferEventsByTransfer(
	ctx context.Context,
	queryer ownershipTransferQueryer,
	transferID string,
) ([]store.OwnershipTransferEvent, error) {
	rows, err := queryer.QueryContext(
		ctx,
		ownershipTransferEventSelect+`
		WHERE transfer_id = ?
		ORDER BY event_index`,
		transferID,
	)
	if err != nil {
		return nil, fmt.Errorf("read ownership transfer events: %w", err)
	}
	defer rows.Close()
	items := make([]store.OwnershipTransferEvent, 0)
	for rows.Next() {
		item, err := scanOwnershipTransferEvent(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ownership transfer events: %w", err)
	}
	return items, nil
}

func ownershipTransferMembershipByTransfer(
	ctx context.Context,
	queryer ownershipTransferQueryer,
	transferID string,
) (store.OwnershipTransferMembership, bool, error) {
	membership, err := scanOwnershipTransferMembership(
		queryer.QueryRowContext(
			ctx,
			ownershipTransferMembershipSelect+" WHERE transfer_id = ?",
			transferID,
		),
	)
	if errors.Is(err, store.ErrNotFound) {
		return store.OwnershipTransferMembership{}, false, nil
	}
	if err != nil {
		return store.OwnershipTransferMembership{}, false, err
	}
	return membership, true, nil
}

func insertOwnershipTransferRecordTx(
	ctx context.Context,
	tx *sql.Tx,
	record store.OwnershipTransferRecord,
) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ownership_transfers (
			transfer_id, ruleset_version, exit_review_id,
			target_deployment_id, claim_action_id, source_group_id,
			target_group_id, legal_name, exit_record_hash,
			exit_verification_event_index, exit_verification_event_hash,
			exit_evidence_hash, prepared_at, record_hash, registry_scope,
			registry_key_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.TransferID,
		record.RulesetVersion,
		record.ExitReviewID,
		record.TargetDeploymentID,
		record.ClaimActionID,
		record.SourceGroupID,
		record.TargetGroupID,
		record.LegalName,
		record.ExitRecordHash,
		record.ExitVerificationEventIndex,
		record.ExitVerificationEventHash,
		record.ExitEvidenceHash,
		record.PreparedAt,
		record.RecordHash,
		record.RegistryScope,
		record.RegistryKeyID,
	); err != nil {
		return fmt.Errorf("insert ownership transfer record: %w", err)
	}
	return nil
}

func insertOwnershipTransferEventTx(
	ctx context.Context,
	tx *sql.Tx,
	event store.OwnershipTransferEvent,
) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ownership_transfer_events (
			event_index, event_id, transfer_id, action, resulting_status,
			effective_date, actor_role, actor_id, reference, evidence_hash,
			reason_code, idempotency_key, payload_hash, record_hash,
			accepted_at, previous_event_hash, previous_transfer_event_hash,
			event_hash, registry_scope, registry_key_id, signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.EventIndex,
		event.EventID,
		event.TransferID,
		event.Action,
		event.ResultingStatus,
		event.EffectiveDate,
		event.ActorRole,
		event.ActorID,
		event.Reference,
		event.EvidenceHash,
		event.ReasonCode,
		event.IdempotencyKey,
		event.PayloadHash,
		event.RecordHash,
		event.AcceptedAt,
		event.PreviousEventHash,
		event.PreviousTransferEventHash,
		event.EventHash,
		event.RegistryScope,
		event.RegistryKeyID,
		event.Signature,
	); err != nil {
		return fmt.Errorf("append ownership transfer event: %w", err)
	}
	return nil
}

func insertOwnershipTransferStateTx(
	ctx context.Context,
	tx *sql.Tx,
	state ownershipTransferState,
) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ownership_transfer_state_rows (
			event_index, event_hash, transfer_id, status,
			target_deployment_id, claim_action_id, source_group_id,
			target_group_id, legal_name, exit_review_id, exit_record_hash,
			exit_verification_event_index, exit_verification_event_hash,
			exit_evidence_hash, record_hash, latest_action,
			latest_effective_date, latest_actor_role, latest_actor_id,
			latest_reference, latest_evidence_hash, latest_reason_code,
			latest_accepted_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		state.EventIndex,
		state.EventHash,
		state.TransferID,
		state.Status,
		state.TargetDeploymentID,
		state.ClaimActionID,
		state.SourceGroupID,
		state.TargetGroupID,
		state.LegalName,
		state.ExitReviewID,
		state.ExitRecordHash,
		state.ExitVerificationEventIndex,
		state.ExitVerificationEventHash,
		state.ExitEvidenceHash,
		state.RecordHash,
		state.LatestAction,
		state.LatestEffectiveDate,
		state.LatestActorRole,
		state.LatestActorID,
		state.LatestReference,
		state.LatestEvidenceHash,
		state.LatestReasonCode,
		state.LatestAcceptedAt,
	); err != nil {
		return fmt.Errorf("append ownership transfer query row: %w", err)
	}
	return nil
}

func insertOwnershipTransferMembershipTx(
	ctx context.Context,
	tx *sql.Tx,
	membership store.OwnershipTransferMembership,
) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ownership_transfer_memberships (
			transfer_id, completion_event_index, completion_event_hash,
			target_deployment_id, claim_action_id, source_group_id,
			target_group_id, effective_date, through_audit_index,
			audit_head_hash, completed_at, membership_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		membership.TransferID,
		membership.CompletionEventIndex,
		membership.CompletionEventHash,
		membership.TargetDeploymentID,
		membership.ClaimActionID,
		membership.SourceGroupID,
		membership.TargetGroupID,
		membership.EffectiveDate,
		membership.ThroughAuditIndex,
		membership.AuditHeadHash,
		membership.CompletedAt,
		membership.MembershipHash,
	); err != nil {
		return fmt.Errorf("append ownership transfer membership: %w", err)
	}
	return nil
}

func scanOwnershipTransferRecord(
	scanner rowScanner,
) (store.OwnershipTransferRecord, error) {
	var record store.OwnershipTransferRecord
	if err := scanner.Scan(
		&record.TransferID,
		&record.RulesetVersion,
		&record.ExitReviewID,
		&record.TargetDeploymentID,
		&record.ClaimActionID,
		&record.SourceGroupID,
		&record.TargetGroupID,
		&record.LegalName,
		&record.ExitRecordHash,
		&record.ExitVerificationEventIndex,
		&record.ExitVerificationEventHash,
		&record.ExitEvidenceHash,
		&record.PreparedAt,
		&record.RecordHash,
		&record.RegistryScope,
		&record.RegistryKeyID,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.OwnershipTransferRecord{}, store.ErrNotFound
		}
		return store.OwnershipTransferRecord{},
			fmt.Errorf("read ownership transfer record: %w", err)
	}
	return record, nil
}

func scanOwnershipTransferEvent(
	scanner rowScanner,
) (store.OwnershipTransferEvent, error) {
	var event store.OwnershipTransferEvent
	if err := scanner.Scan(
		&event.EventIndex,
		&event.EventID,
		&event.TransferID,
		&event.Action,
		&event.ResultingStatus,
		&event.EffectiveDate,
		&event.ActorRole,
		&event.ActorID,
		&event.Reference,
		&event.EvidenceHash,
		&event.ReasonCode,
		&event.IdempotencyKey,
		&event.PayloadHash,
		&event.RecordHash,
		&event.AcceptedAt,
		&event.PreviousEventHash,
		&event.PreviousTransferEventHash,
		&event.EventHash,
		&event.RegistryScope,
		&event.RegistryKeyID,
		&event.Signature,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.OwnershipTransferEvent{}, store.ErrNotFound
		}
		return store.OwnershipTransferEvent{},
			fmt.Errorf("read ownership transfer event: %w", err)
	}
	return event, nil
}

func scanOwnershipTransferState(
	scanner rowScanner,
) (ownershipTransferState, error) {
	var state ownershipTransferState
	if err := scanner.Scan(
		&state.EventIndex,
		&state.EventHash,
		&state.TransferID,
		&state.Status,
		&state.TargetDeploymentID,
		&state.ClaimActionID,
		&state.SourceGroupID,
		&state.TargetGroupID,
		&state.LegalName,
		&state.ExitReviewID,
		&state.ExitRecordHash,
		&state.ExitVerificationEventIndex,
		&state.ExitVerificationEventHash,
		&state.ExitEvidenceHash,
		&state.RecordHash,
		&state.LatestAction,
		&state.LatestEffectiveDate,
		&state.LatestActorRole,
		&state.LatestActorID,
		&state.LatestReference,
		&state.LatestEvidenceHash,
		&state.LatestReasonCode,
		&state.LatestAcceptedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ownershipTransferState{}, store.ErrNotFound
		}
		return ownershipTransferState{},
			fmt.Errorf("read ownership transfer query row: %w", err)
	}
	return state, nil
}

func scanOwnershipTransferMembership(
	scanner rowScanner,
) (store.OwnershipTransferMembership, error) {
	var membership store.OwnershipTransferMembership
	if err := scanner.Scan(
		&membership.TransferID,
		&membership.CompletionEventIndex,
		&membership.CompletionEventHash,
		&membership.TargetDeploymentID,
		&membership.ClaimActionID,
		&membership.SourceGroupID,
		&membership.TargetGroupID,
		&membership.EffectiveDate,
		&membership.ThroughAuditIndex,
		&membership.AuditHeadHash,
		&membership.CompletedAt,
		&membership.MembershipHash,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.OwnershipTransferMembership{}, store.ErrNotFound
		}
		return store.OwnershipTransferMembership{},
			fmt.Errorf("read ownership transfer membership: %w", err)
	}
	return membership, nil
}

func ownershipTransferStateFromEvent(
	record store.OwnershipTransferRecord,
	event store.OwnershipTransferEvent,
) ownershipTransferState {
	return ownershipTransferState{
		EventIndex:                 event.EventIndex,
		EventHash:                  event.EventHash,
		TransferID:                 record.TransferID,
		Status:                     event.ResultingStatus,
		TargetDeploymentID:         record.TargetDeploymentID,
		ClaimActionID:              record.ClaimActionID,
		SourceGroupID:              record.SourceGroupID,
		TargetGroupID:              record.TargetGroupID,
		LegalName:                  record.LegalName,
		ExitReviewID:               record.ExitReviewID,
		ExitRecordHash:             record.ExitRecordHash,
		ExitVerificationEventIndex: record.ExitVerificationEventIndex,
		ExitVerificationEventHash:  record.ExitVerificationEventHash,
		ExitEvidenceHash:           record.ExitEvidenceHash,
		RecordHash:                 record.RecordHash,
		LatestAction:               event.Action,
		LatestEffectiveDate:        event.EffectiveDate,
		LatestActorRole:            event.ActorRole,
		LatestActorID:              event.ActorID,
		LatestReference:            event.Reference,
		LatestEvidenceHash:         event.EvidenceHash,
		LatestReasonCode:           event.ReasonCode,
		LatestAcceptedAt:           event.AcceptedAt,
	}
}

func ownershipTransferFromState(
	record store.OwnershipTransferRecord,
	state ownershipTransferState,
) store.OwnershipTransfer {
	return store.OwnershipTransfer{
		Record:              record,
		Status:              state.Status,
		LatestEventIndex:    state.EventIndex,
		LatestEventHash:     state.EventHash,
		LatestAction:        state.LatestAction,
		LatestEffectiveDate: state.LatestEffectiveDate,
		LatestActorRole:     state.LatestActorRole,
		LatestActorID:       state.LatestActorID,
		LatestReference:     state.LatestReference,
		LatestEvidenceHash:  state.LatestEvidenceHash,
		LatestReasonCode:    state.LatestReasonCode,
		LatestAcceptedAt:    state.LatestAcceptedAt,
	}
}

func activeOwnershipTransferForClaimTx(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	claimActionID string,
) (bool, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM ownership_transfer_state_rows state
		WHERE state.target_deployment_id = ?
		  AND state.claim_action_id = ?
		  AND state.event_index = (
			SELECT MAX(latest.event_index)
			FROM ownership_transfer_state_rows latest
			WHERE latest.transfer_id = state.transfer_id
		  )
		  AND state.status IN ('prepared', 'approved')`,
		deploymentID,
		claimActionID,
	).Scan(&count); err != nil {
		return false, fmt.Errorf("inspect active ownership transfers: %w", err)
	}
	return count > 0, nil
}

func currentOwnershipTransferClaimTx(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	claimActionID string,
	sourceGroupID string,
) (string, error) {
	var legalName string
	if err := tx.QueryRowContext(ctx, `
		SELECT status.legal_name
		FROM operator_claim_status status
		JOIN operator_claim_eligibility_current eligibility
		  ON eligibility.deployment_id = status.deployment_id
		 AND eligibility.claim_action_id = status.claim_action_id
		 AND eligibility.group_id = status.group_id
		WHERE status.deployment_id = ?
		  AND status.claim_action_id = ?
		  AND status.group_id = ?
		  AND status.verification_state = 'approved'
		  AND eligibility.eligibility_state = 'active'`,
		deploymentID,
		claimActionID,
		sourceGroupID,
	).Scan(&legalName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", store.ErrOwnershipTransferClaimBoundary
		}
		return "", fmt.Errorf("read current ownership transfer claim: %w", err)
	}
	var effectiveGroupID string
	if err := tx.QueryRowContext(ctx, `
		WITH current_operator AS (
			SELECT *
			FROM operator_network_state_rows
			WHERE deployment_id = ?
			ORDER BY audit_index DESC
			LIMIT 1
		),
		current_transfer AS (
			SELECT membership.*
			FROM ownership_transfer_memberships membership
			WHERE membership.target_deployment_id = ?
			  AND membership.claim_action_id = ?
			ORDER BY membership.completion_event_index DESC
			LIMIT 1
		)
		SELECT CASE
			WHEN transfer.transfer_id IS NOT NULL
			 AND transfer.through_audit_index >= operator.audit_index
				THEN transfer.target_group_id
			ELSE operator.effective_group_id
		END
		FROM current_operator operator
		LEFT JOIN current_transfer transfer ON TRUE`,
		deploymentID,
		deploymentID,
		claimActionID,
	).Scan(&effectiveGroupID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", store.ErrOwnershipTransferClaimBoundary
		}
		return "", fmt.Errorf("read current source group membership: %w", err)
	}
	if effectiveGroupID != sourceGroupID {
		return "", store.ErrOwnershipTransferClaimBoundary
	}
	return legalName, nil
}

func exactVerifiedExitReviewTx(
	ctx context.Context,
	tx *sql.Tx,
	reviewID string,
	deploymentID string,
	claimActionID string,
	sourceGroupID string,
	verificationEventHash string,
) (store.ExitReview, store.ExitReviewEvent, error) {
	review, err := exitReviewByIDQuery(ctx, tx, reviewID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.ExitReview{}, store.ExitReviewEvent{},
				store.ErrOwnershipTransferExitBoundary
		}
		return store.ExitReview{}, store.ExitReviewEvent{}, err
	}
	if review.Status != protocol.ExitReviewStatusEligible ||
		review.Record.TargetDeploymentID != deploymentID ||
		review.Record.ClaimActionID != claimActionID ||
		review.Record.GroupID != sourceGroupID ||
		review.LatestEventHash != verificationEventHash ||
		review.LatestAction != protocol.ExitReviewActionVerify {
		return store.ExitReview{}, store.ExitReviewEvent{},
			store.ErrOwnershipTransferExitBoundary
	}
	event, err := scanExitReviewEvent(tx.QueryRowContext(
		ctx,
		exitReviewEventSelect+`
		WHERE review_id = ?
		  AND event_hash = ?
		  AND action = 'verify'
		  AND resulting_status = 'verified-eligible'`,
		reviewID,
		verificationEventHash,
	))
	if err != nil ||
		event.EventIndex != review.LatestEventIndex ||
		event.RecordHash != review.Record.RecordHash {
		return store.ExitReview{}, store.ExitReviewEvent{},
			store.ErrOwnershipTransferExitBoundary
	}
	return review, event, nil
}

func targetGroupHasEligibleClaimTx(
	ctx context.Context,
	tx *sql.Tx,
	targetGroupID string,
) (bool, error) {
	var found int
	err := tx.QueryRowContext(ctx, `
		WITH
		operator_ranked AS (
			SELECT
				state.*,
				ROW_NUMBER() OVER (
					PARTITION BY state.deployment_id
					ORDER BY state.audit_index DESC
				) AS rank
			FROM operator_network_state_rows state
		),
		operators AS (
			SELECT *
			FROM operator_ranked
			WHERE rank = 1
		),
		transfer_ranked AS (
			SELECT
				membership.*,
				ROW_NUMBER() OVER (
					PARTITION BY membership.target_deployment_id
					ORDER BY membership.completion_event_index DESC
				) AS rank
			FROM ownership_transfer_memberships membership
		),
		transfers AS (
			SELECT *
			FROM transfer_ranked
			WHERE rank = 1
		)
		SELECT 1
		FROM operator_claim_status status
		JOIN operator_claim_eligibility_current eligibility
		  ON eligibility.deployment_id = status.deployment_id
		 AND eligibility.claim_action_id = status.claim_action_id
		JOIN operators operator
		  ON operator.deployment_id = status.deployment_id
		LEFT JOIN transfers transfer
		  ON transfer.target_deployment_id = status.deployment_id
		 AND transfer.claim_action_id = status.claim_action_id
		 AND transfer.through_audit_index >= operator.audit_index
		WHERE status.verification_state = 'approved'
		  AND status.group_id = ?
		  AND eligibility.eligibility_state = 'active'
		  AND operator.active = 1
		  AND operator.claimed = 1
		  AND CASE
			WHEN transfer.transfer_id IS NOT NULL
				THEN transfer.target_group_id
			ELSE operator.effective_group_id
		  END = ?
		LIMIT 1`,
		targetGroupID,
		targetGroupID,
	).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("verify ownership transfer target group: %w", err)
	}
	return found == 1, nil
}

func ensureTransferCompletionAfterLedgerHead(
	ctx context.Context,
	tx *sql.Tx,
	acceptedAt string,
) error {
	var ledgerAcceptedAt string
	err := tx.QueryRowContext(ctx, `
		SELECT accepted_at
		FROM ledger_entries
		ORDER BY ledger_index DESC
		LIMIT 1`).Scan(&ledgerAcceptedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read ledger head before ownership completion: %w", err)
	}
	if acceptedAt <= ledgerAcceptedAt {
		return store.ErrOwnershipTransferClockBeforeHead
	}
	return nil
}

func ensureTransferCompletionAfterOperatorHead(
	ctx context.Context,
	tx *sql.Tx,
	acceptedAt string,
) error {
	head, err := operatorAuditHeadTx(ctx, tx)
	if err != nil {
		return err
	}
	if head.AcceptedAt != "" && acceptedAt <= head.AcceptedAt {
		return store.ErrOwnershipTransferClockBeforeHead
	}
	return nil
}

func ensureOperatorActionAfterOwnershipTransfer(
	ctx context.Context,
	tx *sql.Tx,
	acceptedAt string,
) error {
	var completedAt string
	err := tx.QueryRowContext(ctx, `
		SELECT completed_at
		FROM ownership_transfer_memberships
		ORDER BY completion_event_index DESC
		LIMIT 1`).Scan(&completedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf(
			"read ownership transfer head before operator action: %w",
			err,
		)
	}
	if acceptedAt <= completedAt {
		return store.ErrAcceptedAtBeforeHead
	}
	return nil
}

func validOwnershipTransferTransition(
	currentStatus string,
	action string,
	resultingStatus string,
) bool {
	switch action {
	case protocol.OwnershipTransferActionApprove:
		return currentStatus == protocol.OwnershipTransferStatusPrepared &&
			resultingStatus == protocol.OwnershipTransferStatusApproved
	case protocol.OwnershipTransferActionReject:
		return currentStatus == protocol.OwnershipTransferStatusPrepared &&
			resultingStatus == protocol.OwnershipTransferStatusRejected
	case protocol.OwnershipTransferActionCancel:
		return (currentStatus == protocol.OwnershipTransferStatusPrepared ||
			currentStatus == protocol.OwnershipTransferStatusApproved) &&
			resultingStatus == protocol.OwnershipTransferStatusCancelled
	case protocol.OwnershipTransferActionComplete:
		return currentStatus == protocol.OwnershipTransferStatusApproved &&
			resultingStatus == protocol.OwnershipTransferStatusCompleted
	default:
		return false
	}
}

func ensureOwnershipTransferAcceptedAt(
	previous string,
	acceptedAt string,
) error {
	if previous == "" {
		return nil
	}
	previousTime, previousErr := time.Parse(time.RFC3339Nano, previous)
	acceptedTime, acceptedErr := time.Parse(time.RFC3339Nano, acceptedAt)
	if previousErr != nil ||
		acceptedErr != nil ||
		acceptedTime.Before(previousTime) {
		return store.ErrOwnershipTransferClockBeforeHead
	}
	return nil
}

func ownershipTransferProtocolRecord(
	record store.OwnershipTransferRecord,
) protocol.OwnershipTransferRecord {
	return protocol.OwnershipTransferRecord{
		TransferID:                 record.TransferID,
		RulesetVersion:             record.RulesetVersion,
		ExitReviewID:               record.ExitReviewID,
		TargetDeploymentID:         record.TargetDeploymentID,
		ClaimActionID:              record.ClaimActionID,
		SourceGroupID:              record.SourceGroupID,
		TargetGroupID:              record.TargetGroupID,
		LegalName:                  record.LegalName,
		ExitRecordHash:             record.ExitRecordHash,
		ExitVerificationEventIndex: record.ExitVerificationEventIndex,
		ExitVerificationEventHash:  record.ExitVerificationEventHash,
		ExitEvidenceHash:           record.ExitEvidenceHash,
		PreparedAt:                 record.PreparedAt,
		RecordHash:                 record.RecordHash,
		RegistryScope:              record.RegistryScope,
		RegistryKeyID:              record.RegistryKeyID,
	}
}

func ownershipTransferProtocolEvent(
	event store.OwnershipTransferEvent,
) protocol.OwnershipTransferEvent {
	return protocol.OwnershipTransferEvent{
		EventIndex:                event.EventIndex,
		EventID:                   event.EventID,
		TransferID:                event.TransferID,
		Action:                    event.Action,
		ResultingStatus:           event.ResultingStatus,
		EffectiveDate:             event.EffectiveDate,
		ActorRole:                 event.ActorRole,
		ActorID:                   event.ActorID,
		Reference:                 event.Reference,
		EvidenceHash:              event.EvidenceHash,
		ReasonCode:                event.ReasonCode,
		IdempotencyKey:            event.IdempotencyKey,
		PayloadHash:               event.PayloadHash,
		RecordHash:                event.RecordHash,
		AcceptedAt:                event.AcceptedAt,
		PreviousEventHash:         event.PreviousEventHash,
		PreviousTransferEventHash: event.PreviousTransferEventHash,
		EventHash:                 event.EventHash,
		RegistryScope:             event.RegistryScope,
		RegistryKeyID:             event.RegistryKeyID,
	}
}

func ownershipTransferProtocolMembership(
	membership store.OwnershipTransferMembership,
) protocol.OwnershipTransferMembership {
	return protocol.OwnershipTransferMembership{
		TransferID:           membership.TransferID,
		CompletionEventIndex: membership.CompletionEventIndex,
		CompletionEventHash:  membership.CompletionEventHash,
		TargetDeploymentID:   membership.TargetDeploymentID,
		ClaimActionID:        membership.ClaimActionID,
		SourceGroupID:        membership.SourceGroupID,
		TargetGroupID:        membership.TargetGroupID,
		EffectiveDate:        membership.EffectiveDate,
		ThroughAuditIndex:    membership.ThroughAuditIndex,
		AuditHeadHash:        membership.AuditHeadHash,
		CompletedAt:          membership.CompletedAt,
		MembershipHash:       membership.MembershipHash,
	}
}
