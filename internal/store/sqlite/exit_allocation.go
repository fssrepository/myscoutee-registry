package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const exitAllocationRecordSelect = `
	SELECT
		allocation_id,
		ruleset_version,
		exit_review_id,
		target_deployment_id,
		claim_action_id,
		source_group_id,
		exit_record_hash,
		exit_verification_event_index,
		exit_verification_event_hash,
		exit_evidence_hash,
		decision_mode,
		ownership_transfer_id,
		ownership_transfer_completion_event_index,
		ownership_transfer_completion_event_hash,
		through_ownership_transfer_event_index,
		ownership_transfer_head_hash,
		beneficiary_type,
		beneficiary_id,
		contract_reference,
		contract_terms_hash,
		evidence_hash,
		settlement_source_count,
		settlement_source_hash,
		currency_allocation_count,
		currency_allocation_hash,
		created_at,
		record_hash,
		registry_scope,
		registry_key_id
	FROM exit_allocations`

const exitAllocationSourceSelect = `
	SELECT
		boundary_order,
		settlement_id,
		period,
		currency_code,
		fraction_digits,
		revision,
		ledger_index,
		settlement_hash,
		source_fingerprint,
		settlement_allocation_hash,
		distributable_minor
	FROM exit_allocation_settlement_sources`

const exitAllocationCurrencySelect = `
	SELECT
		allocation_order,
		currency_code,
		fraction_digits,
		distributable_minor,
		allocated_minor,
		beneficiary_type,
		beneficiary_id
	FROM exit_allocation_currency_allocations`

const exitAllocationEventSelect = `
	SELECT
		event_index,
		event_id,
		allocation_id,
		action,
		resulting_status,
		actor_role,
		actor_id,
		reference,
		evidence_hash,
		idempotency_key,
		payload_hash,
		record_hash,
		accepted_at,
		previous_event_hash,
		previous_allocation_event_hash,
		event_hash,
		registry_scope,
		registry_key_id,
		signature
	FROM exit_allocation_events`

const exitAllocationStateSelect = `
	SELECT
		event_index,
		event_hash,
		allocation_id,
		status,
		decision_mode,
		beneficiary_type,
		beneficiary_id,
		exit_review_id,
		target_deployment_id,
		claim_action_id,
		source_group_id,
		ownership_transfer_id,
		settlement_source_count,
		settlement_source_hash,
		currency_allocation_count,
		currency_allocation_hash,
		record_hash,
		latest_action,
		latest_actor_role,
		latest_actor_id,
		latest_reference,
		latest_evidence_hash,
		latest_accepted_at
	FROM exit_allocation_state_rows`

type exitAllocationState struct {
	EventIndex              int64
	EventHash               string
	AllocationID            string
	Status                  string
	DecisionMode            string
	BeneficiaryType         string
	BeneficiaryID           string
	ExitReviewID            string
	TargetDeploymentID      string
	ClaimActionID           string
	SourceGroupID           string
	OwnershipTransferID     string
	SettlementSourceCount   int64
	SettlementSourceHash    string
	CurrencyAllocationCount int64
	CurrencyAllocationHash  string
	RecordHash              string
	LatestAction            string
	LatestActorRole         string
	LatestActorID           string
	LatestReference         string
	LatestEvidenceHash      string
	LatestAcceptedAt        string
}

func (sqliteStore *Store) CreateExitAllocation(
	ctx context.Context,
	input store.ExitAllocationCreateInput,
	signEvent store.ExitAllocationEventSigner,
) (store.ExitAllocationEvent, store.ExitAllocation, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
			fmt.Errorf("begin final exit allocation create: %w", err)
	}
	defer tx.Rollback()

	existing, err := exitAllocationEventByIdempotency(
		ctx,
		tx,
		input.IdempotencyKey,
	)
	if err == nil {
		current, readErr := exitAllocationByIDQuery(
			ctx,
			tx,
			existing.AllocationID,
		)
		if readErr != nil {
			return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
				readErr
		}
		record := current.Record
		if existing.Action != protocol.ExitAllocationActionCreate ||
			record.ExitReviewID != input.ExitReviewID ||
			record.ExitVerificationEventHash !=
				input.ExitVerificationEventHash ||
			record.DecisionMode != input.DecisionMode ||
			record.OwnershipTransferID != input.OwnershipTransferID ||
			record.OwnershipTransferCompletionEventHash !=
				normalizedExitAllocationTransferHash(input) ||
			(input.DecisionMode ==
				protocol.ExitAllocationDecisionNoTransfer &&
				record.BeneficiaryID != input.BeneficiaryID) ||
			record.ContractReference != input.ContractReference ||
			record.ContractTermsHash != input.ContractTermsHash ||
			record.EvidenceHash != input.EvidenceHash ||
			existing.ActorID != input.ActorID {
			return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
				store.ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
				fmt.Errorf(
					"commit duplicate final exit allocation create: %w",
					err,
				)
		}
		return existing, current, true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	if err := ensureAcceptedAtAfterRegistryCreation(
		ctx,
		tx,
		input.AcceptedAt,
	); err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	head, err := exitAllocationEventHeadQuery(ctx, tx)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	if err := ensureExitAllocationAcceptedAt(
		head.AcceptedAt,
		input.AcceptedAt,
	); err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	var existingAllocationID string
	err = tx.QueryRowContext(ctx, `
		SELECT allocation_id
		FROM exit_allocations
		WHERE exit_review_id = ?`,
		input.ExitReviewID,
	).Scan(&existingAllocationID)
	if err == nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
			store.ErrExitAllocationAlreadyExists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
			fmt.Errorf("check existing final exit allocation: %w", err)
	}

	review, exitEvent, err := exactExitAllocationReviewTx(
		ctx,
		tx,
		input.ExitReviewID,
		input.ExitVerificationEventHash,
	)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	transferHead, err := ownershipTransferEventHeadQuery(ctx, tx)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	beneficiaryType, beneficiaryID, transferEventIndex, transferEventHash,
		err := resolveExitAllocationDecisionTx(
		ctx,
		tx,
		review,
		input.DecisionMode,
		input.OwnershipTransferID,
		input.OwnershipTransferCompletionEventHash,
		input.BeneficiaryID,
	)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	sources, currencies, err := deriveExitAllocationRowsTx(
		ctx,
		tx,
		review,
		beneficiaryType,
		beneficiaryID,
	)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	if err := ensureExitAllocationSourceClockTx(
		ctx,
		tx,
		input.AcceptedAt,
		exitEvent.AcceptedAt,
		transferHead.AcceptedAt,
		sources,
	); err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}

	record := store.ExitAllocationRecord{
		AllocationID:                          input.CandidateAllocationID,
		RulesetVersion:                        protocol.ExitAllocationRulesetVersion,
		ExitReviewID:                          review.Record.ReviewID,
		TargetDeploymentID:                    review.Record.TargetDeploymentID,
		ClaimActionID:                         review.Record.ClaimActionID,
		SourceGroupID:                         review.Record.GroupID,
		ExitRecordHash:                        review.Record.RecordHash,
		ExitVerificationEventIndex:            exitEvent.EventIndex,
		ExitVerificationEventHash:             exitEvent.EventHash,
		ExitEvidenceHash:                      exitEvent.EvidenceHash,
		DecisionMode:                          input.DecisionMode,
		OwnershipTransferID:                   input.OwnershipTransferID,
		OwnershipTransferCompletionEventIndex: transferEventIndex,
		OwnershipTransferCompletionEventHash:  transferEventHash,
		ThroughOwnershipTransferEventIndex:    transferHead.EventIndex,
		OwnershipTransferHeadHash:             transferHead.EventHash,
		BeneficiaryType:                       beneficiaryType,
		BeneficiaryID:                         beneficiaryID,
		ContractReference:                     input.ContractReference,
		ContractTermsHash:                     input.ContractTermsHash,
		EvidenceHash:                          input.EvidenceHash,
		SettlementSourceCount:                 int64(len(sources)),
		SettlementSourceHash: protocol.ExitAllocationSettlementSourceHash(
			exitAllocationProtocolSources(sources),
		),
		CurrencyAllocationCount: int64(len(currencies)),
		CurrencyAllocationHash: protocol.ExitAllocationCurrencyHash(
			exitAllocationProtocolCurrencies(currencies),
		),
		CreatedAt:           input.AcceptedAt,
		RegistryScope:       input.RegistryScope,
		RegistryKeyID:       input.RegistryKeyID,
		SettlementSources:   sources,
		CurrencyAllocations: currencies,
	}
	record.RecordHash = protocol.Digest(
		protocol.ExitAllocationRecordHashMessage(
			exitAllocationProtocolRecord(record),
		),
	)
	event := store.ExitAllocationEvent{
		EventIndex:                  head.EventIndex + 1,
		EventID:                     input.CandidateEventID,
		AllocationID:                record.AllocationID,
		Action:                      protocol.ExitAllocationActionCreate,
		ResultingStatus:             protocol.ExitAllocationStatusRecorded,
		ActorRole:                   protocol.ExitAllocationActorAllocator,
		ActorID:                     input.ActorID,
		Reference:                   input.ContractReference,
		EvidenceHash:                input.EvidenceHash,
		IdempotencyKey:              input.IdempotencyKey,
		RecordHash:                  record.RecordHash,
		AcceptedAt:                  input.AcceptedAt,
		PreviousEventHash:           head.EventHash,
		PreviousAllocationEventHash: protocol.ExitAllocationZeroHash,
		RegistryScope:               input.RegistryScope,
		RegistryKeyID:               input.RegistryKeyID,
	}
	event.PayloadHash = protocol.Digest(
		protocol.ExitAllocationEventPayloadMessage(
			exitAllocationProtocolEvent(event),
		),
	)
	event.EventHash = protocol.Digest(
		protocol.ExitAllocationEventHashMessage(
			exitAllocationProtocolEvent(event),
		),
	)
	event.Signature, err = signEvent(event)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
			fmt.Errorf("sign final exit allocation create event: %w", err)
	}
	if err := insertExitAllocationRecordTx(ctx, tx, record); err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	for _, source := range sources {
		if err := insertExitAllocationSourceTx(
			ctx,
			tx,
			record.AllocationID,
			source,
		); err != nil {
			return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
		}
	}
	for _, allocation := range currencies {
		if err := insertExitAllocationCurrencyTx(
			ctx,
			tx,
			record.AllocationID,
			allocation,
		); err != nil {
			return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
		}
	}
	if err := insertExitAllocationEventTx(ctx, tx, event); err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	if err := insertExitAllocationStateTx(
		ctx,
		tx,
		exitAllocationStateFromEvent(record, event),
	); err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
			fmt.Errorf("commit final exit allocation create: %w", err)
	}
	allocation, err := sqliteStore.ExitAllocation(ctx, record.AllocationID)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	return event, allocation, false, nil
}

func (sqliteStore *Store) VerifyExitAllocation(
	ctx context.Context,
	input store.ExitAllocationVerifyInput,
	signEvent store.ExitAllocationEventSigner,
) (store.ExitAllocationEvent, store.ExitAllocation, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
			fmt.Errorf("begin final exit allocation verify: %w", err)
	}
	defer tx.Rollback()
	existing, err := exitAllocationEventByIdempotency(
		ctx,
		tx,
		input.IdempotencyKey,
	)
	if err == nil {
		current, readErr := exitAllocationByIDQuery(
			ctx,
			tx,
			existing.AllocationID,
		)
		if readErr != nil {
			return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
				readErr
		}
		if existing.AllocationID != input.AllocationID ||
			existing.Action != protocol.ExitAllocationActionVerify ||
			existing.ActorID != input.ActorID ||
			existing.Reference != input.Reference ||
			existing.EvidenceHash != input.EvidenceHash ||
			existing.PayloadHash != input.PayloadHash {
			return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
				store.ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
				fmt.Errorf(
					"commit duplicate final exit allocation verify: %w",
					err,
				)
		}
		return existing, current, true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	if err := ensureAcceptedAtAfterRegistryCreation(
		ctx,
		tx,
		input.AcceptedAt,
	); err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	head, err := exitAllocationEventHeadQuery(ctx, tx)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	if err := ensureExitAllocationAcceptedAt(
		head.AcceptedAt,
		input.AcceptedAt,
	); err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	current, err := exitAllocationByIDQuery(ctx, tx, input.AllocationID)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	if current.Status != protocol.ExitAllocationStatusRecorded ||
		current.LatestAction != protocol.ExitAllocationActionCreate {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
			store.ErrExitAllocationTransition
	}
	review, _, err := exactExitAllocationReviewTx(
		ctx,
		tx,
		current.Record.ExitReviewID,
		current.Record.ExitVerificationEventHash,
	)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	beneficiaryType, beneficiaryID, transferIndex, transferHash, err :=
		resolveExitAllocationDecisionTx(
			ctx,
			tx,
			review,
			current.Record.DecisionMode,
			current.Record.OwnershipTransferID,
			current.Record.OwnershipTransferCompletionEventHash,
			current.Record.BeneficiaryID,
		)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	if beneficiaryType != current.Record.BeneficiaryType ||
		beneficiaryID != current.Record.BeneficiaryID ||
		transferIndex !=
			current.Record.OwnershipTransferCompletionEventIndex ||
		transferHash !=
			current.Record.OwnershipTransferCompletionEventHash {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
			store.ErrExitAllocationTransferBoundary
	}
	sources, currencies, err := deriveExitAllocationRowsTx(
		ctx,
		tx,
		review,
		beneficiaryType,
		beneficiaryID,
	)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	if !equalExitAllocationSources(
		sources,
		current.Record.SettlementSources,
	) || !equalExitAllocationCurrencies(
		currencies,
		current.Record.CurrencyAllocations,
	) {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
			store.ErrExitAllocationConservation
	}
	event := store.ExitAllocationEvent{
		EventIndex:                  head.EventIndex + 1,
		EventID:                     input.CandidateEventID,
		AllocationID:                current.Record.AllocationID,
		Action:                      protocol.ExitAllocationActionVerify,
		ResultingStatus:             protocol.ExitAllocationStatusVerifiedFinal,
		ActorRole:                   protocol.ExitAllocationActorVerifier,
		ActorID:                     input.ActorID,
		Reference:                   input.Reference,
		EvidenceHash:                input.EvidenceHash,
		IdempotencyKey:              input.IdempotencyKey,
		PayloadHash:                 input.PayloadHash,
		RecordHash:                  current.Record.RecordHash,
		AcceptedAt:                  input.AcceptedAt,
		PreviousEventHash:           head.EventHash,
		PreviousAllocationEventHash: current.LatestEventHash,
		RegistryScope:               input.RegistryScope,
		RegistryKeyID:               input.RegistryKeyID,
	}
	event.EventHash = protocol.Digest(
		protocol.ExitAllocationEventHashMessage(
			exitAllocationProtocolEvent(event),
		),
	)
	event.Signature, err = signEvent(event)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
			fmt.Errorf("sign final exit allocation verify event: %w", err)
	}
	if err := insertExitAllocationEventTx(ctx, tx, event); err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	if err := insertExitAllocationStateTx(
		ctx,
		tx,
		exitAllocationStateFromEvent(current.Record, event),
	); err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false,
			fmt.Errorf("commit final exit allocation verify: %w", err)
	}
	allocation, err := sqliteStore.ExitAllocation(ctx, input.AllocationID)
	if err != nil {
		return store.ExitAllocationEvent{}, store.ExitAllocation{}, false, err
	}
	return event, allocation, false, nil
}

func (sqliteStore *Store) ExitAllocation(
	ctx context.Context,
	allocationID string,
) (store.ExitAllocation, error) {
	return exitAllocationByIDQuery(ctx, sqliteStore.db, allocationID)
}

func (sqliteStore *Store) ExitAllocations(
	ctx context.Context,
	query store.ExitAllocationQuery,
) (store.ExitAllocationPage, error) {
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		exitAllocationStateSelect+`
		WHERE event_index = (
			SELECT MAX(latest.event_index)
			FROM exit_allocation_state_rows latest
			WHERE latest.allocation_id =
				exit_allocation_state_rows.allocation_id
		)
		  AND (? = '' OR status = ?)
		  AND (? = '' OR decision_mode = ?)
		  AND (? = 0 OR event_index < ?)
		ORDER BY event_index DESC
		LIMIT ?`,
		query.Status,
		query.Status,
		query.DecisionMode,
		query.DecisionMode,
		query.BeforeEventIndex,
		query.BeforeEventIndex,
		query.Limit+1,
	)
	if err != nil {
		return store.ExitAllocationPage{},
			fmt.Errorf("list final exit allocation state rows: %w", err)
	}
	defer rows.Close()
	states := make([]exitAllocationState, 0, query.Limit+1)
	for rows.Next() {
		state, scanErr := scanExitAllocationState(rows)
		if scanErr != nil {
			return store.ExitAllocationPage{}, scanErr
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return store.ExitAllocationPage{},
			fmt.Errorf("iterate final exit allocation state rows: %w", err)
	}
	page := store.ExitAllocationPage{}
	for index, state := range states {
		if index == query.Limit {
			page.NextEventIndex = states[index-1].EventIndex
			break
		}
		record, err := exitAllocationRecordByID(
			ctx,
			sqliteStore.db,
			state.AllocationID,
		)
		if err != nil {
			return store.ExitAllocationPage{}, err
		}
		page.Items = append(
			page.Items,
			exitAllocationFromState(record, state),
		)
	}
	return page, nil
}

func exitAllocationByIDQuery(
	ctx context.Context,
	queryer ownershipTransferQueryer,
	allocationID string,
) (store.ExitAllocation, error) {
	record, err := exitAllocationRecordByID(ctx, queryer, allocationID)
	if err != nil {
		return store.ExitAllocation{}, err
	}
	state, err := scanExitAllocationState(queryer.QueryRowContext(
		ctx,
		exitAllocationStateSelect+`
		WHERE allocation_id = ?
		ORDER BY event_index DESC
		LIMIT 1`,
		allocationID,
	))
	if err != nil {
		return store.ExitAllocation{}, err
	}
	result := exitAllocationFromState(record, state)
	result.Events, err = exitAllocationEventsByAllocation(
		ctx,
		queryer,
		allocationID,
	)
	if err != nil {
		return store.ExitAllocation{}, err
	}
	return result, nil
}

func exitAllocationRecordByID(
	ctx context.Context,
	queryer ownershipTransferQueryer,
	allocationID string,
) (store.ExitAllocationRecord, error) {
	record, err := scanExitAllocationRecord(queryer.QueryRowContext(
		ctx,
		exitAllocationRecordSelect+" WHERE allocation_id = ?",
		allocationID,
	))
	if err != nil {
		return store.ExitAllocationRecord{}, err
	}
	record.SettlementSources, err = exitAllocationSourcesByAllocation(
		ctx,
		queryer,
		allocationID,
	)
	if err != nil {
		return store.ExitAllocationRecord{}, err
	}
	record.CurrencyAllocations, err = exitAllocationCurrenciesByAllocation(
		ctx,
		queryer,
		allocationID,
	)
	if err != nil {
		return store.ExitAllocationRecord{}, err
	}
	return record, nil
}

func exitAllocationSourcesByAllocation(
	ctx context.Context,
	queryer ownershipTransferQueryer,
	allocationID string,
) ([]store.ExitAllocationSettlementSource, error) {
	rows, err := queryer.QueryContext(
		ctx,
		exitAllocationSourceSelect+`
		WHERE allocation_id = ?
		ORDER BY boundary_order`,
		allocationID,
	)
	if err != nil {
		return nil, fmt.Errorf("read final exit allocation sources: %w", err)
	}
	defer rows.Close()
	items := make([]store.ExitAllocationSettlementSource, 0)
	for rows.Next() {
		item, scanErr := scanExitAllocationSource(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate final exit allocation sources: %w", err)
	}
	return items, nil
}

func exitAllocationCurrenciesByAllocation(
	ctx context.Context,
	queryer ownershipTransferQueryer,
	allocationID string,
) ([]store.ExitAllocationCurrency, error) {
	rows, err := queryer.QueryContext(
		ctx,
		exitAllocationCurrencySelect+`
		WHERE allocation_id = ?
		ORDER BY allocation_order`,
		allocationID,
	)
	if err != nil {
		return nil, fmt.Errorf("read final exit allocation currencies: %w", err)
	}
	defer rows.Close()
	items := make([]store.ExitAllocationCurrency, 0)
	for rows.Next() {
		item, scanErr := scanExitAllocationCurrency(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate final exit allocation currencies: %w", err)
	}
	return items, nil
}

func exitAllocationEventsByAllocation(
	ctx context.Context,
	queryer ownershipTransferQueryer,
	allocationID string,
) ([]store.ExitAllocationEvent, error) {
	rows, err := queryer.QueryContext(
		ctx,
		exitAllocationEventSelect+`
		WHERE allocation_id = ?
		ORDER BY event_index`,
		allocationID,
	)
	if err != nil {
		return nil, fmt.Errorf("read final exit allocation events: %w", err)
	}
	defer rows.Close()
	items := make([]store.ExitAllocationEvent, 0)
	for rows.Next() {
		item, scanErr := scanExitAllocationEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate final exit allocation events: %w", err)
	}
	return items, nil
}

func exitAllocationEventHeadQuery(
	ctx context.Context,
	queryer ownershipTransferQueryer,
) (store.ExitAllocationEvent, error) {
	event, err := scanExitAllocationEvent(queryer.QueryRowContext(
		ctx,
		exitAllocationEventSelect+`
		ORDER BY event_index DESC
		LIMIT 1`,
	))
	if errors.Is(err, store.ErrNotFound) {
		return store.ExitAllocationEvent{
			EventHash: protocol.ExitAllocationZeroHash,
		}, nil
	}
	return event, err
}

func exitAllocationEventByIdempotency(
	ctx context.Context,
	queryer ownershipTransferQueryer,
	idempotencyKey string,
) (store.ExitAllocationEvent, error) {
	return scanExitAllocationEvent(queryer.QueryRowContext(
		ctx,
		exitAllocationEventSelect+" WHERE idempotency_key = ?",
		idempotencyKey,
	))
}

func exactExitAllocationReviewTx(
	ctx context.Context,
	tx *sql.Tx,
	reviewID string,
	verificationEventHash string,
) (store.ExitReview, store.ExitReviewEvent, error) {
	review, err := exitReviewByIDQuery(ctx, tx, reviewID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.ExitReview{}, store.ExitReviewEvent{},
				store.ErrExitAllocationExitBoundary
		}
		return store.ExitReview{}, store.ExitReviewEvent{}, err
	}
	if review.Status != protocol.ExitReviewStatusEligible ||
		review.LatestAction != protocol.ExitReviewActionVerify ||
		review.LatestEventHash != verificationEventHash {
		return store.ExitReview{}, store.ExitReviewEvent{},
			store.ErrExitAllocationExitBoundary
	}
	event, err := scanExitReviewEvent(tx.QueryRowContext(
		ctx,
		exitReviewEventSelect+`
		WHERE review_id = ?
		  AND event_index = ?
		  AND event_hash = ?
		  AND action = 'verify'
		  AND resulting_status = 'verified-eligible'`,
		reviewID,
		review.LatestEventIndex,
		verificationEventHash,
	))
	if err != nil ||
		event.RecordHash != review.Record.RecordHash {
		return store.ExitReview{}, store.ExitReviewEvent{},
			store.ErrExitAllocationExitBoundary
	}
	return review, event, nil
}

func resolveExitAllocationDecisionTx(
	ctx context.Context,
	tx *sql.Tx,
	review store.ExitReview,
	decisionMode string,
	transferID string,
	completionEventHash string,
	requestedBeneficiaryID string,
) (string, string, int64, string, error) {
	switch decisionMode {
	case protocol.ExitAllocationDecisionCompletedTransfer:
		if transferID == "" ||
			!protocol.IsDigest(completionEventHash) ||
			requestedBeneficiaryID != "" {
			return "", "", 0, "", store.ErrExitAllocationTransferBoundary
		}
		transfer, err := ownershipTransferByIDQuery(ctx, tx, transferID)
		if err != nil ||
			transfer.Status != protocol.OwnershipTransferStatusCompleted ||
			transfer.LatestAction !=
				protocol.OwnershipTransferActionComplete ||
			transfer.Membership == nil ||
			transfer.Record.ExitReviewID != review.Record.ReviewID ||
			transfer.Record.TargetDeploymentID !=
				review.Record.TargetDeploymentID ||
			transfer.Record.ClaimActionID != review.Record.ClaimActionID ||
			transfer.Record.SourceGroupID != review.Record.GroupID ||
			transfer.Membership.CompletionEventHash != completionEventHash ||
			transfer.LatestEventHash != completionEventHash {
			return "", "", 0, "", store.ErrExitAllocationTransferBoundary
		}
		conflict, err := conflictingExitAllocationTransferTx(
			ctx,
			tx,
			review.Record.TargetDeploymentID,
			review.Record.ClaimActionID,
			transferID,
		)
		if err != nil {
			return "", "", 0, "", err
		}
		if conflict {
			return "", "", 0, "", store.ErrExitAllocationTransferBoundary
		}
		return protocol.ExitAllocationBeneficiaryOperatorGroup,
			transfer.Record.TargetGroupID,
			transfer.Membership.CompletionEventIndex,
			transfer.Membership.CompletionEventHash,
			nil
	case protocol.ExitAllocationDecisionNoTransfer:
		if transferID != "" ||
			completionEventHash != protocol.ExitAllocationZeroHash ||
			requestedBeneficiaryID == "" {
			return "", "", 0, "", store.ErrExitAllocationTransferBoundary
		}
		conflict, err := conflictingExitAllocationTransferTx(
			ctx,
			tx,
			review.Record.TargetDeploymentID,
			review.Record.ClaimActionID,
			"",
		)
		if err != nil {
			return "", "", 0, "", err
		}
		if conflict {
			return "", "", 0, "", store.ErrExitAllocationTransferBoundary
		}
		return protocol.ExitAllocationBeneficiaryContract,
			requestedBeneficiaryID,
			0,
			protocol.ExitAllocationZeroHash,
			nil
	default:
		return "", "", 0, "", store.ErrExitAllocationTransferBoundary
	}
}

func conflictingExitAllocationTransferTx(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	claimActionID string,
	selectedTransferID string,
) (bool, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM ownership_transfer_state_rows state
		JOIN ownership_transfers transfer
		  ON transfer.transfer_id = state.transfer_id
		WHERE state.event_index = (
			SELECT MAX(latest.event_index)
			FROM ownership_transfer_state_rows latest
			WHERE latest.transfer_id = state.transfer_id
		)
		  AND transfer.target_deployment_id = ?
		  AND transfer.claim_action_id = ?
		  AND state.status IN ('prepared', 'approved', 'completed')
		  AND (? = '' OR transfer.transfer_id <> ?)`,
		deploymentID,
		claimActionID,
		selectedTransferID,
		selectedTransferID,
	).Scan(&count); err != nil {
		return false, fmt.Errorf(
			"inspect ownership transfers for final exit allocation: %w",
			err,
		)
	}
	return count != 0, nil
}

func deriveExitAllocationRowsTx(
	ctx context.Context,
	tx *sql.Tx,
	review store.ExitReview,
	beneficiaryType string,
	beneficiaryID string,
) (
	[]store.ExitAllocationSettlementSource,
	[]store.ExitAllocationCurrency,
	error,
) {
	sources := make([]store.ExitAllocationSettlementSource, 0, len(
		review.Record.Settlements,
	))
	type total struct {
		fractionDigits int64
		minor          int64
	}
	totals := make(map[string]total)
	for _, boundary := range review.Record.Settlements {
		var source store.ExitAllocationSettlementSource
		var allocationMinor int64
		err := tx.QueryRowContext(ctx, `
			SELECT
				settlement.currency_code,
				settlement.fraction_digits,
				settlement.period,
				settlement.revision,
				settlement.ledger_index,
				settlement.settlement_hash,
				settlement.source_fingerprint,
				settlement.allocation_hash,
				COALESCE((
					SELECT allocation.network_pool_allocation_minor
					FROM settlement_allocations allocation
					WHERE allocation.settlement_id =
						settlement.settlement_id
					  AND allocation.beneficiary_type = 'OPERATOR_GROUP'
					  AND allocation.beneficiary_id = ?
				), 0)
			FROM settlements settlement
			WHERE settlement.settlement_id = ?`,
			review.Record.GroupID,
			boundary.SettlementID,
		).Scan(
			&source.CurrencyCode,
			&source.FractionDigits,
			&source.Period,
			&source.Revision,
			&source.LedgerIndex,
			&source.SettlementHash,
			&source.SourceFingerprint,
			&source.SettlementAllocationHash,
			&allocationMinor,
		)
		if err != nil {
			return nil, nil, fmt.Errorf(
				"read frozen settlement allocation source: %w",
				err,
			)
		}
		source.BoundaryOrder = boundary.BoundaryOrder
		source.SettlementID = boundary.SettlementID
		source.DistributableMinor = allocationMinor
		if source.Period != boundary.Period ||
			source.CurrencyCode != boundary.CurrencyCode ||
			source.Revision != boundary.Revision ||
			source.LedgerIndex != boundary.LedgerIndex ||
			source.SettlementHash != boundary.SettlementHash ||
			source.SourceFingerprint != boundary.SourceFingerprint ||
			source.SettlementAllocationHash != boundary.AllocationHash ||
			!protocol.SettlementMinorAmountIsSafe(allocationMinor) {
			return nil, nil, store.ErrExitAllocationConservation
		}
		current, currencyExists := totals[source.CurrencyCode]
		if currencyExists &&
			current.fractionDigits != source.FractionDigits {
			return nil, nil, store.ErrExitAllocationConservation
		}
		if current.minor >
			protocol.SettlementMaximumSafeMinor-allocationMinor {
			return nil, nil, store.ErrExitAllocationConservation
		}
		current.fractionDigits = source.FractionDigits
		current.minor += allocationMinor
		totals[source.CurrencyCode] = current
		sources = append(sources, source)
	}
	codes := make([]string, 0, len(totals))
	for code := range totals {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	currencies := make([]store.ExitAllocationCurrency, 0, len(codes))
	for index, code := range codes {
		value := totals[code]
		currencies = append(currencies, store.ExitAllocationCurrency{
			AllocationOrder:    int64(index),
			CurrencyCode:       code,
			FractionDigits:     value.fractionDigits,
			DistributableMinor: value.minor,
			AllocatedMinor:     value.minor,
			BeneficiaryType:    beneficiaryType,
			BeneficiaryID:      beneficiaryID,
		})
	}
	return sources, currencies, nil
}

func ensureExitAllocationSourceClockTx(
	ctx context.Context,
	tx *sql.Tx,
	acceptedAt string,
	exitAcceptedAt string,
	transferAcceptedAt string,
	sources []store.ExitAllocationSettlementSource,
) error {
	if acceptedAt < exitAcceptedAt ||
		(transferAcceptedAt != "" && acceptedAt < transferAcceptedAt) {
		return store.ErrExitAllocationClockBeforeHead
	}
	for _, source := range sources {
		var settlementAcceptedAt string
		if err := tx.QueryRowContext(ctx, `
			SELECT accepted_at
			FROM settlements
			WHERE settlement_id = ?`,
			source.SettlementID,
		).Scan(&settlementAcceptedAt); err != nil {
			return fmt.Errorf("read final allocation settlement clock: %w", err)
		}
		if acceptedAt < settlementAcceptedAt {
			return store.ErrExitAllocationClockBeforeHead
		}
	}
	return nil
}

func insertExitAllocationRecordTx(
	ctx context.Context,
	tx *sql.Tx,
	record store.ExitAllocationRecord,
) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO exit_allocations (
			allocation_id, ruleset_version, exit_review_id,
			target_deployment_id, claim_action_id, source_group_id,
			exit_record_hash, exit_verification_event_index,
			exit_verification_event_hash, exit_evidence_hash, decision_mode,
			ownership_transfer_id,
			ownership_transfer_completion_event_index,
			ownership_transfer_completion_event_hash,
			through_ownership_transfer_event_index,
			ownership_transfer_head_hash, beneficiary_type, beneficiary_id,
			contract_reference, contract_terms_hash, evidence_hash,
			settlement_source_count, settlement_source_hash,
			currency_allocation_count, currency_allocation_hash, created_at,
			record_hash, registry_scope, registry_key_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.AllocationID,
		record.RulesetVersion,
		record.ExitReviewID,
		record.TargetDeploymentID,
		record.ClaimActionID,
		record.SourceGroupID,
		record.ExitRecordHash,
		record.ExitVerificationEventIndex,
		record.ExitVerificationEventHash,
		record.ExitEvidenceHash,
		record.DecisionMode,
		record.OwnershipTransferID,
		record.OwnershipTransferCompletionEventIndex,
		record.OwnershipTransferCompletionEventHash,
		record.ThroughOwnershipTransferEventIndex,
		record.OwnershipTransferHeadHash,
		record.BeneficiaryType,
		record.BeneficiaryID,
		record.ContractReference,
		record.ContractTermsHash,
		record.EvidenceHash,
		record.SettlementSourceCount,
		record.SettlementSourceHash,
		record.CurrencyAllocationCount,
		record.CurrencyAllocationHash,
		record.CreatedAt,
		record.RecordHash,
		record.RegistryScope,
		record.RegistryKeyID,
	)
	if err != nil {
		return fmt.Errorf("insert final exit allocation record: %w", err)
	}
	return nil
}

func insertExitAllocationSourceTx(
	ctx context.Context,
	tx *sql.Tx,
	allocationID string,
	source store.ExitAllocationSettlementSource,
) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO exit_allocation_settlement_sources (
			allocation_id, boundary_order, settlement_id, period,
			currency_code, fraction_digits, revision, ledger_index,
			settlement_hash, source_fingerprint,
			settlement_allocation_hash, distributable_minor
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		allocationID,
		source.BoundaryOrder,
		source.SettlementID,
		source.Period,
		source.CurrencyCode,
		source.FractionDigits,
		source.Revision,
		source.LedgerIndex,
		source.SettlementHash,
		source.SourceFingerprint,
		source.SettlementAllocationHash,
		source.DistributableMinor,
	)
	if err != nil {
		return fmt.Errorf("insert final exit allocation source: %w", err)
	}
	return nil
}

func insertExitAllocationCurrencyTx(
	ctx context.Context,
	tx *sql.Tx,
	allocationID string,
	allocation store.ExitAllocationCurrency,
) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO exit_allocation_currency_allocations (
			allocation_id, allocation_order, currency_code, fraction_digits,
			distributable_minor, allocated_minor, beneficiary_type,
			beneficiary_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		allocationID,
		allocation.AllocationOrder,
		allocation.CurrencyCode,
		allocation.FractionDigits,
		allocation.DistributableMinor,
		allocation.AllocatedMinor,
		allocation.BeneficiaryType,
		allocation.BeneficiaryID,
	)
	if err != nil {
		return fmt.Errorf("insert final exit allocation currency: %w", err)
	}
	return nil
}

func insertExitAllocationEventTx(
	ctx context.Context,
	tx *sql.Tx,
	event store.ExitAllocationEvent,
) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO exit_allocation_events (
			event_index, event_id, allocation_id, action, resulting_status,
			actor_role, actor_id, reference, evidence_hash, idempotency_key,
			payload_hash, record_hash, accepted_at, previous_event_hash,
			previous_allocation_event_hash, event_hash, registry_scope,
			registry_key_id, signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.EventIndex,
		event.EventID,
		event.AllocationID,
		event.Action,
		event.ResultingStatus,
		event.ActorRole,
		event.ActorID,
		event.Reference,
		event.EvidenceHash,
		event.IdempotencyKey,
		event.PayloadHash,
		event.RecordHash,
		event.AcceptedAt,
		event.PreviousEventHash,
		event.PreviousAllocationEventHash,
		event.EventHash,
		event.RegistryScope,
		event.RegistryKeyID,
		event.Signature,
	)
	if err != nil {
		return fmt.Errorf("append final exit allocation event: %w", err)
	}
	return nil
}

func insertExitAllocationStateTx(
	ctx context.Context,
	tx *sql.Tx,
	state exitAllocationState,
) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO exit_allocation_state_rows (
			event_index, event_hash, allocation_id, status, decision_mode,
			beneficiary_type, beneficiary_id, exit_review_id,
			target_deployment_id, claim_action_id, source_group_id,
			ownership_transfer_id, settlement_source_count,
			settlement_source_hash, currency_allocation_count,
			currency_allocation_hash, record_hash, latest_action,
			latest_actor_role, latest_actor_id, latest_reference,
			latest_evidence_hash, latest_accepted_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		state.EventIndex,
		state.EventHash,
		state.AllocationID,
		state.Status,
		state.DecisionMode,
		state.BeneficiaryType,
		state.BeneficiaryID,
		state.ExitReviewID,
		state.TargetDeploymentID,
		state.ClaimActionID,
		state.SourceGroupID,
		state.OwnershipTransferID,
		state.SettlementSourceCount,
		state.SettlementSourceHash,
		state.CurrencyAllocationCount,
		state.CurrencyAllocationHash,
		state.RecordHash,
		state.LatestAction,
		state.LatestActorRole,
		state.LatestActorID,
		state.LatestReference,
		state.LatestEvidenceHash,
		state.LatestAcceptedAt,
	)
	if err != nil {
		return fmt.Errorf("append final exit allocation query row: %w", err)
	}
	return nil
}

func scanExitAllocationRecord(
	scanner rowScanner,
) (store.ExitAllocationRecord, error) {
	var record store.ExitAllocationRecord
	if err := scanner.Scan(
		&record.AllocationID,
		&record.RulesetVersion,
		&record.ExitReviewID,
		&record.TargetDeploymentID,
		&record.ClaimActionID,
		&record.SourceGroupID,
		&record.ExitRecordHash,
		&record.ExitVerificationEventIndex,
		&record.ExitVerificationEventHash,
		&record.ExitEvidenceHash,
		&record.DecisionMode,
		&record.OwnershipTransferID,
		&record.OwnershipTransferCompletionEventIndex,
		&record.OwnershipTransferCompletionEventHash,
		&record.ThroughOwnershipTransferEventIndex,
		&record.OwnershipTransferHeadHash,
		&record.BeneficiaryType,
		&record.BeneficiaryID,
		&record.ContractReference,
		&record.ContractTermsHash,
		&record.EvidenceHash,
		&record.SettlementSourceCount,
		&record.SettlementSourceHash,
		&record.CurrencyAllocationCount,
		&record.CurrencyAllocationHash,
		&record.CreatedAt,
		&record.RecordHash,
		&record.RegistryScope,
		&record.RegistryKeyID,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ExitAllocationRecord{}, store.ErrNotFound
		}
		return store.ExitAllocationRecord{},
			fmt.Errorf("read final exit allocation record: %w", err)
	}
	return record, nil
}

func scanExitAllocationSource(
	scanner rowScanner,
) (store.ExitAllocationSettlementSource, error) {
	var source store.ExitAllocationSettlementSource
	if err := scanner.Scan(
		&source.BoundaryOrder,
		&source.SettlementID,
		&source.Period,
		&source.CurrencyCode,
		&source.FractionDigits,
		&source.Revision,
		&source.LedgerIndex,
		&source.SettlementHash,
		&source.SourceFingerprint,
		&source.SettlementAllocationHash,
		&source.DistributableMinor,
	); err != nil {
		return store.ExitAllocationSettlementSource{},
			fmt.Errorf("read final exit allocation source: %w", err)
	}
	return source, nil
}

func scanExitAllocationCurrency(
	scanner rowScanner,
) (store.ExitAllocationCurrency, error) {
	var allocation store.ExitAllocationCurrency
	if err := scanner.Scan(
		&allocation.AllocationOrder,
		&allocation.CurrencyCode,
		&allocation.FractionDigits,
		&allocation.DistributableMinor,
		&allocation.AllocatedMinor,
		&allocation.BeneficiaryType,
		&allocation.BeneficiaryID,
	); err != nil {
		return store.ExitAllocationCurrency{},
			fmt.Errorf("read final exit allocation currency: %w", err)
	}
	return allocation, nil
}

func scanExitAllocationEvent(
	scanner rowScanner,
) (store.ExitAllocationEvent, error) {
	var event store.ExitAllocationEvent
	if err := scanner.Scan(
		&event.EventIndex,
		&event.EventID,
		&event.AllocationID,
		&event.Action,
		&event.ResultingStatus,
		&event.ActorRole,
		&event.ActorID,
		&event.Reference,
		&event.EvidenceHash,
		&event.IdempotencyKey,
		&event.PayloadHash,
		&event.RecordHash,
		&event.AcceptedAt,
		&event.PreviousEventHash,
		&event.PreviousAllocationEventHash,
		&event.EventHash,
		&event.RegistryScope,
		&event.RegistryKeyID,
		&event.Signature,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ExitAllocationEvent{}, store.ErrNotFound
		}
		return store.ExitAllocationEvent{},
			fmt.Errorf("read final exit allocation event: %w", err)
	}
	return event, nil
}

func scanExitAllocationState(
	scanner rowScanner,
) (exitAllocationState, error) {
	var state exitAllocationState
	if err := scanner.Scan(
		&state.EventIndex,
		&state.EventHash,
		&state.AllocationID,
		&state.Status,
		&state.DecisionMode,
		&state.BeneficiaryType,
		&state.BeneficiaryID,
		&state.ExitReviewID,
		&state.TargetDeploymentID,
		&state.ClaimActionID,
		&state.SourceGroupID,
		&state.OwnershipTransferID,
		&state.SettlementSourceCount,
		&state.SettlementSourceHash,
		&state.CurrencyAllocationCount,
		&state.CurrencyAllocationHash,
		&state.RecordHash,
		&state.LatestAction,
		&state.LatestActorRole,
		&state.LatestActorID,
		&state.LatestReference,
		&state.LatestEvidenceHash,
		&state.LatestAcceptedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return exitAllocationState{}, store.ErrNotFound
		}
		return exitAllocationState{},
			fmt.Errorf("read final exit allocation query row: %w", err)
	}
	return state, nil
}

func exitAllocationStateFromEvent(
	record store.ExitAllocationRecord,
	event store.ExitAllocationEvent,
) exitAllocationState {
	return exitAllocationState{
		EventIndex:              event.EventIndex,
		EventHash:               event.EventHash,
		AllocationID:            record.AllocationID,
		Status:                  event.ResultingStatus,
		DecisionMode:            record.DecisionMode,
		BeneficiaryType:         record.BeneficiaryType,
		BeneficiaryID:           record.BeneficiaryID,
		ExitReviewID:            record.ExitReviewID,
		TargetDeploymentID:      record.TargetDeploymentID,
		ClaimActionID:           record.ClaimActionID,
		SourceGroupID:           record.SourceGroupID,
		OwnershipTransferID:     record.OwnershipTransferID,
		SettlementSourceCount:   record.SettlementSourceCount,
		SettlementSourceHash:    record.SettlementSourceHash,
		CurrencyAllocationCount: record.CurrencyAllocationCount,
		CurrencyAllocationHash:  record.CurrencyAllocationHash,
		RecordHash:              record.RecordHash,
		LatestAction:            event.Action,
		LatestActorRole:         event.ActorRole,
		LatestActorID:           event.ActorID,
		LatestReference:         event.Reference,
		LatestEvidenceHash:      event.EvidenceHash,
		LatestAcceptedAt:        event.AcceptedAt,
	}
}

func exitAllocationFromState(
	record store.ExitAllocationRecord,
	state exitAllocationState,
) store.ExitAllocation {
	return store.ExitAllocation{
		Record:             record,
		Status:             state.Status,
		LatestEventIndex:   state.EventIndex,
		LatestEventHash:    state.EventHash,
		LatestAction:       state.LatestAction,
		LatestActorRole:    state.LatestActorRole,
		LatestActorID:      state.LatestActorID,
		LatestReference:    state.LatestReference,
		LatestEvidenceHash: state.LatestEvidenceHash,
		LatestAcceptedAt:   state.LatestAcceptedAt,
	}
}

func ensureExitAllocationAcceptedAt(previous, acceptedAt string) error {
	if previous == "" {
		return nil
	}
	previousTime, previousErr := time.Parse(time.RFC3339Nano, previous)
	acceptedTime, acceptedErr := time.Parse(time.RFC3339Nano, acceptedAt)
	if previousErr != nil ||
		acceptedErr != nil ||
		acceptedTime.Before(previousTime) {
		return store.ErrExitAllocationClockBeforeHead
	}
	return nil
}

func normalizedExitAllocationTransferHash(
	input store.ExitAllocationCreateInput,
) string {
	if input.DecisionMode == protocol.ExitAllocationDecisionNoTransfer {
		return protocol.ExitAllocationZeroHash
	}
	return input.OwnershipTransferCompletionEventHash
}

func equalExitAllocationSources(
	left, right []store.ExitAllocationSettlementSource,
) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalExitAllocationCurrencies(
	left, right []store.ExitAllocationCurrency,
) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func exitAllocationProtocolSources(
	sources []store.ExitAllocationSettlementSource,
) []protocol.ExitAllocationSettlementSource {
	result := make([]protocol.ExitAllocationSettlementSource, 0, len(sources))
	for _, source := range sources {
		result = append(result, protocol.ExitAllocationSettlementSource{
			BoundaryOrder:            source.BoundaryOrder,
			SettlementID:             source.SettlementID,
			Period:                   source.Period,
			CurrencyCode:             source.CurrencyCode,
			FractionDigits:           source.FractionDigits,
			Revision:                 source.Revision,
			LedgerIndex:              source.LedgerIndex,
			SettlementHash:           source.SettlementHash,
			SourceFingerprint:        source.SourceFingerprint,
			SettlementAllocationHash: source.SettlementAllocationHash,
			DistributableMinor:       source.DistributableMinor,
		})
	}
	return result
}

func exitAllocationProtocolCurrencies(
	allocations []store.ExitAllocationCurrency,
) []protocol.ExitAllocationCurrency {
	result := make([]protocol.ExitAllocationCurrency, 0, len(allocations))
	for _, allocation := range allocations {
		result = append(result, protocol.ExitAllocationCurrency{
			AllocationOrder:    allocation.AllocationOrder,
			CurrencyCode:       allocation.CurrencyCode,
			FractionDigits:     allocation.FractionDigits,
			DistributableMinor: allocation.DistributableMinor,
			AllocatedMinor:     allocation.AllocatedMinor,
			BeneficiaryType:    allocation.BeneficiaryType,
			BeneficiaryID:      allocation.BeneficiaryID,
		})
	}
	return result
}

func exitAllocationProtocolRecord(
	record store.ExitAllocationRecord,
) protocol.ExitAllocationRecord {
	return protocol.ExitAllocationRecord{
		AllocationID:                          record.AllocationID,
		RulesetVersion:                        record.RulesetVersion,
		ExitReviewID:                          record.ExitReviewID,
		TargetDeploymentID:                    record.TargetDeploymentID,
		ClaimActionID:                         record.ClaimActionID,
		SourceGroupID:                         record.SourceGroupID,
		ExitRecordHash:                        record.ExitRecordHash,
		ExitVerificationEventIndex:            record.ExitVerificationEventIndex,
		ExitVerificationEventHash:             record.ExitVerificationEventHash,
		ExitEvidenceHash:                      record.ExitEvidenceHash,
		DecisionMode:                          record.DecisionMode,
		OwnershipTransferID:                   record.OwnershipTransferID,
		OwnershipTransferCompletionEventIndex: record.OwnershipTransferCompletionEventIndex,
		OwnershipTransferCompletionEventHash:  record.OwnershipTransferCompletionEventHash,
		ThroughOwnershipTransferEventIndex:    record.ThroughOwnershipTransferEventIndex,
		OwnershipTransferHeadHash:             record.OwnershipTransferHeadHash,
		BeneficiaryType:                       record.BeneficiaryType,
		BeneficiaryID:                         record.BeneficiaryID,
		ContractReference:                     record.ContractReference,
		ContractTermsHash:                     record.ContractTermsHash,
		EvidenceHash:                          record.EvidenceHash,
		SettlementSourceCount:                 record.SettlementSourceCount,
		SettlementSourceHash:                  record.SettlementSourceHash,
		CurrencyAllocationCount:               record.CurrencyAllocationCount,
		CurrencyAllocationHash:                record.CurrencyAllocationHash,
		CreatedAt:                             record.CreatedAt,
		RecordHash:                            record.RecordHash,
		RegistryScope:                         record.RegistryScope,
		RegistryKeyID:                         record.RegistryKeyID,
		SettlementSources: exitAllocationProtocolSources(
			record.SettlementSources,
		),
		CurrencyAllocations: exitAllocationProtocolCurrencies(
			record.CurrencyAllocations,
		),
	}
}

func exitAllocationProtocolEvent(
	event store.ExitAllocationEvent,
) protocol.ExitAllocationEvent {
	return protocol.ExitAllocationEvent{
		EventIndex:                  event.EventIndex,
		EventID:                     event.EventID,
		AllocationID:                event.AllocationID,
		Action:                      event.Action,
		ResultingStatus:             event.ResultingStatus,
		ActorRole:                   event.ActorRole,
		ActorID:                     event.ActorID,
		Reference:                   event.Reference,
		EvidenceHash:                event.EvidenceHash,
		IdempotencyKey:              event.IdempotencyKey,
		PayloadHash:                 event.PayloadHash,
		RecordHash:                  event.RecordHash,
		AcceptedAt:                  event.AcceptedAt,
		PreviousEventHash:           event.PreviousEventHash,
		PreviousAllocationEventHash: event.PreviousAllocationEventHash,
		EventHash:                   event.EventHash,
		RegistryScope:               event.RegistryScope,
		RegistryKeyID:               event.RegistryKeyID,
	}
}
