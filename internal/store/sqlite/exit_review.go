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

const exitReviewEventSelect = `
	SELECT
		event_index,
		event_id,
		review_id,
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
		previous_review_event_hash,
		event_hash,
		registry_scope,
		registry_key_id,
		signature
	FROM exit_review_events`

const exitReviewRecordSelect = `
	SELECT
		review_id,
		ruleset_version,
		record_date,
		target_deployment_id,
		claim_action_id,
		group_id,
		legal_name,
		checkpoint_hash,
		through_ledger_index,
		ledger_head_hash,
		merkle_tree_size,
		merkle_root_hash,
		through_audit_index,
		audit_head_hash,
		through_review_index,
		claim_review_head_hash,
		through_eligibility_index,
		eligibility_head_hash,
		through_settlement_ledger_index,
		settlement_boundary_count,
		settlement_boundary_hash,
		deployment_count,
		membership_hash,
		frozen_at,
		record_hash,
		registry_scope,
		registry_key_id
	FROM exit_reviews`

const exitReviewStateSelect = `
	SELECT
		event_index,
		event_hash,
		review_id,
		status,
		record_date,
		target_deployment_id,
		claim_action_id,
		group_id,
		legal_name,
		record_hash,
		latest_action,
		latest_effective_date,
		latest_actor_role,
		latest_actor_id,
		latest_reference,
		latest_evidence_hash,
		latest_reason_code,
		latest_accepted_at
	FROM exit_review_state_rows`

type exitReviewState struct {
	EventIndex          int64
	EventHash           string
	ReviewID            string
	Status              string
	RecordDate          string
	TargetDeploymentID  string
	ClaimActionID       string
	GroupID             string
	LegalName           string
	RecordHash          string
	LatestAction        string
	LatestEffectiveDate string
	LatestActorRole     string
	LatestActorID       string
	LatestReference     string
	LatestEvidenceHash  string
	LatestReasonCode    string
	LatestAcceptedAt    string
}

type exitReviewQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (sqliteStore *Store) FreezeExitReview(
	ctx context.Context,
	input store.ExitReviewFreezeInput,
	signEvent store.ExitReviewEventSigner,
) (store.ExitReviewEvent, store.ExitReview, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false,
			fmt.Errorf("begin exit review freeze: %w", err)
	}
	defer tx.Rollback()

	existing, err := exitReviewEventByIdempotency(ctx, tx, input.IdempotencyKey)
	if err == nil {
		current, readErr := exitReviewByIDQuery(ctx, tx, existing.ReviewID)
		if readErr != nil {
			return store.ExitReviewEvent{}, store.ExitReview{}, false, readErr
		}
		if existing.Action != protocol.ExitReviewActionFreeze ||
			current.Record.RecordDate != input.RecordDate ||
			current.Record.TargetDeploymentID != input.TargetDeploymentID ||
			current.Record.ClaimActionID != input.ClaimActionID ||
			current.Record.GroupID != input.GroupID ||
			existing.ActorRole != input.ActorRole ||
			existing.ActorID != input.ActorID ||
			existing.Reference != input.Reference ||
			existing.EvidenceHash != input.EvidenceHash {
			return store.ExitReviewEvent{}, store.ExitReview{}, false,
				store.ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return store.ExitReviewEvent{}, store.ExitReview{}, false,
				fmt.Errorf("commit duplicate exit review freeze: %w", err)
		}
		return existing, current, true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, err
	}

	if err := ensureAcceptedAtAfterRegistryCreation(ctx, tx, input.AcceptedAt); err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, err
	}
	head, err := exitReviewEventHead(ctx, tx)
	if err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, err
	}
	if err := ensureExitReviewAcceptedAt(head.AcceptedAt, input.AcceptedAt); err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, err
	}
	if _, lookupErr := exitReviewByClaimTx(
		ctx,
		tx,
		input.TargetDeploymentID,
		input.ClaimActionID,
	); lookupErr == nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false,
			store.ErrExitReviewAlreadyFrozen
	} else if !errors.Is(lookupErr, store.ErrNotFound) {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, lookupErr
	}

	record, err := freezeExitReviewRecordTx(ctx, tx, input)
	if err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, err
	}
	if err := insertExitReviewRecordTx(ctx, tx, record); err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, err
	}

	event := store.ExitReviewEvent{
		EventIndex:              head.EventIndex + 1,
		EventID:                 input.CandidateEventID,
		ReviewID:                record.ReviewID,
		Action:                  protocol.ExitReviewActionFreeze,
		ResultingStatus:         protocol.ExitReviewStatusPending,
		EffectiveDate:           record.RecordDate,
		ActorRole:               input.ActorRole,
		ActorID:                 input.ActorID,
		Reference:               input.Reference,
		EvidenceHash:            input.EvidenceHash,
		IdempotencyKey:          input.IdempotencyKey,
		RecordHash:              record.RecordHash,
		AcceptedAt:              input.AcceptedAt,
		PreviousEventHash:       head.EventHash,
		PreviousReviewEventHash: protocol.ExitReviewZeroHash,
		RegistryScope:           input.RegistryScope,
		RegistryKeyID:           input.RegistryKeyID,
	}
	event.PayloadHash = protocol.Digest(
		protocol.ExitReviewEventPayloadMessage(exitReviewProtocolEvent(event)),
	)
	event.EventHash = protocol.Digest(
		protocol.ExitReviewEventHashMessage(exitReviewProtocolEvent(event)),
	)
	event.Signature, err = signEvent(event)
	if err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false,
			fmt.Errorf("sign exit review freeze event: %w", err)
	}
	if err := insertExitReviewEventTx(ctx, tx, event); err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, err
	}
	state := exitReviewStateFromEvent(record, event)
	if err := insertExitReviewStateTx(ctx, tx, state); err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false,
			fmt.Errorf("commit exit review freeze: %w", err)
	}
	return event, exitReviewFromState(record, state), false, nil
}

func (sqliteStore *Store) AppendExitReviewEvent(
	ctx context.Context,
	input store.ExitReviewMutationInput,
	signEvent store.ExitReviewEventSigner,
) (store.ExitReviewEvent, store.ExitReview, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false,
			fmt.Errorf("begin exit review event: %w", err)
	}
	defer tx.Rollback()

	existing, err := exitReviewEventByIdempotency(ctx, tx, input.IdempotencyKey)
	if err == nil {
		current, readErr := exitReviewByIDQuery(ctx, tx, existing.ReviewID)
		if readErr != nil {
			return store.ExitReviewEvent{}, store.ExitReview{}, false, readErr
		}
		if existing.ReviewID != input.ReviewID ||
			existing.Action != input.Action ||
			existing.ResultingStatus != input.ResultingStatus ||
			existing.EffectiveDate != input.EffectiveDate ||
			existing.ActorRole != input.ActorRole ||
			existing.ActorID != input.ActorID ||
			existing.Reference != input.Reference ||
			existing.EvidenceHash != input.EvidenceHash ||
			existing.ReasonCode != input.ReasonCode ||
			existing.PayloadHash != input.PayloadHash {
			return store.ExitReviewEvent{}, store.ExitReview{}, false,
				store.ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return store.ExitReviewEvent{}, store.ExitReview{}, false,
				fmt.Errorf("commit duplicate exit review event: %w", err)
		}
		return existing, current, true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, err
	}

	current, err := exitReviewByIDQuery(ctx, tx, input.ReviewID)
	if err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, err
	}
	if !validExitReviewTransition(current.Status, input.Action, input.ResultingStatus) {
		return store.ExitReviewEvent{}, store.ExitReview{}, false,
			store.ErrExitReviewTransition
	}
	if input.EffectiveDate < current.Record.RecordDate ||
		input.EffectiveDate < current.LatestEffectiveDate {
		return store.ExitReviewEvent{}, store.ExitReview{}, false,
			store.ErrExitReviewTransition
	}
	if err := ensureAcceptedAtAfterRegistryCreation(ctx, tx, input.AcceptedAt); err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, err
	}
	head, err := exitReviewEventHead(ctx, tx)
	if err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, err
	}
	if err := ensureExitReviewAcceptedAt(head.AcceptedAt, input.AcceptedAt); err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, err
	}

	event := store.ExitReviewEvent{
		EventIndex:              head.EventIndex + 1,
		EventID:                 input.CandidateEventID,
		ReviewID:                input.ReviewID,
		Action:                  input.Action,
		ResultingStatus:         input.ResultingStatus,
		EffectiveDate:           input.EffectiveDate,
		ActorRole:               input.ActorRole,
		ActorID:                 input.ActorID,
		Reference:               input.Reference,
		EvidenceHash:            input.EvidenceHash,
		ReasonCode:              input.ReasonCode,
		IdempotencyKey:          input.IdempotencyKey,
		PayloadHash:             input.PayloadHash,
		RecordHash:              current.Record.RecordHash,
		AcceptedAt:              input.AcceptedAt,
		PreviousEventHash:       head.EventHash,
		PreviousReviewEventHash: current.LatestEventHash,
		RegistryScope:           input.RegistryScope,
		RegistryKeyID:           input.RegistryKeyID,
	}
	expectedPayloadHash := protocol.Digest(
		protocol.ExitReviewEventPayloadMessage(exitReviewProtocolEvent(event)),
	)
	if input.PayloadHash != expectedPayloadHash {
		return store.ExitReviewEvent{}, store.ExitReview{}, false,
			store.ErrInconsistentState
	}
	event.EventHash = protocol.Digest(
		protocol.ExitReviewEventHashMessage(exitReviewProtocolEvent(event)),
	)
	event.Signature, err = signEvent(event)
	if err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false,
			fmt.Errorf("sign exit review event: %w", err)
	}
	if err := insertExitReviewEventTx(ctx, tx, event); err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, err
	}
	state := exitReviewStateFromEvent(current.Record, event)
	if err := insertExitReviewStateTx(ctx, tx, state); err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return store.ExitReviewEvent{}, store.ExitReview{}, false,
			fmt.Errorf("commit exit review event: %w", err)
	}
	return event, exitReviewFromState(current.Record, state), false, nil
}

func (sqliteStore *Store) ExitReview(
	ctx context.Context,
	reviewID string,
) (store.ExitReview, error) {
	return exitReviewByIDQuery(ctx, sqliteStore.db, reviewID)
}

func (sqliteStore *Store) ExitReviews(
	ctx context.Context,
	query store.ExitReviewQuery,
) (store.ExitReviewPage, error) {
	arguments := []any{}
	where := "WHERE rank = 1"
	if query.Status != "" {
		where += " AND status = ?"
		arguments = append(arguments, query.Status)
	}
	if query.BeforeEventIndex > 0 {
		where += " AND event_index < ?"
		arguments = append(arguments, query.BeforeEventIndex)
	}
	arguments = append(arguments, query.Limit+1)
	rows, err := sqliteStore.db.QueryContext(ctx, `
		WITH ranked AS (
			SELECT
				event_index,
				event_hash,
				review_id,
				status,
				record_date,
				target_deployment_id,
				claim_action_id,
				group_id,
				legal_name,
				record_hash,
				latest_action,
				latest_effective_date,
				latest_actor_role,
				latest_actor_id,
				latest_reference,
				latest_evidence_hash,
				latest_reason_code,
				latest_accepted_at,
				ROW_NUMBER() OVER (
					PARTITION BY review_id ORDER BY event_index DESC
				) AS rank
			FROM exit_review_state_rows
		)
		SELECT
			event_index, event_hash, review_id, status, record_date,
			target_deployment_id, claim_action_id, group_id, legal_name,
			record_hash, latest_action, latest_effective_date,
			latest_actor_role, latest_actor_id, latest_reference,
			latest_evidence_hash, latest_reason_code, latest_accepted_at
		FROM ranked
		`+where+`
		ORDER BY event_index DESC
		LIMIT ?`,
		arguments...,
	)
	if err != nil {
		return store.ExitReviewPage{}, fmt.Errorf("list exit review query rows: %w", err)
	}
	defer rows.Close()
	states := make([]exitReviewState, 0, query.Limit+1)
	for rows.Next() {
		state, scanErr := scanExitReviewState(rows)
		if scanErr != nil {
			return store.ExitReviewPage{}, scanErr
		}
		states = append(states, state)
	}
	if err := rows.Err(); err != nil {
		return store.ExitReviewPage{}, fmt.Errorf("iterate exit review query rows: %w", err)
	}
	if err := rows.Close(); err != nil {
		return store.ExitReviewPage{}, fmt.Errorf("close exit review query rows: %w", err)
	}
	page := store.ExitReviewPage{Items: make([]store.ExitReview, 0, query.Limit)}
	if len(states) > query.Limit {
		page.NextEventIndex = states[query.Limit-1].EventIndex
		states = states[:query.Limit]
	}
	for _, state := range states {
		record, readErr := exitReviewRecordByID(ctx, sqliteStore.db, state.ReviewID)
		if readErr != nil {
			return store.ExitReviewPage{}, readErr
		}
		page.Items = append(page.Items, exitReviewFromState(record, state))
	}
	return page, nil
}

func freezeExitReviewRecordTx(
	ctx context.Context,
	tx *sql.Tx,
	input store.ExitReviewFreezeInput,
) (store.ExitReviewRecord, error) {
	var checkpoint struct {
		throughLedgerIndex int64
		entryCount         int64
		ledgerHeadHash     string
		checkpointHash     string
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT through_ledger_index, entry_count, ledger_head_hash, checkpoint_hash
		FROM checkpoints
		WHERE checkpoint_date = ?`,
		input.RecordDate,
	).Scan(
		&checkpoint.throughLedgerIndex,
		&checkpoint.entryCount,
		&checkpoint.ledgerHeadHash,
		&checkpoint.checkpointHash,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ExitReviewRecord{}, store.ErrNotFound
		}
		return store.ExitReviewRecord{}, fmt.Errorf("read exit record-date checkpoint: %w", err)
	}
	if checkpoint.entryCount != checkpoint.throughLedgerIndex {
		return store.ExitReviewRecord{}, store.ErrInconsistentState
	}
	day, err := time.Parse("2006-01-02", input.RecordDate)
	if err != nil {
		return store.ExitReviewRecord{}, store.ErrInconsistentState
	}
	endExclusive := day.AddDate(0, 0, 1).UTC().Format(time.RFC3339)
	auditIndex, auditHash, err := exitReviewAuditBoundaryTx(ctx, tx, endExclusive)
	if err != nil {
		return store.ExitReviewRecord{}, err
	}
	reviewIndex, reviewHash, err := exitReviewClaimReviewBoundaryTx(
		ctx,
		tx,
		endExclusive,
	)
	if err != nil {
		return store.ExitReviewRecord{}, err
	}
	eligibilityIndex, eligibilityHash, err :=
		exitReviewEligibilityBoundaryTx(ctx, tx, endExclusive)
	if err != nil {
		return store.ExitReviewRecord{}, err
	}
	transferHead, err := ownershipTransferEventHeadAt(
		ctx,
		tx,
		day.AddDate(0, 0, 1).Add(-time.Second).UTC().Format(time.RFC3339),
	)
	if err != nil {
		return store.ExitReviewRecord{}, err
	}
	members, legalName, err := exitReviewMembersAtBoundaryTx(
		ctx,
		tx,
		input,
		auditIndex,
		reviewIndex,
		eligibilityIndex,
		transferHead.EventIndex,
	)
	if err != nil {
		return store.ExitReviewRecord{}, err
	}
	settlements, settlementLedgerIndex, err :=
		exitReviewSettlementsAtBoundaryTx(
			ctx,
			tx,
			checkpoint.throughLedgerIndex,
		)
	if err != nil {
		return store.ExitReviewRecord{}, err
	}
	merkleRoot := protocol.MerkleEmptyRoot()
	if checkpoint.entryCount > 0 {
		root, rootErr := merkleSubtreeRootTx(
			ctx,
			tx,
			0,
			checkpoint.entryCount,
		)
		if rootErr != nil {
			return store.ExitReviewRecord{}, rootErr
		}
		merkleRoot = encodeMerkleHash(root)
	}
	record := store.ExitReviewRecord{
		ReviewID:                     input.CandidateReviewID,
		RulesetVersion:               protocol.ExitReviewRulesetVersion,
		RecordDate:                   input.RecordDate,
		TargetDeploymentID:           input.TargetDeploymentID,
		ClaimActionID:                input.ClaimActionID,
		GroupID:                      input.GroupID,
		LegalName:                    legalName,
		CheckpointHash:               checkpoint.checkpointHash,
		ThroughLedgerIndex:           checkpoint.throughLedgerIndex,
		LedgerHeadHash:               checkpoint.ledgerHeadHash,
		MerkleTreeSize:               checkpoint.entryCount,
		MerkleRootHash:               merkleRoot,
		ThroughAuditIndex:            auditIndex,
		AuditHeadHash:                auditHash,
		ThroughReviewIndex:           reviewIndex,
		ClaimReviewHeadHash:          reviewHash,
		ThroughEligibilityIndex:      eligibilityIndex,
		EligibilityHeadHash:          eligibilityHash,
		ThroughSettlementLedgerIndex: settlementLedgerIndex,
		SettlementBoundaryCount:      int64(len(settlements)),
		SettlementBoundaryHash: protocol.ExitReviewSettlementBoundaryHash(
			exitReviewProtocolSettlements(settlements),
		),
		DeploymentCount: int64(len(members)),
		MembershipHash: protocol.ExitReviewMembershipHash(
			exitReviewProtocolMembers(members),
		),
		FrozenAt:      input.AcceptedAt,
		RegistryScope: input.RegistryScope,
		RegistryKeyID: input.RegistryKeyID,
		Deployments:   members,
		Settlements:   settlements,
	}
	record.RecordHash = protocol.Digest(
		protocol.ExitReviewRecordHashMessage(exitReviewProtocolRecord(record)),
	)
	return record, nil
}

func exitReviewMembersAtBoundaryTx(
	ctx context.Context,
	tx *sql.Tx,
	input store.ExitReviewFreezeInput,
	auditIndex int64,
	reviewIndex int64,
	eligibilityIndex int64,
	transferEventIndex int64,
) ([]store.ExitReviewDeployment, string, error) {
	var legalName string
	if err := tx.QueryRowContext(ctx, `
		SELECT legal_name
		FROM operator_claim_verification_submissions
		WHERE claim_action_id = ?
		  AND deployment_id = ?
		  AND group_id = ?`,
		input.ClaimActionID,
		input.TargetDeploymentID,
		input.GroupID,
	).Scan(&legalName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", store.ErrExitReviewClaimBoundary
		}
		return nil, "", fmt.Errorf("read exit target claim submission: %w", err)
	}
	rows, err := tx.QueryContext(
		ctx,
		leaderboardStateCTE+`
		SELECT
			deployment_id,
			claim_action_id,
			claim_state,
			eligibility_state,
			eligible
		FROM memberships
		WHERE group_id = ?
		  AND active = 1
		  AND claimed = 1
		ORDER BY deployment_id`,
		auditIndex,
		int64(0),
		reviewIndex,
		eligibilityIndex,
		transferEventIndex,
		input.RecordDate,
		"",
		"",
		input.GroupID,
	)
	if err != nil {
		return nil, "", fmt.Errorf("read exit review membership boundary: %w", err)
	}
	defer rows.Close()
	type membership struct {
		deploymentID     string
		claimActionID    string
		claimState       string
		eligibilityState string
		eligible         bool
	}
	raw := make([]membership, 0)
	targetFound := false
	for rows.Next() {
		var member membership
		if err := rows.Scan(
			&member.deploymentID,
			&member.claimActionID,
			&member.claimState,
			&member.eligibilityState,
			&member.eligible,
		); err != nil {
			return nil, "", fmt.Errorf("scan exit review membership boundary: %w", err)
		}
		if member.deploymentID == input.TargetDeploymentID &&
			member.claimActionID == input.ClaimActionID &&
			member.eligible {
			targetFound = true
		}
		raw = append(raw, member)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("iterate exit review membership boundary: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, "", fmt.Errorf("close exit review membership boundary: %w", err)
	}
	if !targetFound || len(raw) == 0 {
		return nil, "", store.ErrExitReviewClaimBoundary
	}
	members := make([]store.ExitReviewDeployment, 0, len(raw))
	for index, rawMember := range raw {
		member := store.ExitReviewDeployment{
			MemberOrder:      int64(index),
			DeploymentID:     rawMember.deploymentID,
			ClaimActionID:    rawMember.claimActionID,
			ClaimState:       rawMember.claimState,
			EligibilityState: rawMember.eligibilityState,
			ReviewHash:       protocol.OperatorClaimReviewZeroHash,
			EligibilityHash:  protocol.OperatorClaimEligibilityZeroHash,
		}
		if err := tx.QueryRowContext(ctx, `
			SELECT audit_index, audit_hash
			FROM operator_audit_events
			WHERE action_id = ?
			  AND audit_index <= ?`,
			member.ClaimActionID,
			auditIndex,
		).Scan(&member.ClaimAuditIndex, &member.ClaimAuditHash); err != nil {
			return nil, "", fmt.Errorf("read exit member claim boundary: %w", err)
		}
		err := tx.QueryRowContext(ctx, `
			SELECT review_index, review_hash
			FROM operator_claim_reviews
			WHERE claim_action_id = ?
			  AND review_index <= ?
			ORDER BY review_index DESC
			LIMIT 1`,
			member.ClaimActionID,
			reviewIndex,
		).Scan(&member.ReviewIndex, &member.ReviewHash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, "", fmt.Errorf("read exit member review boundary: %w", err)
		}
		err = tx.QueryRowContext(ctx, `
			SELECT eligibility_index, eligibility_hash
			FROM operator_claim_eligibility_events
			WHERE claim_action_id = ?
			  AND eligibility_index <= ?
			ORDER BY eligibility_index DESC
			LIMIT 1`,
			member.ClaimActionID,
			eligibilityIndex,
		).Scan(&member.EligibilityIndex, &member.EligibilityHash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, "", fmt.Errorf("read exit member eligibility boundary: %w", err)
		}
		members = append(members, member)
	}
	return members, legalName, nil
}

func exitReviewSettlementsAtBoundaryTx(
	ctx context.Context,
	tx *sql.Tx,
	throughLedgerIndex int64,
) ([]store.ExitReviewSettlementBoundary, int64, error) {
	rows, err := tx.QueryContext(ctx, `
		WITH ranked AS (
			SELECT
				settlement_id,
				period,
				currency_code,
				revision,
				ledger_index,
				settlement_hash,
				source_fingerprint,
				allocation_hash,
				ROW_NUMBER() OVER (
					PARTITION BY period, currency_code
					ORDER BY revision DESC, ledger_index DESC
				) AS rank
			FROM settlements
			WHERE ledger_index <= ?
		)
		SELECT
			settlement_id,
			period,
			currency_code,
			revision,
			ledger_index,
			settlement_hash,
			source_fingerprint,
			allocation_hash
		FROM ranked
		WHERE rank = 1
		ORDER BY period, currency_code`,
		throughLedgerIndex,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("read exit settlement boundary: %w", err)
	}
	defer rows.Close()
	boundaries := make([]store.ExitReviewSettlementBoundary, 0)
	var throughSettlementLedgerIndex int64
	for rows.Next() {
		boundary := store.ExitReviewSettlementBoundary{
			BoundaryOrder: int64(len(boundaries)),
		}
		if err := rows.Scan(
			&boundary.SettlementID,
			&boundary.Period,
			&boundary.CurrencyCode,
			&boundary.Revision,
			&boundary.LedgerIndex,
			&boundary.SettlementHash,
			&boundary.SourceFingerprint,
			&boundary.AllocationHash,
		); err != nil {
			return nil, 0, fmt.Errorf("scan exit settlement boundary: %w", err)
		}
		if boundary.LedgerIndex > throughSettlementLedgerIndex {
			throughSettlementLedgerIndex = boundary.LedgerIndex
		}
		boundaries = append(boundaries, boundary)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate exit settlement boundary: %w", err)
	}
	return boundaries, throughSettlementLedgerIndex, nil
}

func exitReviewAuditBoundaryTx(
	ctx context.Context,
	tx *sql.Tx,
	endExclusive string,
) (int64, string, error) {
	var index int64
	hash := protocol.OperatorAuditZeroHash
	err := tx.QueryRowContext(ctx, `
		SELECT audit_index, audit_hash
		FROM operator_audit_events
		WHERE accepted_at < ?
		ORDER BY audit_index DESC
		LIMIT 1`,
		endExclusive,
	).Scan(&index, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, hash, nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("read exit operator-audit boundary: %w", err)
	}
	return index, hash, nil
}

func exitReviewClaimReviewBoundaryTx(
	ctx context.Context,
	tx *sql.Tx,
	endExclusive string,
) (int64, string, error) {
	var index int64
	hash := protocol.OperatorClaimReviewZeroHash
	err := tx.QueryRowContext(ctx, `
		SELECT review_index, review_hash
		FROM operator_claim_reviews
		WHERE reviewed_at < ?
		ORDER BY review_index DESC
		LIMIT 1`,
		endExclusive,
	).Scan(&index, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, hash, nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("read exit claim-review boundary: %w", err)
	}
	return index, hash, nil
}

func exitReviewEligibilityBoundaryTx(
	ctx context.Context,
	tx *sql.Tx,
	endExclusive string,
) (int64, string, error) {
	var index int64
	hash := protocol.OperatorClaimEligibilityZeroHash
	err := tx.QueryRowContext(ctx, `
		SELECT eligibility_index, eligibility_hash
		FROM operator_claim_eligibility_events
		WHERE decided_at < ?
		ORDER BY eligibility_index DESC
		LIMIT 1`,
		endExclusive,
	).Scan(&index, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, hash, nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("read exit eligibility boundary: %w", err)
	}
	return index, hash, nil
}

func insertExitReviewRecordTx(
	ctx context.Context,
	tx *sql.Tx,
	record store.ExitReviewRecord,
) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO exit_reviews (
			review_id, ruleset_version, record_date, target_deployment_id,
			claim_action_id, group_id, legal_name, checkpoint_hash,
			through_ledger_index, ledger_head_hash, merkle_tree_size,
			merkle_root_hash, through_audit_index, audit_head_hash,
			through_review_index, claim_review_head_hash,
			through_eligibility_index, eligibility_head_hash,
			through_settlement_ledger_index, settlement_boundary_count,
			settlement_boundary_hash, deployment_count, membership_hash,
			frozen_at, record_hash, registry_scope, registry_key_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ReviewID,
		record.RulesetVersion,
		record.RecordDate,
		record.TargetDeploymentID,
		record.ClaimActionID,
		record.GroupID,
		record.LegalName,
		record.CheckpointHash,
		record.ThroughLedgerIndex,
		record.LedgerHeadHash,
		record.MerkleTreeSize,
		record.MerkleRootHash,
		record.ThroughAuditIndex,
		record.AuditHeadHash,
		record.ThroughReviewIndex,
		record.ClaimReviewHeadHash,
		record.ThroughEligibilityIndex,
		record.EligibilityHeadHash,
		record.ThroughSettlementLedgerIndex,
		record.SettlementBoundaryCount,
		record.SettlementBoundaryHash,
		record.DeploymentCount,
		record.MembershipHash,
		record.FrozenAt,
		record.RecordHash,
		record.RegistryScope,
		record.RegistryKeyID,
	); err != nil {
		return fmt.Errorf("insert frozen exit review: %w", err)
	}
	for _, member := range record.Deployments {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO exit_review_deployments (
				review_id, member_order, deployment_id, claim_action_id,
				claim_state, eligibility_state,
				claim_audit_index, claim_audit_hash, review_index,
				review_hash, eligibility_index, eligibility_hash
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			record.ReviewID,
			member.MemberOrder,
			member.DeploymentID,
			member.ClaimActionID,
			member.ClaimState,
			member.EligibilityState,
			member.ClaimAuditIndex,
			member.ClaimAuditHash,
			member.ReviewIndex,
			member.ReviewHash,
			member.EligibilityIndex,
			member.EligibilityHash,
		); err != nil {
			return fmt.Errorf("insert frozen exit review deployment: %w", err)
		}
	}
	for _, boundary := range record.Settlements {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO exit_review_settlement_boundaries (
				review_id, boundary_order, settlement_id, period,
				currency_code, revision, ledger_index, settlement_hash,
				source_fingerprint, allocation_hash
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			record.ReviewID,
			boundary.BoundaryOrder,
			boundary.SettlementID,
			boundary.Period,
			boundary.CurrencyCode,
			boundary.Revision,
			boundary.LedgerIndex,
			boundary.SettlementHash,
			boundary.SourceFingerprint,
			boundary.AllocationHash,
		); err != nil {
			return fmt.Errorf("insert frozen exit settlement boundary: %w", err)
		}
	}
	return nil
}

func insertExitReviewEventTx(
	ctx context.Context,
	tx *sql.Tx,
	event store.ExitReviewEvent,
) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO exit_review_events (
			event_index, event_id, review_id, action, resulting_status,
			effective_date, actor_role, actor_id, reference, evidence_hash,
			reason_code, idempotency_key, payload_hash, record_hash,
			accepted_at, previous_event_hash, previous_review_event_hash,
			event_hash, registry_scope, registry_key_id, signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.EventIndex,
		event.EventID,
		event.ReviewID,
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
		event.PreviousReviewEventHash,
		event.EventHash,
		event.RegistryScope,
		event.RegistryKeyID,
		event.Signature,
	); err != nil {
		return fmt.Errorf("append exit review event: %w", err)
	}
	return nil
}

func insertExitReviewStateTx(
	ctx context.Context,
	tx *sql.Tx,
	state exitReviewState,
) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO exit_review_state_rows (
			event_index, event_hash, review_id, status, record_date,
			target_deployment_id, claim_action_id, group_id, legal_name,
			record_hash, latest_action, latest_effective_date,
			latest_actor_role, latest_actor_id, latest_reference,
			latest_evidence_hash, latest_reason_code, latest_accepted_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		state.EventIndex,
		state.EventHash,
		state.ReviewID,
		state.Status,
		state.RecordDate,
		state.TargetDeploymentID,
		state.ClaimActionID,
		state.GroupID,
		state.LegalName,
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
		return fmt.Errorf("append exit review query row: %w", err)
	}
	return nil
}

func exitReviewByIDQuery(
	ctx context.Context,
	queryer exitReviewQueryer,
	reviewID string,
) (store.ExitReview, error) {
	record, err := exitReviewRecordByID(ctx, queryer, reviewID)
	if err != nil {
		return store.ExitReview{}, err
	}
	state, err := scanExitReviewState(queryer.QueryRowContext(
		ctx,
		exitReviewStateSelect+`
		WHERE review_id = ?
		ORDER BY event_index DESC
		LIMIT 1`,
		reviewID,
	))
	if err != nil {
		return store.ExitReview{}, err
	}
	result := exitReviewFromState(record, state)
	result.Events, err = exitReviewEventsByReviewQuery(ctx, queryer, reviewID)
	return result, err
}

func exitReviewRecordByID(
	ctx context.Context,
	queryer exitReviewQueryer,
	reviewID string,
) (store.ExitReviewRecord, error) {
	record, err := scanExitReviewRecord(queryer.QueryRowContext(
		ctx,
		exitReviewRecordSelect+" WHERE review_id = ?",
		reviewID,
	))
	if err != nil {
		return store.ExitReviewRecord{}, err
	}
	record.Deployments, err = exitReviewMembersQuery(ctx, queryer, reviewID)
	if err != nil {
		return store.ExitReviewRecord{}, err
	}
	record.Settlements, err = exitReviewSettlementBoundariesQuery(
		ctx,
		queryer,
		reviewID,
	)
	return record, err
}

func exitReviewByClaimTx(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	claimActionID string,
) (store.ExitReviewRecord, error) {
	return scanExitReviewRecord(tx.QueryRowContext(
		ctx,
		exitReviewRecordSelect+`
		WHERE target_deployment_id = ?
		  AND claim_action_id = ?`,
		deploymentID,
		claimActionID,
	))
}

func exitReviewEventHead(
	ctx context.Context,
	queryer operatorActionQuerier,
) (store.ExitReviewEvent, error) {
	event, err := scanExitReviewEvent(queryer.QueryRowContext(
		ctx,
		exitReviewEventSelect+`
		ORDER BY event_index DESC
		LIMIT 1`,
	))
	if errors.Is(err, store.ErrNotFound) {
		return store.ExitReviewEvent{EventHash: protocol.ExitReviewZeroHash}, nil
	}
	return event, err
}

func exitReviewEventByIdempotency(
	ctx context.Context,
	queryer operatorActionQuerier,
	idempotencyKey string,
) (store.ExitReviewEvent, error) {
	return scanExitReviewEvent(queryer.QueryRowContext(
		ctx,
		exitReviewEventSelect+" WHERE idempotency_key = ?",
		idempotencyKey,
	))
}

func scanExitReviewRecord(scanner rowScanner) (store.ExitReviewRecord, error) {
	var record store.ExitReviewRecord
	if err := scanner.Scan(
		&record.ReviewID,
		&record.RulesetVersion,
		&record.RecordDate,
		&record.TargetDeploymentID,
		&record.ClaimActionID,
		&record.GroupID,
		&record.LegalName,
		&record.CheckpointHash,
		&record.ThroughLedgerIndex,
		&record.LedgerHeadHash,
		&record.MerkleTreeSize,
		&record.MerkleRootHash,
		&record.ThroughAuditIndex,
		&record.AuditHeadHash,
		&record.ThroughReviewIndex,
		&record.ClaimReviewHeadHash,
		&record.ThroughEligibilityIndex,
		&record.EligibilityHeadHash,
		&record.ThroughSettlementLedgerIndex,
		&record.SettlementBoundaryCount,
		&record.SettlementBoundaryHash,
		&record.DeploymentCount,
		&record.MembershipHash,
		&record.FrozenAt,
		&record.RecordHash,
		&record.RegistryScope,
		&record.RegistryKeyID,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ExitReviewRecord{}, store.ErrNotFound
		}
		return store.ExitReviewRecord{}, fmt.Errorf("read exit review record: %w", err)
	}
	return record, nil
}

func scanExitReviewEvent(scanner rowScanner) (store.ExitReviewEvent, error) {
	var event store.ExitReviewEvent
	if err := scanner.Scan(
		&event.EventIndex,
		&event.EventID,
		&event.ReviewID,
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
		&event.PreviousReviewEventHash,
		&event.EventHash,
		&event.RegistryScope,
		&event.RegistryKeyID,
		&event.Signature,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ExitReviewEvent{}, store.ErrNotFound
		}
		return store.ExitReviewEvent{}, fmt.Errorf("read exit review event: %w", err)
	}
	return event, nil
}

func scanExitReviewState(scanner rowScanner) (exitReviewState, error) {
	var state exitReviewState
	if err := scanner.Scan(
		&state.EventIndex,
		&state.EventHash,
		&state.ReviewID,
		&state.Status,
		&state.RecordDate,
		&state.TargetDeploymentID,
		&state.ClaimActionID,
		&state.GroupID,
		&state.LegalName,
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
			return exitReviewState{}, store.ErrNotFound
		}
		return exitReviewState{}, fmt.Errorf("read exit review query row: %w", err)
	}
	return state, nil
}

func exitReviewMembersQuery(
	ctx context.Context,
	queryer exitReviewQueryer,
	reviewID string,
) ([]store.ExitReviewDeployment, error) {
	rows, err := queryer.QueryContext(ctx, `
		SELECT
			member_order, deployment_id, claim_action_id, claim_state,
			eligibility_state, claim_audit_index,
			claim_audit_hash, review_index, review_hash, eligibility_index,
			eligibility_hash
		FROM exit_review_deployments
		WHERE review_id = ?
		ORDER BY member_order`,
		reviewID,
	)
	if err != nil {
		return nil, fmt.Errorf("read exit review deployments: %w", err)
	}
	defer rows.Close()
	items := make([]store.ExitReviewDeployment, 0)
	for rows.Next() {
		var item store.ExitReviewDeployment
		if err := rows.Scan(
			&item.MemberOrder,
			&item.DeploymentID,
			&item.ClaimActionID,
			&item.ClaimState,
			&item.EligibilityState,
			&item.ClaimAuditIndex,
			&item.ClaimAuditHash,
			&item.ReviewIndex,
			&item.ReviewHash,
			&item.EligibilityIndex,
			&item.EligibilityHash,
		); err != nil {
			return nil, fmt.Errorf("scan exit review deployment: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate exit review deployments: %w", err)
	}
	return items, nil
}

func exitReviewSettlementBoundariesQuery(
	ctx context.Context,
	queryer exitReviewQueryer,
	reviewID string,
) ([]store.ExitReviewSettlementBoundary, error) {
	rows, err := queryer.QueryContext(ctx, `
		SELECT
			boundary_order, settlement_id, period, currency_code, revision,
			ledger_index, settlement_hash, source_fingerprint, allocation_hash
		FROM exit_review_settlement_boundaries
		WHERE review_id = ?
		ORDER BY boundary_order`,
		reviewID,
	)
	if err != nil {
		return nil, fmt.Errorf("read exit settlement boundaries: %w", err)
	}
	defer rows.Close()
	items := make([]store.ExitReviewSettlementBoundary, 0)
	for rows.Next() {
		var item store.ExitReviewSettlementBoundary
		if err := rows.Scan(
			&item.BoundaryOrder,
			&item.SettlementID,
			&item.Period,
			&item.CurrencyCode,
			&item.Revision,
			&item.LedgerIndex,
			&item.SettlementHash,
			&item.SourceFingerprint,
			&item.AllocationHash,
		); err != nil {
			return nil, fmt.Errorf("scan exit settlement boundary: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate exit settlement boundaries: %w", err)
	}
	return items, nil
}

func exitReviewEventsByReviewQuery(
	ctx context.Context,
	queryer exitReviewQueryer,
	reviewID string,
) ([]store.ExitReviewEvent, error) {
	rows, err := queryer.QueryContext(
		ctx,
		exitReviewEventSelect+`
		WHERE review_id = ?
		ORDER BY event_index`,
		reviewID,
	)
	if err != nil {
		return nil, fmt.Errorf("read exit review event history: %w", err)
	}
	defer rows.Close()
	items := make([]store.ExitReviewEvent, 0)
	for rows.Next() {
		item, scanErr := scanExitReviewEvent(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate exit review event history: %w", err)
	}
	return items, nil
}

func exitReviewStateFromEvent(
	record store.ExitReviewRecord,
	event store.ExitReviewEvent,
) exitReviewState {
	return exitReviewState{
		EventIndex:          event.EventIndex,
		EventHash:           event.EventHash,
		ReviewID:            record.ReviewID,
		Status:              event.ResultingStatus,
		RecordDate:          record.RecordDate,
		TargetDeploymentID:  record.TargetDeploymentID,
		ClaimActionID:       record.ClaimActionID,
		GroupID:             record.GroupID,
		LegalName:           record.LegalName,
		RecordHash:          record.RecordHash,
		LatestAction:        event.Action,
		LatestEffectiveDate: event.EffectiveDate,
		LatestActorRole:     event.ActorRole,
		LatestActorID:       event.ActorID,
		LatestReference:     event.Reference,
		LatestEvidenceHash:  event.EvidenceHash,
		LatestReasonCode:    event.ReasonCode,
		LatestAcceptedAt:    event.AcceptedAt,
	}
}

func exitReviewFromState(
	record store.ExitReviewRecord,
	state exitReviewState,
) store.ExitReview {
	return store.ExitReview{
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

func validExitReviewTransition(currentStatus, action, resultingStatus string) bool {
	switch action {
	case protocol.ExitReviewActionVerify:
		return (currentStatus == protocol.ExitReviewStatusPending ||
			currentStatus == protocol.ExitReviewStatusDisputed) &&
			resultingStatus == protocol.ExitReviewStatusEligible
	case protocol.ExitReviewActionReject:
		return (currentStatus == protocol.ExitReviewStatusPending ||
			currentStatus == protocol.ExitReviewStatusDisputed) &&
			resultingStatus == protocol.ExitReviewStatusRejected
	case protocol.ExitReviewActionDispute:
		return (currentStatus == protocol.ExitReviewStatusEligible ||
			currentStatus == protocol.ExitReviewStatusRejected) &&
			resultingStatus == protocol.ExitReviewStatusDisputed
	case protocol.ExitReviewActionWithdraw:
		return currentStatus != protocol.ExitReviewStatusWithdrawn &&
			resultingStatus == protocol.ExitReviewStatusWithdrawn
	default:
		return false
	}
}

func ensureExitReviewAcceptedAt(previous, acceptedAt string) error {
	if previous == "" {
		return nil
	}
	previousTime, previousErr := time.Parse(time.RFC3339Nano, previous)
	acceptedTime, acceptedErr := time.Parse(time.RFC3339Nano, acceptedAt)
	if previousErr != nil || acceptedErr != nil || acceptedTime.Before(previousTime) {
		return store.ErrExitReviewClockBeforeHead
	}
	return nil
}

func exitReviewProtocolMembers(
	items []store.ExitReviewDeployment,
) []protocol.ExitReviewDeployment {
	result := make([]protocol.ExitReviewDeployment, 0, len(items))
	for _, item := range items {
		result = append(result, protocol.ExitReviewDeployment{
			MemberOrder:      item.MemberOrder,
			DeploymentID:     item.DeploymentID,
			ClaimActionID:    item.ClaimActionID,
			ClaimState:       item.ClaimState,
			EligibilityState: item.EligibilityState,
			ClaimAuditIndex:  item.ClaimAuditIndex,
			ClaimAuditHash:   item.ClaimAuditHash,
			ReviewIndex:      item.ReviewIndex,
			ReviewHash:       item.ReviewHash,
			EligibilityIndex: item.EligibilityIndex,
			EligibilityHash:  item.EligibilityHash,
		})
	}
	return result
}

func exitReviewProtocolSettlements(
	items []store.ExitReviewSettlementBoundary,
) []protocol.ExitReviewSettlementBoundary {
	result := make([]protocol.ExitReviewSettlementBoundary, 0, len(items))
	for _, item := range items {
		result = append(result, protocol.ExitReviewSettlementBoundary{
			BoundaryOrder:     item.BoundaryOrder,
			SettlementID:      item.SettlementID,
			Period:            item.Period,
			CurrencyCode:      item.CurrencyCode,
			Revision:          item.Revision,
			LedgerIndex:       item.LedgerIndex,
			SettlementHash:    item.SettlementHash,
			SourceFingerprint: item.SourceFingerprint,
			AllocationHash:    item.AllocationHash,
		})
	}
	return result
}

func exitReviewProtocolRecord(record store.ExitReviewRecord) protocol.ExitReviewRecord {
	return protocol.ExitReviewRecord{
		ReviewID:                     record.ReviewID,
		RulesetVersion:               record.RulesetVersion,
		RecordDate:                   record.RecordDate,
		TargetDeploymentID:           record.TargetDeploymentID,
		ClaimActionID:                record.ClaimActionID,
		GroupID:                      record.GroupID,
		LegalName:                    record.LegalName,
		CheckpointHash:               record.CheckpointHash,
		ThroughLedgerIndex:           record.ThroughLedgerIndex,
		LedgerHeadHash:               record.LedgerHeadHash,
		MerkleTreeSize:               record.MerkleTreeSize,
		MerkleRootHash:               record.MerkleRootHash,
		ThroughAuditIndex:            record.ThroughAuditIndex,
		AuditHeadHash:                record.AuditHeadHash,
		ThroughReviewIndex:           record.ThroughReviewIndex,
		ClaimReviewHeadHash:          record.ClaimReviewHeadHash,
		ThroughEligibilityIndex:      record.ThroughEligibilityIndex,
		EligibilityHeadHash:          record.EligibilityHeadHash,
		ThroughSettlementLedgerIndex: record.ThroughSettlementLedgerIndex,
		SettlementBoundaryCount:      record.SettlementBoundaryCount,
		SettlementBoundaryHash:       record.SettlementBoundaryHash,
		DeploymentCount:              record.DeploymentCount,
		MembershipHash:               record.MembershipHash,
		FrozenAt:                     record.FrozenAt,
		RecordHash:                   record.RecordHash,
		RegistryScope:                record.RegistryScope,
		RegistryKeyID:                record.RegistryKeyID,
		Deployments:                  exitReviewProtocolMembers(record.Deployments),
		Settlements:                  exitReviewProtocolSettlements(record.Settlements),
	}
}

func exitReviewProtocolEvent(event store.ExitReviewEvent) protocol.ExitReviewEvent {
	return protocol.ExitReviewEvent{
		EventIndex:              event.EventIndex,
		EventID:                 event.EventID,
		ReviewID:                event.ReviewID,
		Action:                  event.Action,
		ResultingStatus:         event.ResultingStatus,
		EffectiveDate:           event.EffectiveDate,
		ActorRole:               event.ActorRole,
		ActorID:                 event.ActorID,
		Reference:               event.Reference,
		EvidenceHash:            event.EvidenceHash,
		ReasonCode:              event.ReasonCode,
		IdempotencyKey:          event.IdempotencyKey,
		PayloadHash:             event.PayloadHash,
		RecordHash:              event.RecordHash,
		AcceptedAt:              event.AcceptedAt,
		PreviousEventHash:       event.PreviousEventHash,
		PreviousReviewEventHash: event.PreviousReviewEventHash,
		EventHash:               event.EventHash,
		RegistryScope:           event.RegistryScope,
		RegistryKeyID:           event.RegistryKeyID,
	}
}
