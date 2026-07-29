package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func (sqliteStore *Store) AcceptGlobalIdentityPresenceBatch(
	ctx context.Context,
	input store.GlobalIdentityPresenceInput,
	signEvent store.GlobalIdentityEventSigner,
	signReceipt store.GlobalIdentityPresenceReceiptSigner,
) (store.GlobalIdentityPresenceRecord, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.GlobalIdentityPresenceRecord{}, false,
			fmt.Errorf("begin global identity presence batch: %w", err)
	}
	defer tx.Rollback()

	existing, err := globalIdentityPresenceByIdempotency(
		ctx,
		tx,
		input.DeploymentID,
		input.IdempotencyKey,
	)
	if err == nil {
		if existing.PayloadHash != input.PayloadHash {
			return store.GlobalIdentityPresenceRecord{}, false,
				store.ErrIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return store.GlobalIdentityPresenceRecord{}, false,
				fmt.Errorf("commit duplicate identity presence chunk: %w", err)
		}
		return existing, true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}
	if _, eventErr := globalIdentityEventByIdempotency(
		ctx,
		tx,
		input.DeploymentID,
		input.IdempotencyKey,
	); eventErr == nil {
		return store.GlobalIdentityPresenceRecord{}, false,
			store.ErrIdempotencyConflict
	} else if !errors.Is(eventErr, store.ErrNotFound) {
		return store.GlobalIdentityPresenceRecord{}, false, eventErr
	}
	if err := ensureGlobalIdentityPresenceNonceAvailable(
		ctx,
		tx,
		input.DeploymentID,
		input.Nonce,
		input.RequestHash,
	); err != nil {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}
	active, err := operatorDeploymentActiveTx(ctx, tx, input.DeploymentID)
	if err != nil {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}
	if !active {
		return store.GlobalIdentityPresenceRecord{}, false,
			store.ErrDeploymentInactive
	}
	if _, err := globalIdentityVOPRFKeyTx(
		ctx,
		tx,
		input.KeyVersion,
		input.Suite,
	); err != nil {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}
	if err := verifyPresenceQMAUSource(ctx, tx, input); err != nil {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}
	if err := verifyPresenceRevision(ctx, tx, input); err != nil {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}
	submissionExists, err := ensureGlobalIdentityPresenceSubmission(
		ctx,
		tx,
		input,
	)
	if err != nil {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}
	if !submissionExists &&
		(input.RequiredActiveKeyVersion < 1 ||
			input.KeyVersion != input.RequiredActiveKeyVersion) {
		return store.GlobalIdentityPresenceRecord{}, false,
			store.ErrGlobalIdentityKeyMismatch
	}
	var duplicateIndex int
	err = tx.QueryRowContext(ctx, `
		SELECT 1
		FROM global_identity_presence_chunks
		WHERE submission_id = ? AND chunk_index = ?`,
		input.SubmissionID,
		input.ChunkIndex,
	).Scan(&duplicateIndex)
	if err == nil {
		return store.GlobalIdentityPresenceRecord{}, false,
			store.ErrGlobalIdentityPresenceConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return store.GlobalIdentityPresenceRecord{}, false,
			fmt.Errorf("read global identity presence chunk index: %w", err)
	}
	for _, commitment := range input.Commitments {
		active, err := globalIdentityCommitmentActiveForPeriod(
			ctx,
			tx,
			input.DeploymentID,
			input.KeyVersion,
			commitment,
			input.Period,
			0,
		)
		if err != nil {
			return store.GlobalIdentityPresenceRecord{}, false, err
		}
		if !active {
			return store.GlobalIdentityPresenceRecord{}, false,
			store.ErrGlobalIdentityLinkConflict
		}
	}
	if err := ensureAcceptedAtAfterRegistryCreation(
		ctx,
		tx,
		input.AcceptedAt,
	); err != nil {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}
	head, err := globalIdentityEventHead(ctx, tx)
	if err != nil {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}
	if err := ensureGlobalIdentityAcceptedAt(
		input.AcceptedAt,
		head.AcceptedAt,
	); err != nil {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}

	var receivedChunkCount int64
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) + 1
		FROM global_identity_presence_chunks
		WHERE submission_id = ?`,
		input.SubmissionID,
	).Scan(&receivedChunkCount); err != nil {
		return store.GlobalIdentityPresenceRecord{}, false,
			fmt.Errorf("count global identity presence chunks: %w", err)
	}
	if receivedChunkCount > input.ChunkCount {
		return store.GlobalIdentityPresenceRecord{}, false,
			store.ErrGlobalIdentityPresenceConflict
	}
	if input.ChunkIndex != receivedChunkCount-1 {
		return store.GlobalIdentityPresenceRecord{}, false,
			store.ErrGlobalIdentityPresenceConflict
	}
	complete := receivedChunkCount == input.ChunkCount
	record := store.GlobalIdentityPresenceRecord{
		SubmissionID:         input.SubmissionID,
		DeploymentID:         input.DeploymentID,
		RegistryScope:        input.RegistryScope,
		Period:               input.Period,
		Revision:             input.Revision,
		ChunkIndex:           input.ChunkIndex,
		ChunkCount:           input.ChunkCount,
		ReceivedChunkCount:   receivedChunkCount,
		TotalCommitmentCount: input.TotalCommitmentCount,
		CommitmentSetHash:    input.CommitmentSetHash,
		Complete:             complete,
		SupersedesBatchID:    input.SupersedesBatchID,
		ReportedQMAUCount:    input.ReportedQMAUCount,
		RequestHash:          input.RequestHash,
		PayloadHash:          input.PayloadHash,
		AcceptedAt:           input.AcceptedAt,
		RegistryKeyID:        input.RegistryKeyID,
	}
	var aggregatePayloadHash string
	if complete {
		allCommitments, readErr := globalIdentityCompletedCommitments(
			ctx,
			tx,
			input,
		)
		if readErr != nil {
			return store.GlobalIdentityPresenceRecord{}, false, readErr
		}
		if int64(len(allCommitments)) != input.TotalCommitmentCount ||
			protocol.Digest(
				protocol.GlobalIdentityPresenceCommitmentSetMessage(
					allCommitments,
				),
			) != input.CommitmentSetHash {
			return store.GlobalIdentityPresenceRecord{}, false,
				store.ErrGlobalIdentityPresenceConflict
		}
		for index, commitment := range allCommitments {
			if index > 0 &&
				allCommitments[index-1] > commitment {
				return store.GlobalIdentityPresenceRecord{}, false,
					store.ErrGlobalIdentityPresenceConflict
			}
			active, linkErr := globalIdentityCommitmentActiveForPeriod(
				ctx,
				tx,
				input.DeploymentID,
				input.KeyVersion,
				commitment,
				input.Period,
				0,
			)
			if linkErr != nil {
				return store.GlobalIdentityPresenceRecord{}, false, linkErr
			}
			if !active {
				return store.GlobalIdentityPresenceRecord{}, false,
					store.ErrGlobalIdentityLinkConflict
			}
		}
		aggregatePayloadHash = protocol.Digest(
			protocol.GlobalIdentityLegacyPresenceBatchPayload(
				input.Period,
				input.Revision,
				input.SupersedesBatchID,
				input.ReportedQMAUCount,
				input.KeyVersion,
				input.Suite,
				allCommitments,
			),
		)
		input.Commitments = allCommitments
		input.PrivateEventHash = protocol.Digest(
			protocol.GlobalIdentityPrivateEventCommitment(
				protocol.GlobalIdentityActionPresence,
				input.DeploymentID,
				input.CandidateBatchID,
				input.KeyVersion,
				"",
				"",
				"",
				input.Period,
				aggregatePayloadHash,
			),
		)
		snapshot, snapshotErr := calculateGlobalIdentitySnapshot(
			ctx,
			tx,
			input.Period,
			head.EventIndex+1,
			input.PrivateEventHash,
			&input,
		)
		if snapshotErr != nil {
			return store.GlobalIdentityPresenceRecord{}, false, snapshotErr
		}
		snapshot.RegistryScope = input.RegistryScope
		event := store.GlobalIdentityEvent{
			EventIndex:          head.EventIndex + 1,
			EventID:             input.CandidateEventID,
			Action:              protocol.GlobalIdentityActionPresence,
			DeploymentID:        input.DeploymentID,
			Period:              input.Period,
			AggregateCommitment: snapshot.AggregateCommitment,
			ReportedCount:       snapshot.ReportedQMAUCount,
			DeduplicatedCount:   snapshot.DeduplicatedNetworkQMAU,
			AcceptedAt:          input.AcceptedAt,
			PreviousEventHash:   head.EventHash,
			RegistryScope:       input.RegistryScope,
			RegistryKeyID:       input.RegistryKeyID,
			IdempotencyKey:      input.IdempotencyKey,
			RequestNonce:        input.Nonce,
			RequestTimestamp:    input.RequestTimestamp,
			RequestHash:         input.RequestHash,
			PayloadHash:         input.PayloadHash,
			RequestSignature: append(
				[]byte(nil),
				input.RequestSignature...,
			),
			PrivateEventHash: input.PrivateEventHash,
			SubjectID:        input.CandidateBatchID,
		}
		event.EventHash = protocol.Digest(
			protocol.GlobalIdentityEventHashMessage(
				globalIdentityProtocolEvent(event),
			),
		)
		snapshot.ThroughEventHash = event.EventHash
		snapshot.GeneratedAt = event.AcceptedAt
		event.ReceiptSignature, err = signEvent(event)
		if err != nil {
			return store.GlobalIdentityPresenceRecord{}, false,
				fmt.Errorf("sign global identity presence event: %w", err)
		}
		record.BatchID = input.CandidateBatchID
		record.LinkedObservationCount = int64(len(allCommitments))
		record.UnlinkedQMAUCount = input.ReportedQMAUCount -
			record.LinkedObservationCount
		record.Event = event
		record.Snapshot = snapshot
	}
	receiptView := globalIdentityPresenceReceiptView(record)
	receiptMessage := protocol.GlobalIdentityPresenceChunkReceiptMessage(
		receiptView,
	)
	record.ReceiptHash = protocol.Digest(receiptMessage)
	record.ReceiptSignature, err = signReceipt(receiptView)
	if err != nil {
		return store.GlobalIdentityPresenceRecord{}, false,
			fmt.Errorf("sign global identity presence chunk receipt: %w", err)
	}
	if !submissionExists {
		if err := insertGlobalIdentityPresenceSubmission(
			ctx,
			tx,
			input,
		); err != nil {
			return store.GlobalIdentityPresenceRecord{}, false, err
		}
	}
	if err := insertGlobalIdentityPresenceChunk(
		ctx,
		tx,
		input,
		record,
	); err != nil {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}
	if complete {
		if err := insertCompletedGlobalIdentityPresence(
			ctx,
			tx,
			input,
			record,
			aggregatePayloadHash,
		); err != nil {
			return store.GlobalIdentityPresenceRecord{}, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return store.GlobalIdentityPresenceRecord{}, false,
			fmt.Errorf("commit global identity presence chunk: %w", err)
	}
	return record, false, nil
}

func ensureGlobalIdentityPresenceSubmission(
	ctx context.Context,
	tx *sql.Tx,
	input store.GlobalIdentityPresenceInput,
) (bool, error) {
	var persisted store.GlobalIdentityPresenceInput
	err := tx.QueryRowContext(ctx, `
		SELECT
			submission_id,
			deployment_id,
			registry_scope,
			period,
			revision,
			supersedes_batch_id,
			reported_qmau_count,
			key_version,
			suite,
			chunk_count,
			total_commitment_count,
			commitment_set_hash
		FROM global_identity_presence_submissions
		WHERE submission_id = ?`,
		input.SubmissionID,
	).Scan(
		&persisted.SubmissionID,
		&persisted.DeploymentID,
		&persisted.RegistryScope,
		&persisted.Period,
		&persisted.Revision,
		&persisted.SupersedesBatchID,
		&persisted.ReportedQMAUCount,
		&persisted.KeyVersion,
		&persisted.Suite,
		&persisted.ChunkCount,
		&persisted.TotalCommitmentCount,
		&persisted.CommitmentSetHash,
	)
	if err == nil {
		if persisted.DeploymentID != input.DeploymentID ||
			persisted.RegistryScope != input.RegistryScope ||
			persisted.Period != input.Period ||
			persisted.Revision != input.Revision ||
			persisted.SupersedesBatchID != input.SupersedesBatchID ||
			persisted.ReportedQMAUCount != input.ReportedQMAUCount ||
			persisted.KeyVersion != input.KeyVersion ||
			persisted.Suite != input.Suite ||
			persisted.ChunkCount != input.ChunkCount ||
			persisted.TotalCommitmentCount !=
				input.TotalCommitmentCount ||
			persisted.CommitmentSetHash != input.CommitmentSetHash {
			return false, store.ErrGlobalIdentityPresenceConflict
		}
		return true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf(
			"read global identity presence submission: %w",
			err,
		)
	}
	var conflictingSubmission string
	err = tx.QueryRowContext(ctx, `
		SELECT submission_id
		FROM global_identity_presence_submissions
		WHERE deployment_id = ? AND period = ? AND revision = ?`,
		input.DeploymentID,
		input.Period,
		input.Revision,
	).Scan(&conflictingSubmission)
	if err == nil {
		return false, store.ErrGlobalIdentityPresenceConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf(
			"read competing global identity presence submission: %w",
			err,
		)
	}
	return false, nil
}

func insertGlobalIdentityPresenceSubmission(
	ctx context.Context,
	tx *sql.Tx,
	input store.GlobalIdentityPresenceInput,
) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO global_identity_presence_submissions (
			submission_id,
			deployment_id,
			registry_scope,
			period,
			revision,
			supersedes_batch_id,
			reported_qmau_count,
			key_version,
			suite,
			chunk_count,
			total_commitment_count,
			commitment_set_hash,
			created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		input.SubmissionID,
		input.DeploymentID,
		input.RegistryScope,
		input.Period,
		input.Revision,
		input.SupersedesBatchID,
		input.ReportedQMAUCount,
		input.KeyVersion,
		input.Suite,
		input.ChunkCount,
		input.TotalCommitmentCount,
		input.CommitmentSetHash,
		input.AcceptedAt,
	); err != nil {
		return fmt.Errorf(
			"persist global identity presence submission: %w",
			err,
		)
	}
	return nil
}

func globalIdentityCompletedCommitments(
	ctx context.Context,
	tx *sql.Tx,
	input store.GlobalIdentityPresenceInput,
) ([]string, error) {
	chunks := make([][]string, input.ChunkCount)
	seen := make([]bool, input.ChunkCount)
	expectedItemCounts := make([]int64, input.ChunkCount)
	rows, err := tx.QueryContext(ctx, `
		SELECT
			c.chunk_index,
			c.item_count,
			i.item_index,
			i.key_version,
			i.network_identity_commitment
		FROM global_identity_presence_chunks c
		LEFT JOIN global_identity_presence_chunk_items i
		  ON i.submission_id = c.submission_id
		 AND i.chunk_index = c.chunk_index
		WHERE c.submission_id = ?
		ORDER BY c.chunk_index, i.item_index`,
		input.SubmissionID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"read staged global identity presence chunks: %w",
			err,
		)
	}
	for rows.Next() {
		var chunkIndex, itemCount int64
		var itemIndex, keyVersion sql.NullInt64
		var commitment sql.NullString
		if err := rows.Scan(
			&chunkIndex,
			&itemCount,
			&itemIndex,
			&keyVersion,
			&commitment,
		); err != nil {
			rows.Close()
			return nil, fmt.Errorf(
				"scan staged global identity presence item: %w",
				err,
			)
		}
		if chunkIndex < 0 ||
			chunkIndex >= input.ChunkCount ||
			chunkIndex == input.ChunkIndex {
			rows.Close()
			return nil, store.ErrInconsistentState
		}
		seen[chunkIndex] = true
		expectedItemCounts[chunkIndex] = itemCount
		if !itemIndex.Valid {
			if itemCount != 0 {
				rows.Close()
				return nil, store.ErrInconsistentState
			}
			continue
		}
		if !keyVersion.Valid ||
			!commitment.Valid ||
			keyVersion.Int64 != input.KeyVersion ||
			itemIndex.Int64 != int64(len(chunks[chunkIndex])) ||
			int64(len(chunks[chunkIndex])) >= itemCount {
			rows.Close()
			return nil, store.ErrInconsistentState
		}
		chunks[chunkIndex] = append(
			chunks[chunkIndex],
			commitment.String,
		)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf(
			"iterate staged global identity presence items: %w",
			err,
		)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf(
			"close staged global identity presence items: %w",
			err,
		)
	}
	chunks[input.ChunkIndex] = append(
		[]string(nil),
		input.Commitments...,
	)
	seen[input.ChunkIndex] = true
	total := 0
	for chunkIndex, present := range seen {
		if !present ||
			int64(len(chunks[chunkIndex])) !=
				expectedItemCounts[chunkIndex] {
			return nil, store.ErrGlobalIdentityPresenceConflict
		}
		total += len(chunks[chunkIndex])
	}
	commitments := make([]string, 0, total)
	for _, chunk := range chunks {
		commitments = append(commitments, chunk...)
	}
	return commitments, nil
}

func globalIdentityPresenceReceiptView(
	record store.GlobalIdentityPresenceRecord,
) protocol.GlobalIdentityPresenceBatchResponse {
	response := protocol.GlobalIdentityPresenceBatchResponse{
		ProtocolVersion:      protocol.Version,
		RegistryScope:        record.RegistryScope,
		SubmissionID:         record.SubmissionID,
		DeploymentID:         record.DeploymentID,
		Period:               record.Period,
		Revision:             record.Revision,
		ChunkIndex:           record.ChunkIndex,
		ChunkCount:           record.ChunkCount,
		ReceivedChunkCount:   record.ReceivedChunkCount,
		TotalCommitmentCount: record.TotalCommitmentCount,
		CommitmentSetHash:    record.CommitmentSetHash,
		Complete:             record.Complete,
		BatchID:              record.BatchID,
		LinkedCount:          record.LinkedObservationCount,
		UnlinkedCount:        record.UnlinkedQMAUCount,
		RequestHash:          record.RequestHash,
		PayloadHash:          record.PayloadHash,
		AcceptedAt:           record.AcceptedAt,
		RegistryKeyID:        record.RegistryKeyID,
	}
	if record.Complete {
		event := globalIdentityProtocolEvent(record.Event)
		response.Event = &event
	}
	return response
}

func insertGlobalIdentityPresenceChunk(
	ctx context.Context,
	tx *sql.Tx,
	input store.GlobalIdentityPresenceInput,
	record store.GlobalIdentityPresenceRecord,
) error {
	completedEventHash := ""
	if record.Complete {
		completedEventHash = record.Event.EventHash
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO global_identity_presence_chunks (
			submission_id,
			chunk_index,
			deployment_id,
			idempotency_key,
			request_nonce,
			request_timestamp,
			request_hash,
			payload_hash,
			request_signature,
			item_count,
			acceptance_index,
			received_chunk_count,
			complete,
			completed_batch_id,
			completed_event_hash,
			accepted_at,
			registry_key_id,
			receipt_hash,
			receipt_signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		input.SubmissionID,
		input.ChunkIndex,
		input.DeploymentID,
		input.IdempotencyKey,
		input.Nonce,
		input.RequestTimestamp,
		input.RequestHash,
		input.PayloadHash,
		input.RequestSignature,
		len(input.Commitments),
		record.ReceivedChunkCount,
		record.ReceivedChunkCount,
		record.Complete,
		record.BatchID,
		completedEventHash,
		record.AcceptedAt,
		record.RegistryKeyID,
		record.ReceiptHash,
		record.ReceiptSignature,
	); err != nil {
		return fmt.Errorf(
			"persist global identity presence chunk: %w",
			err,
		)
	}
	for itemIndex, commitment := range input.Commitments {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO global_identity_presence_chunk_items (
				submission_id,
				chunk_index,
				item_index,
				key_version,
				network_identity_commitment
			) VALUES (?, ?, ?, ?, ?)`,
			input.SubmissionID,
			input.ChunkIndex,
			itemIndex,
			input.KeyVersion,
			commitment,
		); err != nil {
			return fmt.Errorf(
				"persist global identity presence chunk item: %w",
				err,
			)
		}
	}
	return nil
}

func insertCompletedGlobalIdentityPresence(
	ctx context.Context,
	tx *sql.Tx,
	input store.GlobalIdentityPresenceInput,
	record store.GlobalIdentityPresenceRecord,
	aggregatePayloadHash string,
) error {
	if err := insertGlobalIdentityEvent(ctx, tx, record.Event); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO global_identity_presence_batches (
			batch_id,
			deployment_id,
			period,
			revision,
			supersedes_batch_id,
			reported_qmau_count,
			linked_observation_count,
			unlinked_qmau_count,
			key_version,
			suite,
			payload_hash,
			event_index,
			accepted_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.BatchID,
		record.DeploymentID,
		record.Period,
		record.Revision,
		record.SupersedesBatchID,
		record.ReportedQMAUCount,
		record.LinkedObservationCount,
		record.UnlinkedQMAUCount,
		input.KeyVersion,
		input.Suite,
		record.PayloadHash,
		record.Event.EventIndex,
		record.AcceptedAt,
	); err != nil {
		return fmt.Errorf("persist global identity presence batch: %w", err)
	}
	for itemIndex, commitment := range input.Commitments {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO global_identity_presence_items (
				batch_id,
				item_index,
				key_version,
				network_identity_commitment
			) VALUES (?, ?, ?, ?)`,
			record.BatchID,
			itemIndex,
			input.KeyVersion,
			commitment,
		); err != nil {
			return fmt.Errorf(
				"persist completed global identity presence item: %w",
				err,
			)
		}
	}
	if err := insertGlobalIdentitySnapshot(
		ctx,
		tx,
		record.Snapshot,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO global_identity_presence_completions (
			submission_id,
			completing_chunk_index,
			batch_id,
			event_index,
			aggregate_payload_hash,
			completed_at
		) VALUES (?, ?, ?, ?, ?, ?)`,
		record.SubmissionID,
		record.ChunkIndex,
		record.BatchID,
		record.Event.EventIndex,
		aggregatePayloadHash,
		record.AcceptedAt,
	); err != nil {
		return fmt.Errorf(
			"persist global identity presence completion: %w",
			err,
		)
	}
	return nil
}

func ensureGlobalIdentityPresenceNonceAvailable(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	nonce string,
	requestHash string,
) error {
	var persisted string
	err := tx.QueryRowContext(ctx, `
		SELECT request_hash
		FROM global_identity_presence_chunks
		WHERE deployment_id = ? AND request_nonce = ?`,
		deploymentID,
		nonce,
	).Scan(&persisted)
	if err == nil {
		if persisted != requestHash {
			return store.ErrReplayConflict
		}
		return store.ErrInconsistentState
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf(
			"read global identity presence chunk nonce: %w",
			err,
		)
	}
	return ensureGlobalIdentityNonceAvailable(
		ctx,
		tx,
		deploymentID,
		nonce,
		requestHash,
	)
}

func verifyPresenceQMAUSource(
	ctx context.Context,
	tx *sql.Tx,
	input store.GlobalIdentityPresenceInput,
) error {
	var qualifiedMAUCount int64
	if err := tx.QueryRowContext(ctx, `
		SELECT qualified_mau_count
		FROM mau_batches
		WHERE deployment_id = ?
		  AND period = ?
		  AND kind = ?
		  AND revision = ?`,
		input.DeploymentID,
		input.Period,
		protocol.QualifiedMAUKind,
		input.Revision,
	).Scan(&qualifiedMAUCount); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		return fmt.Errorf("read QMAU source for global dedup: %w", err)
	}
	if qualifiedMAUCount != input.ReportedQMAUCount {
		return store.ErrGlobalIdentityPresenceConflict
	}
	return nil
}

func globalIdentityCommitmentActiveForPeriod(
	ctx context.Context,
	queryer queryRower,
	deploymentID string,
	keyVersion int64,
	commitment string,
	period string,
	throughEventIndex int64,
) (bool, error) {
	var active int
	if err := queryer.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1
			FROM global_identity_link_history h
			JOIN global_identity_events e
			  ON e.event_index = h.event_index
			WHERE h.deployment_id = ?
			  AND h.status = 'ACTIVE'
			  AND h.key_version = ?
			  AND h.network_identity_commitment = ?
			  AND h.active_from_period <= ?
			  AND (
			      h.inactive_from_period = ''
			      OR h.inactive_from_period > ?
			  )
			  AND e.period <= ?
			  AND (? = 0 OR h.event_index <= ?)
			  AND NOT EXISTS (
			      SELECT 1
			      FROM global_identity_link_history h2
			      JOIN global_identity_events e2
			        ON e2.event_index = h2.event_index
			      WHERE h2.link_id = h.link_id
			        AND h2.event_index > h.event_index
			        AND (? = 0 OR h2.event_index <= ?)
			        AND e2.action IN (?, ?)
			        AND e2.period <= ?
			  )
		)`,
		deploymentID,
		keyVersion,
		commitment,
		period,
		period,
		period,
		throughEventIndex,
		throughEventIndex,
		throughEventIndex,
		throughEventIndex,
		protocol.GlobalIdentityActionCorrect,
		protocol.GlobalIdentityActionUnlink,
		period,
	).Scan(&active); err != nil {
		return false, fmt.Errorf(
			"verify period-effective global identity link: %w",
			err,
		)
	}
	return active == 1, nil
}

func verifyPresenceRevision(
	ctx context.Context,
	tx *sql.Tx,
	input store.GlobalIdentityPresenceInput,
) error {
	var batchID string
	var revision int64
	err := tx.QueryRowContext(ctx, `
		SELECT batch_id, revision
		FROM global_identity_presence_batches
		WHERE deployment_id = ? AND period = ?
		ORDER BY revision DESC
		LIMIT 1`,
		input.DeploymentID,
		input.Period,
	).Scan(&batchID, &revision)
	if errors.Is(err, sql.ErrNoRows) {
		if input.Revision < 1 || input.SupersedesBatchID != "" {
			return store.ErrGlobalIdentityPresenceConflict
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read current global identity presence revision: %w", err)
	}
	if input.Revision != revision+1 || input.SupersedesBatchID != batchID {
		return store.ErrGlobalIdentityPresenceConflict
	}
	return nil
}

func calculateGlobalIdentitySnapshot(
	ctx context.Context,
	tx *sql.Tx,
	period string,
	throughEventIndex int64,
	privateEventHash string,
	candidate *store.GlobalIdentityPresenceInput,
) (protocol.GlobalIdentityDedupSnapshot, error) {
	excludedDeployment := ""
	if candidate != nil {
		excludedDeployment = candidate.DeploymentID
	}
	rows, err := tx.QueryContext(ctx, `
		WITH current_batches AS (
			SELECT b.*
			FROM global_identity_presence_batches b
			JOIN (
				SELECT deployment_id, MAX(revision) AS revision
				FROM global_identity_presence_batches
				WHERE period = ? AND deployment_id <> ?
				GROUP BY deployment_id
			) latest
			  ON latest.deployment_id = b.deployment_id
			 AND latest.revision = b.revision
			WHERE b.period = ?
		)
		SELECT
			deployment_id,
			reported_qmau_count,
			linked_observation_count,
			unlinked_qmau_count
		FROM current_batches`,
		period,
		excludedDeployment,
		period,
	)
	if err != nil {
		return protocol.GlobalIdentityDedupSnapshot{},
			fmt.Errorf("read current global identity presence totals: %w", err)
	}
	var reported, linked, unlinked, covered int64
	for rows.Next() {
		var deploymentID string
		var rowReported, rowLinked, rowUnlinked int64
		if err := rows.Scan(
			&deploymentID,
			&rowReported,
			&rowLinked,
			&rowUnlinked,
		); err != nil {
			rows.Close()
			return protocol.GlobalIdentityDedupSnapshot{},
				fmt.Errorf("scan global identity presence totals: %w", err)
		}
		reported += rowReported
		linked += rowLinked
		unlinked += rowUnlinked
		covered++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return protocol.GlobalIdentityDedupSnapshot{},
			fmt.Errorf("iterate global identity presence totals: %w", err)
	}
	if err := rows.Close(); err != nil {
		return protocol.GlobalIdentityDedupSnapshot{},
			fmt.Errorf("close global identity presence totals: %w", err)
	}

	globalIDs := make(map[string]struct{})
	identityRows, err := tx.QueryContext(ctx, `
		WITH current_batches AS (
			SELECT b.batch_id
			FROM global_identity_presence_batches b
			JOIN (
				SELECT deployment_id, MAX(revision) AS revision
				FROM global_identity_presence_batches
				WHERE period = ? AND deployment_id <> ?
				GROUP BY deployment_id
			) latest
			  ON latest.deployment_id = b.deployment_id
			 AND latest.revision = b.revision
			WHERE b.period = ?
		)
		SELECT DISTINCT a.global_identity_id
		FROM current_batches b
		JOIN global_identity_presence_items i ON i.batch_id = b.batch_id
		JOIN global_identity_aliases a
		  ON a.key_version = i.key_version
		 AND a.network_identity_commitment =
		     i.network_identity_commitment`,
		period,
		excludedDeployment,
		period,
	)
	if err != nil {
		return protocol.GlobalIdentityDedupSnapshot{},
			fmt.Errorf("read unique global identities for snapshot: %w", err)
	}
	for identityRows.Next() {
		var globalID string
		if err := identityRows.Scan(&globalID); err != nil {
			identityRows.Close()
			return protocol.GlobalIdentityDedupSnapshot{},
				fmt.Errorf("scan unique global identity: %w", err)
		}
		globalIDs[globalID] = struct{}{}
	}
	if err := identityRows.Err(); err != nil {
		identityRows.Close()
		return protocol.GlobalIdentityDedupSnapshot{},
			fmt.Errorf("iterate unique global identities: %w", err)
	}
	if err := identityRows.Close(); err != nil {
		return protocol.GlobalIdentityDedupSnapshot{},
			fmt.Errorf("close unique global identities: %w", err)
	}

	if candidate != nil {
		reported += candidate.ReportedQMAUCount
		linked += int64(len(candidate.Commitments))
		unlinked += candidate.ReportedQMAUCount -
			int64(len(candidate.Commitments))
		covered++
		for _, commitment := range candidate.Commitments {
			globalID, err := globalIdentityAliasTx(
				ctx,
				tx,
				candidate.KeyVersion,
				commitment,
			)
			if err != nil {
				return protocol.GlobalIdentityDedupSnapshot{}, err
			}
			globalIDs[globalID] = struct{}{}
		}
	}
	unique := int64(len(globalIDs))
	deduplicated := unique + unlinked
	if deduplicated > reported {
		return protocol.GlobalIdentityDedupSnapshot{},
			store.ErrInconsistentState
	}
	var revision int64
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(revision), 0) + 1
		FROM global_identity_dedup_snapshots
		WHERE period = ?`,
		period,
	).Scan(&revision); err != nil {
		return protocol.GlobalIdentityDedupSnapshot{},
			fmt.Errorf("read next global identity snapshot revision: %w", err)
	}
	snapshot := protocol.GlobalIdentityDedupSnapshot{
		ProtocolVersion:           protocol.Version,
		Period:                    period,
		Revision:                  revision,
		ReportedQMAUCount:         reported,
		LinkedObservationCount:    linked,
		GloballyUniqueLinkedCount: unique,
		UnlinkedQMAUCount:         unlinked,
		DeduplicatedNetworkQMAU:   deduplicated,
		DuplicateReduction:        reported - deduplicated,
		CoveredDeploymentCount:    covered,
		ThroughEventIndex:         throughEventIndex,
	}
	snapshot.AggregateCommitment = protocol.Digest(
		protocol.GlobalIdentitySnapshotCommitmentMessage(
			snapshot.Period,
			snapshot.Revision,
			snapshot.ReportedQMAUCount,
			snapshot.LinkedObservationCount,
			snapshot.GloballyUniqueLinkedCount,
			snapshot.UnlinkedQMAUCount,
			snapshot.DeduplicatedNetworkQMAU,
			snapshot.DuplicateReduction,
			snapshot.CoveredDeploymentCount,
			snapshot.ThroughEventIndex,
			privateEventHash,
		),
	)
	return snapshot, nil
}

func writeGlobalIdentitySnapshot(
	ctx context.Context,
	tx *sql.Tx,
	period string,
	event store.GlobalIdentityEvent,
	privateEventHash string,
) (protocol.GlobalIdentityDedupSnapshot, error) {
	snapshot, err := calculateGlobalIdentitySnapshot(
		ctx,
		tx,
		period,
		event.EventIndex,
		privateEventHash,
		nil,
	)
	if err != nil {
		return protocol.GlobalIdentityDedupSnapshot{}, err
	}
	snapshot.RegistryScope = event.RegistryScope
	snapshot.ThroughEventHash = event.EventHash
	snapshot.GeneratedAt = event.AcceptedAt
	if err := insertGlobalIdentitySnapshot(ctx, tx, snapshot); err != nil {
		return protocol.GlobalIdentityDedupSnapshot{}, err
	}
	return snapshot, nil
}

func insertGlobalIdentitySnapshot(
	ctx context.Context,
	tx *sql.Tx,
	snapshot protocol.GlobalIdentityDedupSnapshot,
) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO global_identity_dedup_snapshots (
			period,
			revision,
			reported_qmau_count,
			linked_observation_count,
			globally_unique_linked_count,
			unlinked_qmau_count,
			deduplicated_network_qmau,
			duplicate_reduction,
			covered_deployment_count,
			aggregate_commitment,
			through_event_index,
			through_event_hash,
			generated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		snapshot.Period,
		snapshot.Revision,
		snapshot.ReportedQMAUCount,
		snapshot.LinkedObservationCount,
		snapshot.GloballyUniqueLinkedCount,
		snapshot.UnlinkedQMAUCount,
		snapshot.DeduplicatedNetworkQMAU,
		snapshot.DuplicateReduction,
		snapshot.CoveredDeploymentCount,
		snapshot.AggregateCommitment,
		snapshot.ThroughEventIndex,
		snapshot.ThroughEventHash,
		snapshot.GeneratedAt,
	); err != nil {
		return fmt.Errorf("persist global identity dedup snapshot: %w", err)
	}
	return nil
}

func (sqliteStore *Store) GlobalIdentityDedupSnapshot(
	ctx context.Context,
	period string,
) (protocol.GlobalIdentityDedupSnapshot, error) {
	return scanGlobalIdentitySnapshot(sqliteStore.db.QueryRowContext(ctx, `
		SELECT
			period,
			revision,
			reported_qmau_count,
			linked_observation_count,
			globally_unique_linked_count,
			unlinked_qmau_count,
			deduplicated_network_qmau,
			duplicate_reduction,
			covered_deployment_count,
			aggregate_commitment,
			through_event_index,
			through_event_hash,
			generated_at
		FROM global_identity_dedup_snapshots
		WHERE period = ?
		ORDER BY revision DESC
		LIMIT 1`,
		period,
	))
}

func globalIdentityPresenceByEvent(
	ctx context.Context,
	queryer queryRower,
	eventIndex int64,
) (store.GlobalIdentityPresenceRecord, error) {
	var record store.GlobalIdentityPresenceRecord
	if err := queryer.QueryRowContext(ctx, `
		SELECT
			batch_id,
			deployment_id,
			period,
			revision,
			supersedes_batch_id,
			reported_qmau_count,
			linked_observation_count,
			unlinked_qmau_count,
			payload_hash,
			accepted_at
		FROM global_identity_presence_batches
		WHERE event_index = ?`,
		eventIndex,
	).Scan(
		&record.BatchID,
		&record.DeploymentID,
		&record.Period,
		&record.Revision,
		&record.SupersedesBatchID,
		&record.ReportedQMAUCount,
		&record.LinkedObservationCount,
		&record.UnlinkedQMAUCount,
		&record.PayloadHash,
		&record.AcceptedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.GlobalIdentityPresenceRecord{}, store.ErrNotFound
		}
		return store.GlobalIdentityPresenceRecord{},
			fmt.Errorf("read global identity presence batch: %w", err)
	}
	event, err := scanGlobalIdentityEvent(queryer.QueryRowContext(
		ctx,
		globalIdentityEventSelect+" WHERE event_index = ?",
		eventIndex,
	))
	if err != nil {
		return store.GlobalIdentityPresenceRecord{}, err
	}
	record.Event = event
	record.Snapshot, err = scanGlobalIdentitySnapshot(queryer.QueryRowContext(
		ctx,
		`SELECT
			period,
			revision,
			reported_qmau_count,
			linked_observation_count,
			globally_unique_linked_count,
			unlinked_qmau_count,
			deduplicated_network_qmau,
			duplicate_reduction,
			covered_deployment_count,
			aggregate_commitment,
			through_event_index,
			through_event_hash,
			generated_at
		FROM global_identity_dedup_snapshots
		WHERE through_event_index = ?`,
		eventIndex,
	))
	return record, err
}

func globalIdentityPresenceByIdempotency(
	ctx context.Context,
	queryer queryRower,
	deploymentID string,
	idempotencyKey string,
) (store.GlobalIdentityPresenceRecord, error) {
	var record store.GlobalIdentityPresenceRecord
	var complete int
	var eventIndex sql.NullInt64
	if err := queryer.QueryRowContext(ctx, `
		SELECT
			s.submission_id,
			s.deployment_id,
			s.registry_scope,
			s.period,
			s.revision,
			s.supersedes_batch_id,
			s.reported_qmau_count,
			s.chunk_count,
			s.total_commitment_count,
			s.commitment_set_hash,
			c.chunk_index,
			c.received_chunk_count,
			c.complete,
			c.completed_batch_id,
			c.request_hash,
			c.payload_hash,
			c.accepted_at,
			c.registry_key_id,
			c.receipt_hash,
			c.receipt_signature,
			x.event_index
		FROM global_identity_presence_chunks c
		JOIN global_identity_presence_submissions s
		  ON s.submission_id = c.submission_id
		LEFT JOIN global_identity_presence_completions x
		  ON x.submission_id = c.submission_id
		 AND x.completing_chunk_index = c.chunk_index
		WHERE c.deployment_id = ?
		  AND c.idempotency_key = ?`,
		deploymentID,
		idempotencyKey,
	).Scan(
		&record.SubmissionID,
		&record.DeploymentID,
		&record.RegistryScope,
		&record.Period,
		&record.Revision,
		&record.SupersedesBatchID,
		&record.ReportedQMAUCount,
		&record.ChunkCount,
		&record.TotalCommitmentCount,
		&record.CommitmentSetHash,
		&record.ChunkIndex,
		&record.ReceivedChunkCount,
		&complete,
		&record.BatchID,
		&record.RequestHash,
		&record.PayloadHash,
		&record.AcceptedAt,
		&record.RegistryKeyID,
		&record.ReceiptHash,
		&record.ReceiptSignature,
		&eventIndex,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.GlobalIdentityPresenceRecord{}, store.ErrNotFound
		}
		return store.GlobalIdentityPresenceRecord{}, fmt.Errorf(
			"read global identity presence chunk by idempotency: %w",
			err,
		)
	}
	record.Complete = complete == 1
	if !record.Complete {
		if record.BatchID != "" || eventIndex.Valid {
			return store.GlobalIdentityPresenceRecord{},
				store.ErrInconsistentState
		}
		return record, nil
	}
	if record.BatchID == "" || !eventIndex.Valid {
		return store.GlobalIdentityPresenceRecord{},
			store.ErrInconsistentState
	}
	completed, err := globalIdentityPresenceByEvent(
		ctx,
		queryer,
		eventIndex.Int64,
	)
	if err != nil {
		return store.GlobalIdentityPresenceRecord{}, err
	}
	if completed.BatchID != record.BatchID ||
		completed.DeploymentID != record.DeploymentID ||
		completed.Period != record.Period ||
		completed.Revision != record.Revision {
		return store.GlobalIdentityPresenceRecord{},
			store.ErrInconsistentState
	}
	record.LinkedObservationCount = completed.LinkedObservationCount
	record.UnlinkedQMAUCount = completed.UnlinkedQMAUCount
	record.Event = completed.Event
	record.Snapshot = completed.Snapshot
	return record, nil
}

func scanGlobalIdentitySnapshot(
	scanner rowScanner,
) (protocol.GlobalIdentityDedupSnapshot, error) {
	snapshot := protocol.GlobalIdentityDedupSnapshot{
		ProtocolVersion: protocol.Version,
	}
	if err := scanner.Scan(
		&snapshot.Period,
		&snapshot.Revision,
		&snapshot.ReportedQMAUCount,
		&snapshot.LinkedObservationCount,
		&snapshot.GloballyUniqueLinkedCount,
		&snapshot.UnlinkedQMAUCount,
		&snapshot.DeduplicatedNetworkQMAU,
		&snapshot.DuplicateReduction,
		&snapshot.CoveredDeploymentCount,
		&snapshot.AggregateCommitment,
		&snapshot.ThroughEventIndex,
		&snapshot.ThroughEventHash,
		&snapshot.GeneratedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return protocol.GlobalIdentityDedupSnapshot{}, store.ErrNotFound
		}
		return protocol.GlobalIdentityDedupSnapshot{},
			fmt.Errorf("scan global identity dedup snapshot: %w", err)
	}
	return snapshot, nil
}
