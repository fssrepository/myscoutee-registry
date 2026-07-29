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
) (store.GlobalIdentityPresenceRecord, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.GlobalIdentityPresenceRecord{}, false,
			fmt.Errorf("begin global identity presence batch: %w", err)
	}
	defer tx.Rollback()

	existing, err := globalIdentityEventByIdempotency(
		ctx,
		tx,
		input.DeploymentID,
		input.IdempotencyKey,
	)
	if err == nil {
		if existing.Action != protocol.GlobalIdentityActionPresence ||
			existing.PayloadHash != input.PayloadHash {
			return store.GlobalIdentityPresenceRecord{}, false,
				store.ErrIdempotencyConflict
		}
		record, readErr := globalIdentityPresenceByEvent(
			ctx,
			tx,
			existing.EventIndex,
		)
		if readErr != nil {
			return store.GlobalIdentityPresenceRecord{}, false, readErr
		}
		if err := tx.Commit(); err != nil {
			return store.GlobalIdentityPresenceRecord{}, false,
				fmt.Errorf("commit duplicate identity presence batch: %w", err)
		}
		return record, true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}
	if err := ensureGlobalIdentityNonceAvailable(
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
	if int64(len(input.Commitments)) > input.ReportedQMAUCount {
		return store.GlobalIdentityPresenceRecord{}, false,
			store.ErrGlobalIdentityPresenceConflict
	}
	if err := verifyPresenceQMAUSource(ctx, tx, input); err != nil {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}
	if err := verifyPresenceRevision(ctx, tx, input); err != nil {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}
	for _, commitment := range input.Commitments {
		var activeLink int
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS(
				SELECT 1
				FROM global_identity_links
				WHERE deployment_id = ?
				  AND status = 'ACTIVE'
				  AND key_version = ?
				  AND network_identity_commitment = ?
				  AND active_from_period <= ?
				  AND (
				      inactive_from_period = ''
				      OR inactive_from_period > ?
				  )
			)`,
			input.DeploymentID,
			input.KeyVersion,
			commitment,
			input.Period,
			input.Period,
		).Scan(&activeLink); err != nil {
			return store.GlobalIdentityPresenceRecord{}, false,
				fmt.Errorf("verify active global identity presence link: %w", err)
		}
		if activeLink != 1 {
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

	snapshot, err := calculateGlobalIdentitySnapshot(
		ctx,
		tx,
		input.Period,
		head.EventIndex+1,
		input.PrivateEventHash,
		&input,
	)
	if err != nil {
		return store.GlobalIdentityPresenceRecord{}, false, err
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
		RequestSignature:    append([]byte(nil), input.RequestSignature...),
		PrivateEventHash:    input.PrivateEventHash,
		SubjectID:           input.CandidateBatchID,
	}
	event.EventHash = protocol.Digest(
		protocol.GlobalIdentityEventHashMessage(
			globalIdentityProtocolEvent(event),
		),
	)
	event.ReceiptSignature, err = signEvent(event)
	if err != nil {
		return store.GlobalIdentityPresenceRecord{}, false,
			fmt.Errorf("sign global identity presence event: %w", err)
	}
	if err := insertGlobalIdentityEvent(ctx, tx, event); err != nil {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}
	linkedCount := int64(len(input.Commitments))
	unlinkedCount := input.ReportedQMAUCount - linkedCount
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
		input.CandidateBatchID,
		input.DeploymentID,
		input.Period,
		input.Revision,
		input.SupersedesBatchID,
		input.ReportedQMAUCount,
		linkedCount,
		unlinkedCount,
		input.KeyVersion,
		input.Suite,
		input.PayloadHash,
		event.EventIndex,
		input.AcceptedAt,
	); err != nil {
		return store.GlobalIdentityPresenceRecord{}, false,
			fmt.Errorf("persist global identity presence batch: %w", err)
	}
	for index, commitment := range input.Commitments {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO global_identity_presence_items (
				batch_id,
				item_index,
				key_version,
				network_identity_commitment
			) VALUES (?, ?, ?, ?)`,
			input.CandidateBatchID,
			index,
			input.KeyVersion,
			commitment,
		); err != nil {
			return store.GlobalIdentityPresenceRecord{}, false,
				fmt.Errorf("persist global identity presence item: %w", err)
		}
	}
	snapshot.ThroughEventHash = event.EventHash
	snapshot.GeneratedAt = event.AcceptedAt
	if err := insertGlobalIdentitySnapshot(ctx, tx, snapshot); err != nil {
		return store.GlobalIdentityPresenceRecord{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return store.GlobalIdentityPresenceRecord{}, false,
			fmt.Errorf("commit global identity presence batch: %w", err)
	}
	return store.GlobalIdentityPresenceRecord{
		BatchID:                input.CandidateBatchID,
		DeploymentID:           input.DeploymentID,
		Period:                 input.Period,
		Revision:               input.Revision,
		SupersedesBatchID:      input.SupersedesBatchID,
		ReportedQMAUCount:      input.ReportedQMAUCount,
		LinkedObservationCount: linkedCount,
		UnlinkedQMAUCount:      unlinkedCount,
		PayloadHash:            input.PayloadHash,
		AcceptedAt:             input.AcceptedAt,
		Event:                  event,
		Snapshot:               snapshot,
	}, false, nil
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
