package sqlite

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

type globalIdentityPresenceSubmissionAudit struct {
	submissionID         string
	deploymentID         string
	registryScope        string
	period               string
	revision             int64
	supersedesBatchID    string
	reportedQMAUCount    int64
	keyVersion           int64
	suite                string
	chunkCount           int64
	totalCommitmentCount int64
	commitmentSetHash    string
	createdAt            string
	deploymentKey        ed25519.PublicKey
}

type globalIdentityPresenceChunkAudit struct {
	chunkIndex         int64
	idempotencyKey     string
	nonce              string
	requestTimestamp   string
	requestHash        string
	payloadHash        string
	requestSignature   []byte
	itemCount          int64
	acceptanceIndex    int64
	receivedChunkCount int64
	complete           bool
	completedBatchID   string
	completedEventHash string
	acceptedAt         string
	registryKeyID      string
	receiptHash        string
	receiptSignature   []byte
	commitments        []string
}

type globalIdentityPresenceCompletionAudit struct {
	exists               bool
	completingChunkIndex int64
	batchID              string
	eventIndex           int64
	aggregatePayloadHash string
	completedAt          string
}

func (sqliteStore *Store) verifyGlobalIdentityPresenceChunks(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
	events map[int64]store.GlobalIdentityEvent,
) error {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT submission_id
		FROM global_identity_presence_submissions
		ORDER BY submission_id`)
	if err != nil {
		return inconsistent(
			"read global identity presence submission identifiers",
			err,
		)
	}
	submissionIDs := make([]string, 0)
	for rows.Next() {
		var submissionID string
		if err := rows.Scan(&submissionID); err != nil {
			rows.Close()
			return inconsistent(
				"scan global identity presence submission identifier",
				err,
			)
		}
		submissionIDs = append(submissionIDs, submissionID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return inconsistent(
			"iterate global identity presence submission identifiers",
			err,
		)
	}
	if err := rows.Close(); err != nil {
		return inconsistent(
			"close global identity presence submission identifiers",
			err,
		)
	}
	for _, submissionID := range submissionIDs {
		submission, err := sqliteStore.globalIdentityPresenceSubmissionAudit(
			ctx,
			submissionID,
		)
		if err != nil {
			return err
		}
		if err := sqliteStore.verifyGlobalIdentityPresenceSubmission(
			ctx,
			submission,
			registryPublicKey,
			registryKeyID,
			registryScope,
			events,
		); err != nil {
			return err
		}
	}
	return nil
}

func (sqliteStore *Store) globalIdentityPresenceSubmissionAudit(
	ctx context.Context,
	submissionID string,
) (globalIdentityPresenceSubmissionAudit, error) {
	var submission globalIdentityPresenceSubmissionAudit
	var deploymentDER []byte
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT
			s.submission_id,
			s.deployment_id,
			s.registry_scope,
			s.period,
			s.revision,
			s.supersedes_batch_id,
			s.reported_qmau_count,
			s.key_version,
			s.suite,
			s.chunk_count,
			s.total_commitment_count,
			s.commitment_set_hash,
			s.created_at,
			d.public_key_der
		FROM global_identity_presence_submissions s
		JOIN deployments d ON d.deployment_id = s.deployment_id
		WHERE s.submission_id = ?`,
		submissionID,
	).Scan(
		&submission.submissionID,
		&submission.deploymentID,
		&submission.registryScope,
		&submission.period,
		&submission.revision,
		&submission.supersedesBatchID,
		&submission.reportedQMAUCount,
		&submission.keyVersion,
		&submission.suite,
		&submission.chunkCount,
		&submission.totalCommitmentCount,
		&submission.commitmentSetHash,
		&submission.createdAt,
		&deploymentDER,
	); err != nil {
		return globalIdentityPresenceSubmissionAudit{}, inconsistent(
			"read global identity presence submission",
			err,
		)
	}
	deploymentKey, err := globalIdentityDeploymentKey(deploymentDER)
	if err != nil {
		return globalIdentityPresenceSubmissionAudit{}, inconsistent(
			"parse global identity presence deployment key",
			err,
		)
	}
	submission.deploymentKey = deploymentKey
	return submission, nil
}

func (sqliteStore *Store) verifyGlobalIdentityPresenceSubmission(
	ctx context.Context,
	submission globalIdentityPresenceSubmissionAudit,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
	events map[int64]store.GlobalIdentityEvent,
) error {
	if !validHexID(submission.submissionID, "gipsub_", 32) ||
		!validHexID(submission.deploymentID, "dep_", 32) ||
		submission.registryScope != registryScope ||
		!validGlobalIdentityPresencePeriod(submission.period) ||
		submission.revision < 1 ||
		(submission.supersedesBatchID != "" &&
			!validHexID(submission.supersedesBatchID, "batch_", 32)) ||
		submission.reportedQMAUCount < 0 ||
		submission.keyVersion < 1 ||
		submission.suite != protocol.GlobalIdentityVOPRFSuite ||
		submission.chunkCount < 1 ||
		submission.chunkCount > 4096 ||
		submission.totalCommitmentCount < 0 ||
		submission.totalCommitmentCount > submission.reportedQMAUCount ||
		submission.chunkCount >
			maxPresenceAuditInt64(1, submission.totalCommitmentCount) ||
		!protocol.IsDigest(submission.commitmentSetHash) ||
		!validPersistedTimestamp(submission.createdAt) {
		return inconsistentMessage(
			"global identity presence submission %s has invalid manifest fields",
			submission.submissionID,
		)
	}
	var keySuite string
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT suite
		FROM global_identity_voprf_keys
		WHERE key_version = ?`,
		submission.keyVersion,
	).Scan(&keySuite); err != nil {
		return inconsistent(
			"read global identity presence submission VOPRF key",
			err,
		)
	}
	if keySuite != submission.suite {
		return inconsistentMessage(
			"global identity presence submission %s has a mismatched VOPRF suite",
			submission.submissionID,
		)
	}
	if err := sqliteStore.verifyGlobalIdentityPresenceSubmissionSource(
		ctx,
		submission,
	); err != nil {
		return err
	}
	completion, err := sqliteStore.globalIdentityPresenceCompletionAudit(
		ctx,
		submission.submissionID,
	)
	if err != nil {
		return err
	}
	chunks, err := sqliteStore.globalIdentityPresenceChunkAudits(
		ctx,
		submission,
	)
	if err != nil {
		return err
	}
	if len(chunks) < 1 ||
		int64(len(chunks)) > submission.chunkCount {
		return inconsistentMessage(
			"global identity presence submission %s has an invalid chunk count",
			submission.submissionID,
		)
	}
	var aggregateCommitments []string
	var previousAcceptedAt string
	for index := range chunks {
		chunk := &chunks[index]
		if chunk.chunkIndex != int64(index) ||
			chunk.acceptanceIndex != int64(index)+1 ||
			chunk.receivedChunkCount != chunk.acceptanceIndex ||
			(chunk.itemCount == 0 &&
				submission.totalCommitmentCount != 0) ||
			chunk.itemCount != int64(len(chunk.commitments)) ||
			chunk.itemCount > 4096 ||
			!validPersistedTimestamp(chunk.requestTimestamp) ||
			!validPersistedTimestamp(chunk.acceptedAt) ||
			(previousAcceptedAt != "" &&
				chunk.acceptedAt < previousAcceptedAt) {
			return inconsistentMessage(
				"global identity presence submission %s has invalid chunk sequencing",
				submission.submissionID,
			)
		}
		if index == 0 && chunk.acceptedAt != submission.createdAt {
			return inconsistentMessage(
				"global identity presence submission %s has an invalid creation timestamp",
				submission.submissionID,
			)
		}
		previousAcceptedAt = chunk.acceptedAt
		request := protocol.GlobalIdentityPresenceBatchRequest{
			ProtocolVersion:      protocol.Version,
			RegistryScope:        registryScope,
			DeploymentID:         submission.deploymentID,
			Timestamp:            chunk.requestTimestamp,
			Nonce:                chunk.nonce,
			IdempotencyKey:       chunk.idempotencyKey,
			SubmissionID:         submission.submissionID,
			Period:               submission.period,
			Revision:             submission.revision,
			SupersedesBatchID:    submission.supersedesBatchID,
			ReportedQMAUCount:    submission.reportedQMAUCount,
			KeyVersion:           submission.keyVersion,
			Suite:                submission.suite,
			ChunkIndex:           chunk.chunkIndex,
			ChunkCount:           submission.chunkCount,
			TotalCommitmentCount: submission.totalCommitmentCount,
			CommitmentSetHash:    submission.commitmentSetHash,
			Commitments:          chunk.commitments,
			PayloadHash:          chunk.payloadHash,
		}
		payloadHash := protocol.Digest(
			protocol.GlobalIdentityPresenceBatchPayload(request),
		)
		requestMessage := protocol.CanonicalRequest(
			"POST",
			protocol.GlobalIdentityPresenceBatchPath,
			protocol.Version,
			registryScope,
			submission.deploymentID,
			chunk.requestTimestamp,
			chunk.nonce,
			chunk.idempotencyKey,
			chunk.payloadHash,
		)
		if chunk.payloadHash != payloadHash ||
			chunk.requestHash != protocol.Digest(requestMessage) ||
			!ed25519.Verify(
				submission.deploymentKey,
				requestMessage,
				chunk.requestSignature,
			) {
			return inconsistentMessage(
				"global identity presence submission %s chunk %d fails request verification",
				submission.submissionID,
				chunk.chunkIndex,
			)
		}
		for commitmentIndex, commitment := range chunk.commitments {
			if !protocol.IsDigest(commitment) ||
				(commitmentIndex > 0 &&
					chunk.commitments[commitmentIndex-1] > commitment) {
				return inconsistentMessage(
					"global identity presence submission %s chunk %d has invalid commitments",
					submission.submissionID,
					chunk.chunkIndex,
				)
			}
			active, err := globalIdentityCommitmentActiveForPeriod(
				ctx,
				sqliteStore.db,
				submission.deploymentID,
				submission.keyVersion,
				commitment,
				submission.period,
				0,
			)
			if err != nil {
				return inconsistent(
					"verify staged global identity presence commitment",
					err,
				)
			}
			if !active {
				return inconsistentMessage(
					"global identity presence submission %s has an unaudited staged commitment",
					submission.submissionID,
				)
			}
		}
		if err := verifyGlobalIdentityPresenceChunkReceipt(
			submission,
			*chunk,
			completion,
			events,
			registryPublicKey,
			registryKeyID,
			registryScope,
		); err != nil {
			return err
		}
		aggregateCommitments = append(
			aggregateCommitments,
			chunk.commitments...,
		)
	}
	complete := int64(len(chunks)) == submission.chunkCount
	if complete != completion.exists {
		return inconsistentMessage(
			"global identity presence submission %s has an inconsistent completion",
			submission.submissionID,
		)
	}
	if !complete {
		if chunks[len(chunks)-1].complete {
			return inconsistentMessage(
				"partial global identity presence submission %s is marked complete",
				submission.submissionID,
			)
		}
		return nil
	}
	for index, commitment := range aggregateCommitments {
		if index > 0 && aggregateCommitments[index-1] > commitment {
			return inconsistentMessage(
				"global identity presence submission %s is not globally sorted",
				submission.submissionID,
			)
		}
	}
	if int64(len(aggregateCommitments)) !=
		submission.totalCommitmentCount ||
		protocol.Digest(
			protocol.GlobalIdentityPresenceCommitmentSetMessage(
				aggregateCommitments,
			),
		) != submission.commitmentSetHash ||
		!chunks[len(chunks)-1].complete ||
		completion.completingChunkIndex !=
			chunks[len(chunks)-1].chunkIndex ||
		completion.completedAt != chunks[len(chunks)-1].acceptedAt {
		return inconsistentMessage(
			"global identity presence submission %s has an invalid completed set",
			submission.submissionID,
		)
	}
	expectedAggregatePayloadHash := protocol.Digest(
		protocol.GlobalIdentityLegacyPresenceBatchPayload(
			submission.period,
			submission.revision,
			submission.supersedesBatchID,
			submission.reportedQMAUCount,
			submission.keyVersion,
			submission.suite,
			aggregateCommitments,
		),
	)
	if completion.aggregatePayloadHash != expectedAggregatePayloadHash {
		return inconsistentMessage(
			"global identity presence submission %s has an invalid aggregate payload commitment",
			submission.submissionID,
		)
	}
	return nil
}

func (sqliteStore *Store) verifyGlobalIdentityPresenceSubmissionSource(
	ctx context.Context,
	submission globalIdentityPresenceSubmissionAudit,
) error {
	var qualifiedMAUCount int64
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT qualified_mau_count
		FROM mau_batches
		WHERE deployment_id = ?
		  AND period = ?
		  AND kind = ?
		  AND revision = ?`,
		submission.deploymentID,
		submission.period,
		protocol.QualifiedMAUKind,
		submission.revision,
	).Scan(&qualifiedMAUCount); err != nil {
		return inconsistent(
			"read staged global identity presence QMAU source",
			err,
		)
	}
	if qualifiedMAUCount != submission.reportedQMAUCount {
		return inconsistentMessage(
			"global identity presence submission %s differs from its QMAU source",
			submission.submissionID,
		)
	}
	var priorBatchID string
	var priorRevision int64
	err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT batch_id, revision
		FROM global_identity_presence_batches
		WHERE deployment_id = ?
		  AND period = ?
		  AND revision < ?
		ORDER BY revision DESC
		LIMIT 1`,
		submission.deploymentID,
		submission.period,
		submission.revision,
	).Scan(&priorBatchID, &priorRevision)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if submission.revision != 1 ||
			submission.supersedesBatchID != "" {
			return inconsistentMessage(
				"global identity presence submission %s has an invalid first revision",
				submission.submissionID,
			)
		}
	case err != nil:
		return inconsistent(
			"read staged global identity presence prior revision",
			err,
		)
	case submission.revision != priorRevision+1 ||
		submission.supersedesBatchID != priorBatchID:
		return inconsistentMessage(
			"global identity presence submission %s does not extend the prior revision",
			submission.submissionID,
		)
	}
	return nil
}

func (sqliteStore *Store) globalIdentityPresenceCompletionAudit(
	ctx context.Context,
	submissionID string,
) (globalIdentityPresenceCompletionAudit, error) {
	var completion globalIdentityPresenceCompletionAudit
	err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT
			completing_chunk_index,
			batch_id,
			event_index,
			aggregate_payload_hash,
			completed_at
		FROM global_identity_presence_completions
		WHERE submission_id = ?`,
		submissionID,
	).Scan(
		&completion.completingChunkIndex,
		&completion.batchID,
		&completion.eventIndex,
		&completion.aggregatePayloadHash,
		&completion.completedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return completion, nil
	}
	if err != nil {
		return globalIdentityPresenceCompletionAudit{}, inconsistent(
			"read global identity presence completion",
			err,
		)
	}
	completion.exists = true
	return completion, nil
}

func (sqliteStore *Store) globalIdentityPresenceChunkAudits(
	ctx context.Context,
	submission globalIdentityPresenceSubmissionAudit,
) ([]globalIdentityPresenceChunkAudit, error) {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT chunk_index
		FROM global_identity_presence_chunks
		WHERE submission_id = ?
		ORDER BY acceptance_index`,
		submission.submissionID,
	)
	if err != nil {
		return nil, inconsistent(
			"read global identity presence chunk identifiers",
			err,
		)
	}
	indexes := make([]int64, 0)
	for rows.Next() {
		var chunkIndex int64
		if err := rows.Scan(&chunkIndex); err != nil {
			rows.Close()
			return nil, inconsistent(
				"scan global identity presence chunk identifier",
				err,
			)
		}
		indexes = append(indexes, chunkIndex)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, inconsistent(
			"iterate global identity presence chunk identifiers",
			err,
		)
	}
	if err := rows.Close(); err != nil {
		return nil, inconsistent(
			"close global identity presence chunk identifiers",
			err,
		)
	}
	chunks := make([]globalIdentityPresenceChunkAudit, 0, len(indexes))
	for _, chunkIndex := range indexes {
		var chunk globalIdentityPresenceChunkAudit
		var complete int
		if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT
				chunk_index,
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
			FROM global_identity_presence_chunks
			WHERE submission_id = ? AND chunk_index = ?`,
			submission.submissionID,
			chunkIndex,
		).Scan(
			&chunk.chunkIndex,
			&chunk.idempotencyKey,
			&chunk.nonce,
			&chunk.requestTimestamp,
			&chunk.requestHash,
			&chunk.payloadHash,
			&chunk.requestSignature,
			&chunk.itemCount,
			&chunk.acceptanceIndex,
			&chunk.receivedChunkCount,
			&complete,
			&chunk.completedBatchID,
			&chunk.completedEventHash,
			&chunk.acceptedAt,
			&chunk.registryKeyID,
			&chunk.receiptHash,
			&chunk.receiptSignature,
		); err != nil {
			return nil, inconsistent(
				"read global identity presence chunk",
				err,
			)
		}
		chunk.complete = complete == 1
		itemRows, err := sqliteStore.db.QueryContext(ctx, `
			SELECT item_index, key_version, network_identity_commitment
			FROM global_identity_presence_chunk_items
			WHERE submission_id = ? AND chunk_index = ?
			ORDER BY item_index`,
			submission.submissionID,
			chunkIndex,
		)
		if err != nil {
			return nil, inconsistent(
				"read global identity presence chunk items",
				err,
			)
		}
		for itemRows.Next() {
			var itemIndex, keyVersion int64
			var commitment string
			if err := itemRows.Scan(
				&itemIndex,
				&keyVersion,
				&commitment,
			); err != nil {
				itemRows.Close()
				return nil, inconsistent(
					"scan global identity presence chunk item",
					err,
				)
			}
			if itemIndex != int64(len(chunk.commitments)) ||
				keyVersion != submission.keyVersion {
				itemRows.Close()
				return nil, inconsistentMessage(
					"global identity presence submission %s has invalid chunk item indexes",
					submission.submissionID,
				)
			}
			chunk.commitments = append(
				chunk.commitments,
				commitment,
			)
		}
		if err := itemRows.Err(); err != nil {
			itemRows.Close()
			return nil, inconsistent(
				"iterate global identity presence chunk items",
				err,
			)
		}
		if err := itemRows.Close(); err != nil {
			return nil, inconsistent(
				"close global identity presence chunk items",
				err,
			)
		}
		chunks = append(chunks, chunk)
	}
	return chunks, nil
}

func verifyGlobalIdentityPresenceChunkReceipt(
	submission globalIdentityPresenceSubmissionAudit,
	chunk globalIdentityPresenceChunkAudit,
	completion globalIdentityPresenceCompletionAudit,
	events map[int64]store.GlobalIdentityEvent,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	response := protocol.GlobalIdentityPresenceBatchResponse{
		ProtocolVersion:      protocol.Version,
		RegistryScope:        registryScope,
		SubmissionID:         submission.submissionID,
		DeploymentID:         submission.deploymentID,
		Period:               submission.period,
		Revision:             submission.revision,
		ChunkIndex:           chunk.chunkIndex,
		ChunkCount:           submission.chunkCount,
		ReceivedChunkCount:   chunk.receivedChunkCount,
		TotalCommitmentCount: submission.totalCommitmentCount,
		CommitmentSetHash:    submission.commitmentSetHash,
		Complete:             chunk.complete,
		BatchID:              chunk.completedBatchID,
		RequestHash:          chunk.requestHash,
		PayloadHash:          chunk.payloadHash,
		AcceptedAt:           chunk.acceptedAt,
		RegistryKeyID:        chunk.registryKeyID,
	}
	if chunk.complete {
		if !completion.exists ||
			completion.completingChunkIndex != chunk.chunkIndex {
			return inconsistentMessage(
				"global identity presence submission %s has an orphaned completion receipt",
				submission.submissionID,
			)
		}
		event, ok := events[completion.eventIndex]
		if !ok ||
			event.EventHash != chunk.completedEventHash ||
			event.SubjectID != completion.batchID ||
			completion.batchID != chunk.completedBatchID {
			return inconsistentMessage(
				"global identity presence submission %s completion receipt does not match its event",
				submission.submissionID,
			)
		}
		protocolEvent := globalIdentityProtocolEvent(event)
		response.Event = &protocolEvent
	} else if chunk.completedBatchID != "" ||
		chunk.completedEventHash != "" {
		return inconsistentMessage(
			"partial global identity presence submission %s exposes aggregate state",
			submission.submissionID,
		)
	}
	receiptMessage := protocol.GlobalIdentityPresenceChunkReceiptMessage(
		response,
	)
	if chunk.registryKeyID != registryKeyID ||
		!protocol.IsDigest(chunk.requestHash) ||
		!protocol.IsDigest(chunk.payloadHash) ||
		!protocol.IsDigest(chunk.receiptHash) ||
		chunk.receiptHash != protocol.Digest(receiptMessage) ||
		!ed25519.Verify(
			registryPublicKey,
			receiptMessage,
			chunk.receiptSignature,
		) {
		return inconsistentMessage(
			"global identity presence submission %s chunk %d fails receipt verification",
			submission.submissionID,
			chunk.chunkIndex,
		)
	}
	return nil
}

func validGlobalIdentityPresencePeriod(value string) bool {
	if len(value) != len("2006-01") {
		return false
	}
	parsed, err := time.Parse("2006-01", value)
	return err == nil && parsed.Format("2006-01") == value
}

func maxPresenceAuditInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
