package sqlite

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func (sqliteStore *Store) VerifyGlobalIdentities(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	if len(registryPublicKey) != ed25519.PublicKeySize {
		return inconsistentMessage(
			"global identity verifier has an invalid registry public key",
		)
	}
	if err := sqliteStore.verifyGlobalIdentityKeys(ctx); err != nil {
		return err
	}
	if err := sqliteStore.verifyGlobalIdentityEvaluations(
		ctx,
		registryPublicKey,
		registryKeyID,
		registryScope,
	); err != nil {
		return err
	}
	events, err := sqliteStore.verifyGlobalIdentityEvents(
		ctx,
		registryPublicKey,
		registryKeyID,
		registryScope,
	)
	if err != nil {
		return err
	}
	if err := sqliteStore.verifyGlobalIdentityPresenceChunks(
		ctx,
		registryPublicKey,
		registryKeyID,
		registryScope,
		events,
	); err != nil {
		return err
	}
	if err := sqliteStore.verifyGlobalIdentitySnapshots(
		ctx,
		events,
		registryScope,
	); err != nil {
		return err
	}
	if err := sqliteStore.verifyGlobalIdentityDirectRows(ctx); err != nil {
		return err
	}
	return nil
}

func (sqliteStore *Store) verifyGlobalIdentityKeys(
	ctx context.Context,
) error {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT key_version, suite, public_key, activated_at
		FROM global_identity_voprf_keys
		ORDER BY key_version`)
	if err != nil {
		return inconsistent("read global identity VOPRF keys", err)
	}
	defer rows.Close()
	var expectedVersion int64 = 1
	for rows.Next() {
		var version int64
		var suite, activatedAt string
		var publicKey []byte
		if err := rows.Scan(
			&version,
			&suite,
			&publicKey,
			&activatedAt,
		); err != nil {
			return inconsistent("scan global identity VOPRF key", err)
		}
		if version != expectedVersion ||
			suite != protocol.GlobalIdentityVOPRFSuite ||
			len(publicKey) != 33 ||
			!validPersistedTimestamp(activatedAt) {
			return inconsistentMessage(
				"global identity VOPRF key version %d is invalid",
				version,
			)
		}
		expectedVersion++
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate global identity VOPRF keys", err)
	}
	return nil
}

func (sqliteStore *Store) verifyGlobalIdentityEvaluations(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			e.evaluation_id,
			e.deployment_id,
			e.idempotency_key,
			e.request_nonce,
			e.request_timestamp,
			e.request_hash,
			e.request_signature,
			e.payload_hash,
			e.key_version,
			e.suite,
			e.blinded_element,
			e.public_key,
			e.evaluated_element,
			e.proof,
			e.response_hash,
			e.evaluated_at,
			e.receipt_signature,
			d.public_key_der,
			k.suite,
			k.public_key
		FROM global_identity_evaluations e
		JOIN deployments d ON d.deployment_id = e.deployment_id
		JOIN global_identity_voprf_keys k
		  ON k.key_version = e.key_version
		ORDER BY e.evaluated_at, e.evaluation_id`)
	if err != nil {
		return inconsistent("read global identity evaluations", err)
	}
	defer rows.Close()
	for rows.Next() {
		var record store.GlobalIdentityEvaluationRecord
		var deploymentDER []byte
		var persistedSuite string
		var persistedPublicKey []byte
		if err := rows.Scan(
			&record.EvaluationID,
			&record.DeploymentID,
			&record.IdempotencyKey,
			&record.Nonce,
			&record.RequestTimestamp,
			&record.RequestHash,
			&record.RequestSignature,
			&record.PayloadHash,
			&record.KeyVersion,
			&record.Suite,
			&record.BlindedElement,
			&record.PublicKey,
			&record.EvaluatedElement,
			&record.Proof,
			&record.ResponseHash,
			&record.EvaluatedAt,
			&record.ReceiptSignature,
			&deploymentDER,
			&persistedSuite,
			&persistedPublicKey,
		); err != nil {
			return inconsistent("scan global identity evaluation", err)
		}
		deploymentKey, err := globalIdentityDeploymentKey(deploymentDER)
		if err != nil {
			return inconsistent(
				"parse global identity evaluation deployment key",
				err,
			)
		}
		blinded := base64.StdEncoding.EncodeToString(record.BlindedElement)
		publicKey := base64.StdEncoding.EncodeToString(record.PublicKey)
		evaluated := base64.StdEncoding.EncodeToString(record.EvaluatedElement)
		proof := base64.StdEncoding.EncodeToString(record.Proof)
		if !validHexID(record.EvaluationID, "gieval_", 32) ||
			record.Suite != protocol.GlobalIdentityVOPRFSuite ||
			len(record.BlindedElement) != 33 ||
			len(record.PublicKey) != 33 ||
			len(record.EvaluatedElement) != 33 ||
			len(record.Proof) != 64 ||
			record.Suite != persistedSuite ||
			!bytes.Equal(
				record.PublicKey,
				persistedPublicKey,
			) ||
			!protocol.IsDigest(record.PayloadHash) ||
			!protocol.IsDigest(record.RequestHash) ||
			!protocol.IsDigest(record.ResponseHash) ||
			!validPersistedTimestamp(record.RequestTimestamp) ||
			!validPersistedTimestamp(record.EvaluatedAt) {
			return inconsistentMessage(
				"global identity evaluation %s has invalid fields",
				record.EvaluationID,
			)
		}
		payloadHash := protocol.Digest(
			protocol.GlobalIdentityEvaluationPayload(
				record.KeyVersion,
				record.Suite,
				blinded,
			),
		)
		requestMessage := protocol.CanonicalRequest(
			"POST",
			protocol.GlobalIdentityEvaluatePath,
			protocol.Version,
			registryScope,
			record.DeploymentID,
			record.RequestTimestamp,
			record.Nonce,
			record.IdempotencyKey,
			record.PayloadHash,
		)
		expectedResponseHash := protocol.Digest(
			protocol.GlobalIdentityEvaluationResult(
				record.KeyVersion,
				record.Suite,
				publicKey,
				evaluated,
				proof,
			),
		)
		receiptMessage := protocol.GlobalIdentityEvaluationReceiptMessage(
			protocol.Version,
			registryScope,
			record.DeploymentID,
			record.KeyVersion,
			record.Suite,
			record.RequestHash,
			record.ResponseHash,
			record.EvaluatedAt,
			registryKeyID,
		)
		if record.PayloadHash != payloadHash ||
			record.RequestHash != protocol.Digest(requestMessage) ||
			!ed25519.Verify(
				deploymentKey,
				requestMessage,
				record.RequestSignature,
			) ||
			record.ResponseHash != expectedResponseHash ||
			!ed25519.Verify(
				registryPublicKey,
				receiptMessage,
				record.ReceiptSignature,
			) {
			return inconsistentMessage(
				"global identity evaluation %s fails signature or hash verification",
				record.EvaluationID,
			)
		}
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate global identity evaluations", err)
	}
	return nil
}

func (sqliteStore *Store) verifyGlobalIdentityEvents(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) (map[int64]store.GlobalIdentityEvent, error) {
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		`SELECT event_index
		 FROM global_identity_events
		 ORDER BY event_index`,
	)
	if err != nil {
		return nil, inconsistent("read global identity events", err)
	}
	eventIndexes := make([]int64, 0)
	for rows.Next() {
		var eventIndex int64
		if err := rows.Scan(&eventIndex); err != nil {
			rows.Close()
			return nil, inconsistent("scan global identity event index", err)
		}
		eventIndexes = append(eventIndexes, eventIndex)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, inconsistent("iterate global identity event indexes", err)
	}
	if err := rows.Close(); err != nil {
		return nil, inconsistent("close global identity event indexes", err)
	}
	events := make(map[int64]store.GlobalIdentityEvent)
	var previousHash = protocol.ZeroHash
	var previousAcceptedAt string
	var expectedIndex int64 = 1
	for _, eventIndex := range eventIndexes {
		event, err := scanGlobalIdentityEvent(
			sqliteStore.db.QueryRowContext(
				ctx,
				globalIdentityEventSelect+" WHERE event_index = ?",
				eventIndex,
			),
		)
		if err != nil {
			return nil, inconsistent("scan global identity event", err)
		}
		if event.EventIndex != expectedIndex ||
			!validHexID(event.EventID, "gievt_", 32) ||
			event.RegistryScope != registryScope ||
			event.RegistryKeyID != registryKeyID ||
			event.PreviousEventHash != previousHash ||
			!protocol.IsDigest(event.AggregateCommitment) ||
			!protocol.IsDigest(event.PrivateEventHash) ||
			!protocol.IsDigest(event.EventHash) ||
			!protocol.IsDigest(event.PayloadHash) ||
			!protocol.IsDigest(event.RequestHash) ||
			!validPersistedTimestamp(event.RequestTimestamp) ||
			!validPersistedTimestamp(event.AcceptedAt) ||
			(previousAcceptedAt != "" &&
				event.AcceptedAt < previousAcceptedAt) {
			return nil, inconsistentMessage(
				"global identity event %d has invalid chain fields",
				event.EventIndex,
			)
		}
		payload, privateHash, err :=
			sqliteStore.globalIdentityEventSource(ctx, event)
		if err != nil {
			return nil, err
		}
		deploymentKey, err := sqliteStore.globalIdentityDeploymentKey(
			ctx,
			event.DeploymentID,
		)
		if err != nil {
			return nil, err
		}
		requestMessage := protocol.CanonicalRequest(
			"POST",
			globalIdentityActionPath(event.Action),
			protocol.Version,
			registryScope,
			event.DeploymentID,
			event.RequestTimestamp,
			event.RequestNonce,
			event.IdempotencyKey,
			event.PayloadHash,
		)
		protocolEvent := globalIdentityProtocolEvent(event)
		if event.PayloadHash != protocol.Digest(payload) ||
			event.RequestHash != protocol.Digest(requestMessage) ||
			event.PrivateEventHash != privateHash ||
			!ed25519.Verify(
				deploymentKey,
				requestMessage,
				event.RequestSignature,
			) ||
			event.EventHash != protocol.Digest(
				protocol.GlobalIdentityEventHashMessage(protocolEvent),
			) ||
			!ed25519.Verify(
				registryPublicKey,
				protocol.GlobalIdentityEventReceiptMessage(protocolEvent),
				event.ReceiptSignature,
			) {
			return nil, inconsistentMessage(
				"global identity event %d fails signature or hash verification",
				event.EventIndex,
			)
		}
		events[event.EventIndex] = event
		previousHash = event.EventHash
		previousAcceptedAt = event.AcceptedAt
		expectedIndex++
	}
	return events, nil
}

func (sqliteStore *Store) globalIdentityEventSource(
	ctx context.Context,
	event store.GlobalIdentityEvent,
) ([]byte, string, error) {
	switch event.Action {
	case protocol.GlobalIdentityActionLink,
		protocol.GlobalIdentityActionUnlink,
		protocol.GlobalIdentityActionCorrect:
		var link store.GlobalIdentityLink
		var reason string
		if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT
				link_id,
				deployment_id,
				global_identity_id,
				status,
				key_version,
				suite,
				network_identity_commitment,
				consent_version,
				consent_evidence_commitment,
				verified_at,
				active_from_period,
				inactive_from_period,
				event_index,
				'',
				reason_commitment
			FROM global_identity_link_history
			WHERE event_index = ?`,
			event.EventIndex,
		).Scan(
			&link.LinkID,
			&link.DeploymentID,
			&link.GlobalIdentityID,
			&link.Status,
			&link.KeyVersion,
			&link.Suite,
			&link.NetworkIdentityCommitment,
			&link.ConsentVersion,
			&link.ConsentEvidenceCommitment,
			&link.VerifiedAt,
			&link.ActiveFromPeriod,
			&link.InactiveFromPeriod,
			&link.LatestEventIndex,
			&link.LatestEventHash,
			&reason,
		); err != nil {
			return nil, "", inconsistent(
				"read global identity link event source",
				err,
			)
		}
		if link.LinkID != event.SubjectID ||
			link.DeploymentID != event.DeploymentID {
			return nil, "", inconsistentMessage(
				"global identity link history does not match event %d",
				event.EventIndex,
			)
		}
		if event.Action == protocol.GlobalIdentityActionLink {
			request := protocol.GlobalIdentityLinkRequest{
				KeyVersion:                link.KeyVersion,
				Suite:                     link.Suite,
				NetworkIdentityCommitment: link.NetworkIdentityCommitment,
				ConsentVersion:            link.ConsentVersion,
				ConsentEvidenceCommitment: link.ConsentEvidenceCommitment,
				VerifiedAt:                link.VerifiedAt,
				EffectivePeriod:           event.Period,
			}
			privateHash := protocol.Digest(
				protocol.GlobalIdentityPrivateEventCommitment(
					event.Action,
					event.DeploymentID,
					link.LinkID,
					link.KeyVersion,
					link.NetworkIdentityCommitment,
					link.ConsentEvidenceCommitment,
					"",
					event.Period,
					event.PayloadHash,
				),
			)
			return protocol.GlobalIdentityLinkPayload(request),
				privateHash,
				nil
		}
		request := protocol.GlobalIdentityLinkActionRequest{
			Action:           event.Action,
			LinkID:           link.LinkID,
			EffectivePeriod:  event.Period,
			ReasonCommitment: reason,
		}
		if event.Action == protocol.GlobalIdentityActionCorrect {
			request.ReplacementKeyVersion = link.KeyVersion
			request.ReplacementSuite = link.Suite
			request.ReplacementCommitment =
				link.NetworkIdentityCommitment
			request.ConsentVersion = link.ConsentVersion
			request.ConsentEvidenceCommitment =
				link.ConsentEvidenceCommitment
			request.VerifiedAt = link.VerifiedAt
		}
		aggregatePayloadHash := protocol.Digest(
			protocol.GlobalIdentityLegacyPresenceBatchPayload(
				request.Period,
				request.Revision,
				request.SupersedesBatchID,
				request.ReportedQMAUCount,
				request.KeyVersion,
				request.Suite,
				request.Commitments,
			),
		)
		signedPayload := protocol.GlobalIdentityLegacyPresenceBatchPayload(
			request.Period,
			request.Revision,
			request.SupersedesBatchID,
			request.ReportedQMAUCount,
			request.KeyVersion,
			request.Suite,
			request.Commitments,
		)
		privatePayloadHash := event.PayloadHash
		chunkRequest, completedAggregateHash, chunked, err :=
			sqliteStore.globalIdentityCompletedPresenceRequest(
				ctx,
				event,
				batchID,
				request,
			)
		if err != nil {
			return nil, "", err
		}
		if chunked {
			if completedAggregateHash != aggregatePayloadHash {
				return nil, "", inconsistentMessage(
					"global identity presence completion %s has an invalid aggregate payload hash",
					batchID,
				)
			}
			signedPayload = protocol.GlobalIdentityPresenceBatchPayload(
				chunkRequest,
			)
			privatePayloadHash = completedAggregateHash
		}
		privateHash := protocol.Digest(
			protocol.GlobalIdentityPrivateEventCommitment(
				event.Action,
				event.DeploymentID,
				link.LinkID,
				request.ReplacementKeyVersion,
				request.ReplacementCommitment,
				request.ConsentEvidenceCommitment,
				reason,
				event.Period,
				event.PayloadHash,
			),
		)
		return protocol.GlobalIdentityLinkActionPayload(request),
			privateHash,
			nil
	case protocol.GlobalIdentityActionPresence:
		var request protocol.GlobalIdentityPresenceBatchRequest
		var batchID string
		var linkedObservationCount int64
		var unlinkedQMAUCount int64
		var payloadHash string
		var acceptedAt string
		if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT
				batch_id,
				period,
				revision,
				supersedes_batch_id,
				reported_qmau_count,
				key_version,
				suite,
				linked_observation_count,
				unlinked_qmau_count,
				payload_hash,
				accepted_at
			FROM global_identity_presence_batches
			WHERE event_index = ?`,
			event.EventIndex,
		).Scan(
			&batchID,
			&request.Period,
			&request.Revision,
			&request.SupersedesBatchID,
			&request.ReportedQMAUCount,
			&request.KeyVersion,
			&request.Suite,
			&linkedObservationCount,
			&unlinkedQMAUCount,
			&payloadHash,
			&acceptedAt,
		); err != nil {
			return nil, "", inconsistent(
				"read global identity presence event source",
				err,
			)
		}
		if batchID != event.SubjectID ||
			request.Period != event.Period ||
			payloadHash != event.PayloadHash ||
			acceptedAt != event.AcceptedAt {
			return nil, "", inconsistentMessage(
				"global identity presence batch does not match event %d",
				event.EventIndex,
			)
		}
		var persistedSuite string
		if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT suite
			FROM global_identity_voprf_keys
			WHERE key_version = ?`,
			request.KeyVersion,
		).Scan(&persistedSuite); err != nil {
			return nil, "", inconsistent(
				"read global identity presence VOPRF key",
				err,
			)
		}
		if request.Suite != persistedSuite {
			return nil, "", inconsistentMessage(
				"global identity presence batch %s has a mismatched VOPRF suite",
				batchID,
			)
		}
		itemRows, err := sqliteStore.db.QueryContext(ctx, `
			SELECT
				item_index,
				key_version,
				network_identity_commitment
			FROM global_identity_presence_items
			WHERE batch_id = ?
			ORDER BY item_index`,
			event.SubjectID,
		)
		if err != nil {
			return nil, "", inconsistent(
				"read global identity presence items",
				err,
			)
		}
		var expectedItemIndex int64
		var previousCommitment string
		for itemRows.Next() {
			var itemIndex int64
			var itemKeyVersion int64
			var commitment string
			if err := itemRows.Scan(
				&itemIndex,
				&itemKeyVersion,
				&commitment,
			); err != nil {
				itemRows.Close()
				return nil, "", inconsistent(
					"scan global identity presence item",
					err,
				)
			}
			if itemIndex != expectedItemIndex ||
				itemKeyVersion != request.KeyVersion ||
				!protocol.IsDigest(commitment) ||
				(previousCommitment != "" &&
					strings.Compare(previousCommitment, commitment) > 0) {
				itemRows.Close()
				return nil, "", inconsistentMessage(
					"global identity presence batch %s has invalid items",
					batchID,
				)
			}
			request.Commitments = append(request.Commitments, commitment)
			expectedItemIndex++
			previousCommitment = commitment
		}
		if err := itemRows.Err(); err != nil {
			itemRows.Close()
			return nil, "", inconsistent(
				"iterate global identity presence items",
				err,
			)
		}
		itemRows.Close()
		if linkedObservationCount != int64(len(request.Commitments)) ||
			unlinkedQMAUCount !=
				request.ReportedQMAUCount-linkedObservationCount ||
			request.ReportedQMAUCount < linkedObservationCount {
			return nil, "", inconsistentMessage(
				"global identity presence batch %s has inconsistent counts",
				batchID,
			)
		}
		var qualifiedMAUCount int64
		if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT qualified_mau_count
			FROM mau_batches
			WHERE deployment_id = ?
			  AND period = ?
			  AND kind = ?
			  AND revision = ?`,
			event.DeploymentID,
			request.Period,
			protocol.QualifiedMAUKind,
			request.Revision,
		).Scan(&qualifiedMAUCount); err != nil {
			return nil, "", inconsistent(
				"read global identity presence QMAU source",
				err,
			)
		}
		if qualifiedMAUCount != request.ReportedQMAUCount {
			return nil, "", inconsistentMessage(
				"global identity presence batch %s differs from its QMAU source",
				batchID,
			)
		}
		var previousBatchID string
		var previousRevision int64
		previousErr := sqliteStore.db.QueryRowContext(ctx, `
			SELECT batch_id, revision
			FROM global_identity_presence_batches
			WHERE deployment_id = ?
			  AND period = ?
			  AND revision < ?
			ORDER BY revision DESC
			LIMIT 1`,
			event.DeploymentID,
			request.Period,
			request.Revision,
		).Scan(&previousBatchID, &previousRevision)
		switch {
		case errors.Is(previousErr, sql.ErrNoRows):
			if request.SupersedesBatchID != "" {
				return nil, "", inconsistentMessage(
					"first global identity presence batch %s supersedes another batch",
					batchID,
				)
			}
		case previousErr != nil:
			return nil, "", inconsistent(
				"read prior global identity presence revision",
				previousErr,
			)
		case request.Revision != previousRevision+1 ||
			request.SupersedesBatchID != previousBatchID:
			return nil, "", inconsistentMessage(
				"global identity presence batch %s does not extend the prior revision",
				batchID,
			)
		}
		for _, commitment := range request.Commitments {
			active, err := globalIdentityCommitmentActiveForPeriod(
				ctx,
				sqliteStore.db,
				event.DeploymentID,
				request.KeyVersion,
				commitment,
				request.Period,
				event.EventIndex,
			)
			if err != nil {
				return nil, "", inconsistent(
					"verify period-effective global identity presence link",
					err,
				)
			}
			if !active {
				return nil, "", inconsistentMessage(
					"global identity presence batch %s contains an unaudited link",
					batchID,
				)
			}
		}
		privateHash := protocol.Digest(
			protocol.GlobalIdentityPrivateEventCommitment(
				event.Action,
				event.DeploymentID,
				event.SubjectID,
				request.KeyVersion,
				"",
				"",
				"",
				event.Period,
				privatePayloadHash,
			),
		)
		return signedPayload, privateHash, nil
	default:
		return nil, "", inconsistentMessage(
			"global identity event %d has unsupported action",
			event.EventIndex,
		)
	}
}

func (sqliteStore *Store) globalIdentityCompletedPresenceRequest(
	ctx context.Context,
	event store.GlobalIdentityEvent,
	batchID string,
	aggregateRequest protocol.GlobalIdentityPresenceBatchRequest,
) (protocol.GlobalIdentityPresenceBatchRequest, string, bool, error) {
	request := aggregateRequest
	var registryScope string
	var itemCount, receivedChunkCount int64
	var complete int
	var completedBatchID, completedEventHash string
	var persistedPayloadHash, aggregatePayloadHash string
	err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT
			s.submission_id,
			s.registry_scope,
			s.chunk_count,
			s.total_commitment_count,
			s.commitment_set_hash,
			c.chunk_index,
			c.item_count,
			c.received_chunk_count,
			c.complete,
			c.completed_batch_id,
			c.completed_event_hash,
			c.payload_hash,
			x.aggregate_payload_hash
		FROM global_identity_presence_completions x
		JOIN global_identity_presence_submissions s
		  ON s.submission_id = x.submission_id
		JOIN global_identity_presence_chunks c
		  ON c.submission_id = x.submission_id
		 AND c.chunk_index = x.completing_chunk_index
		WHERE x.event_index = ?
		  AND x.batch_id = ?`,
		event.EventIndex,
		batchID,
	).Scan(
		&request.SubmissionID,
		&registryScope,
		&request.ChunkCount,
		&request.TotalCommitmentCount,
		&request.CommitmentSetHash,
		&request.ChunkIndex,
		&itemCount,
		&receivedChunkCount,
		&complete,
		&completedBatchID,
		&completedEventHash,
		&persistedPayloadHash,
		&aggregatePayloadHash,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return protocol.GlobalIdentityPresenceBatchRequest{}, "", false, nil
	}
	if err != nil {
		return protocol.GlobalIdentityPresenceBatchRequest{}, "", false,
			inconsistent("read global identity presence completion", err)
	}
	if !validHexID(request.SubmissionID, "gipsub_", 32) ||
		registryScope != event.RegistryScope ||
		request.ChunkCount < 1 ||
		request.ChunkCount > 4096 ||
		request.ChunkIndex < 0 ||
		request.ChunkIndex >= request.ChunkCount ||
		receivedChunkCount != request.ChunkCount ||
		complete != 1 ||
		completedBatchID != batchID ||
		completedEventHash != event.EventHash ||
		persistedPayloadHash != event.PayloadHash ||
		request.TotalCommitmentCount !=
			int64(len(aggregateRequest.Commitments)) ||
		protocol.Digest(
			protocol.GlobalIdentityPresenceCommitmentSetMessage(
				aggregateRequest.Commitments,
			),
		) != request.CommitmentSetHash {
		return protocol.GlobalIdentityPresenceBatchRequest{}, "", false,
			inconsistentMessage(
				"global identity presence completion %s has invalid manifest fields",
				batchID,
			)
	}
	request.Commitments = nil
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT item_index, key_version, network_identity_commitment
		FROM global_identity_presence_chunk_items
		WHERE submission_id = ? AND chunk_index = ?
		ORDER BY item_index`,
		request.SubmissionID,
		request.ChunkIndex,
	)
	if err != nil {
		return protocol.GlobalIdentityPresenceBatchRequest{}, "", false,
			inconsistent(
				"read completing global identity presence chunk items",
				err,
			)
	}
	for rows.Next() {
		var itemIndex, keyVersion int64
		var commitment string
		if err := rows.Scan(
			&itemIndex,
			&keyVersion,
			&commitment,
		); err != nil {
			rows.Close()
			return protocol.GlobalIdentityPresenceBatchRequest{}, "", false,
				inconsistent(
					"scan completing global identity presence chunk item",
					err,
				)
		}
		if itemIndex != int64(len(request.Commitments)) ||
			keyVersion != request.KeyVersion ||
			!protocol.IsDigest(commitment) ||
			(len(request.Commitments) > 0 &&
				request.Commitments[len(request.Commitments)-1] > commitment) {
			rows.Close()
			return protocol.GlobalIdentityPresenceBatchRequest{}, "", false,
				inconsistentMessage(
					"global identity presence completion %s has invalid chunk items",
					batchID,
				)
		}
		request.Commitments = append(request.Commitments, commitment)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return protocol.GlobalIdentityPresenceBatchRequest{}, "", false,
			inconsistent(
				"iterate completing global identity presence chunk items",
				err,
			)
	}
	if err := rows.Close(); err != nil {
		return protocol.GlobalIdentityPresenceBatchRequest{}, "", false,
			inconsistent(
				"close completing global identity presence chunk items",
				err,
			)
	}
	if int64(len(request.Commitments)) != itemCount ||
		persistedPayloadHash != protocol.Digest(
			protocol.GlobalIdentityPresenceBatchPayload(request),
		) {
		return protocol.GlobalIdentityPresenceBatchRequest{}, "", false,
			inconsistentMessage(
				"global identity presence completion %s has an invalid signed chunk payload",
				batchID,
			)
	}
	return request, aggregatePayloadHash, true, nil
}

func (sqliteStore *Store) verifyGlobalIdentitySnapshots(
	ctx context.Context,
	events map[int64]store.GlobalIdentityEvent,
	registryScope string,
) error {
	rows, err := sqliteStore.db.QueryContext(ctx, `
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
		ORDER BY period, revision`)
	if err != nil {
		return inconsistent("read global identity dedup snapshots", err)
	}
	defer rows.Close()
	revisions := make(map[string]int64)
	seenEvents := make(map[int64]bool)
	for rows.Next() {
		snapshot, err := scanGlobalIdentitySnapshot(rows)
		if err != nil {
			return inconsistent("scan global identity dedup snapshot", err)
		}
		event, ok := events[snapshot.ThroughEventIndex]
		if !ok ||
			seenEvents[snapshot.ThroughEventIndex] ||
			snapshot.Revision != revisions[snapshot.Period]+1 ||
			snapshot.Period != event.Period ||
			snapshot.RegistryScope != "" ||
			snapshot.ThroughEventHash != event.EventHash ||
			snapshot.GeneratedAt != event.AcceptedAt ||
			snapshot.ReportedQMAUCount != event.ReportedCount ||
			snapshot.DeduplicatedNetworkQMAU !=
				event.DeduplicatedCount ||
			snapshot.DeduplicatedNetworkQMAU !=
				snapshot.GloballyUniqueLinkedCount+
					snapshot.UnlinkedQMAUCount ||
			snapshot.DuplicateReduction !=
				snapshot.ReportedQMAUCount-
					snapshot.DeduplicatedNetworkQMAU {
			return inconsistentMessage(
				"global identity snapshot %s revision %d is inconsistent",
				snapshot.Period,
				snapshot.Revision,
			)
		}
		expected := protocol.Digest(
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
				event.PrivateEventHash,
			),
		)
		if snapshot.AggregateCommitment != expected ||
			event.AggregateCommitment != expected ||
			event.RegistryScope != registryScope {
			return inconsistentMessage(
				"global identity snapshot %s revision %d has an invalid aggregate commitment",
				snapshot.Period,
				snapshot.Revision,
			)
		}
		revisions[snapshot.Period] = snapshot.Revision
		seenEvents[snapshot.ThroughEventIndex] = true
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate global identity dedup snapshots", err)
	}
	if len(events) != len(seenEvents) {
		return inconsistentMessage(
			"every global identity event must have exactly one dedup snapshot",
		)
	}
	return nil
}

func (sqliteStore *Store) verifyGlobalIdentityDirectRows(
	ctx context.Context,
) error {
	type aliasKey struct {
		version    int64
		commitment string
	}
	type replayedLink struct {
		globalIdentityID          string
		status                    string
		keyVersion                int64
		suite                     string
		commitment                string
		consentVersion            string
		consentEvidenceCommitment string
		verifiedAt                string
		activeFromPeriod          string
		inactiveFromPeriod        string
	}

	aliases := make(map[aliasKey]string)
	createdIdentities := make(map[string]string)
	links := make(map[string]replayedLink)
	historyRows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			e.action,
			e.period,
			e.accepted_at,
			h.link_id,
			h.global_identity_id,
			h.status,
			h.key_version,
			h.suite,
			h.network_identity_commitment,
			h.consent_version,
			h.consent_evidence_commitment,
			h.verified_at,
			h.active_from_period,
			h.inactive_from_period
		FROM global_identity_events e
		JOIN global_identity_link_history h
		  ON h.event_index = e.event_index
		WHERE e.action IN (?, ?, ?)
		ORDER BY e.event_index`,
		protocol.GlobalIdentityActionLink,
		protocol.GlobalIdentityActionUnlink,
		protocol.GlobalIdentityActionCorrect,
	)
	if err != nil {
		return inconsistent("read global identity history for replay", err)
	}
	defer historyRows.Close()
	for historyRows.Next() {
		var action, period, acceptedAt, linkID string
		var history replayedLink
		if err := historyRows.Scan(
			&action,
			&period,
			&acceptedAt,
			&linkID,
			&history.globalIdentityID,
			&history.status,
			&history.keyVersion,
			&history.suite,
			&history.commitment,
			&history.consentVersion,
			&history.consentEvidenceCommitment,
			&history.verifiedAt,
			&history.activeFromPeriod,
			&history.inactiveFromPeriod,
		); err != nil {
			return inconsistent("scan global identity history for replay", err)
		}
		key := aliasKey{
			version:    history.keyVersion,
			commitment: history.commitment,
		}
		previous, existed := links[linkID]
		switch action {
		case protocol.GlobalIdentityActionLink:
			if existed ||
				history.status != protocol.GlobalIdentityLinkActive ||
				history.activeFromPeriod != period ||
				history.inactiveFromPeriod != "" {
				return inconsistentMessage(
					"global identity link %s has an invalid creation transition",
					linkID,
				)
			}
			globalID, aliasExists := aliases[key]
			if !aliasExists {
				globalID = history.globalIdentityID
				aliases[key] = globalID
				if priorCreatedAt, duplicateID :=
					createdIdentities[globalID]; duplicateID &&
					priorCreatedAt != acceptedAt {
					return inconsistentMessage(
						"global identity %s has multiple creation points",
						globalID,
					)
				}
				createdIdentities[globalID] = acceptedAt
			}
			if history.globalIdentityID != globalID {
				return inconsistentMessage(
					"global identity link %s conflicts with the replayed alias map",
					linkID,
				)
			}
		case protocol.GlobalIdentityActionUnlink:
			if !existed ||
				previous.status != protocol.GlobalIdentityLinkActive ||
				history.status != protocol.GlobalIdentityLinkUnlinked ||
				history.globalIdentityID != previous.globalIdentityID ||
				history.keyVersion != previous.keyVersion ||
				history.suite != previous.suite ||
				history.commitment != previous.commitment ||
				history.consentVersion != previous.consentVersion ||
				history.consentEvidenceCommitment !=
					previous.consentEvidenceCommitment ||
				history.verifiedAt != previous.verifiedAt ||
				history.activeFromPeriod != previous.activeFromPeriod ||
				history.inactiveFromPeriod != period {
				return inconsistentMessage(
					"global identity link %s has an invalid unlink transition",
					linkID,
				)
			}
		case protocol.GlobalIdentityActionCorrect:
			if !existed ||
				previous.status != protocol.GlobalIdentityLinkActive ||
				history.status != protocol.GlobalIdentityLinkActive ||
				history.activeFromPeriod != previous.activeFromPeriod ||
				history.inactiveFromPeriod != "" {
				return inconsistentMessage(
					"global identity link %s has an invalid correction transition",
					linkID,
				)
			}
			sourceKey := aliasKey{
				version:    previous.keyVersion,
				commitment: previous.commitment,
			}
			sourceGlobalID, sourceExists := aliases[sourceKey]
			if !sourceExists {
				return inconsistentMessage(
					"global identity link %s correction has no replayed source alias",
					linkID,
				)
			}
			targetGlobalID, targetExists := aliases[key]
			if !targetExists {
				targetGlobalID = sourceGlobalID
				aliases[key] = targetGlobalID
			}
			if history.globalIdentityID != targetGlobalID {
				return inconsistentMessage(
					"global identity link %s correction conflicts with the replayed alias map",
					linkID,
				)
			}
			if targetGlobalID != sourceGlobalID {
				for replayKey, globalID := range aliases {
					if globalID == sourceGlobalID {
						aliases[replayKey] = targetGlobalID
					}
				}
			}
		default:
			return inconsistentMessage(
				"global identity link %s has an unsupported history action",
				linkID,
			)
		}
		links[linkID] = history
	}
	if err := historyRows.Err(); err != nil {
		return inconsistent("iterate global identity history for replay", err)
	}
	if err := historyRows.Close(); err != nil {
		return inconsistent("close global identity history replay", err)
	}
	var linkEventCount, historyCount int64
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*)
			 FROM global_identity_events
			 WHERE action IN (?, ?, ?)),
			(SELECT COUNT(*) FROM global_identity_link_history)`,
		protocol.GlobalIdentityActionLink,
		protocol.GlobalIdentityActionUnlink,
		protocol.GlobalIdentityActionCorrect,
	).Scan(&linkEventCount, &historyCount); err != nil {
		return inconsistent("count global identity link audit rows", err)
	}
	if linkEventCount != historyCount {
		return inconsistentMessage(
			"global identity link events and immutable history differ",
		)
	}

	var inconsistentLinks int64
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM global_identity_links l
		WHERE NOT EXISTS (
			SELECT 1
			FROM global_identity_link_history h
			WHERE h.link_id = l.link_id
			  AND h.event_index = l.latest_event_index
			  AND h.deployment_id = l.deployment_id
			  AND h.global_identity_id = l.global_identity_id
			  AND h.status = l.status
			  AND h.key_version = l.key_version
			  AND h.suite = l.suite
			  AND h.network_identity_commitment =
			      l.network_identity_commitment
			  AND h.consent_version = l.consent_version
			  AND h.consent_evidence_commitment =
			      l.consent_evidence_commitment
				  AND h.verified_at = l.verified_at
				  AND h.active_from_period = l.active_from_period
				  AND h.inactive_from_period = l.inactive_from_period
				  AND EXISTS (
				      SELECT 1
				      FROM global_identity_events e
				      WHERE e.event_index = l.latest_event_index
				        AND e.event_hash = l.latest_event_hash
				  )
		)`).Scan(&inconsistentLinks); err != nil {
		return inconsistent("verify global identity direct links", err)
	}
	if inconsistentLinks != 0 {
		return inconsistentMessage(
			"global identity current links differ from immutable history",
		)
	}
	var persistedLinkCount int
	if err := sqliteStore.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM global_identity_links`,
	).Scan(&persistedLinkCount); err != nil {
		return inconsistent("count global identity direct links", err)
	}
	if persistedLinkCount != len(links) {
		return inconsistentMessage(
			"global identity direct link count differs from immutable history replay",
		)
	}
	aliasRows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			key_version,
			network_identity_commitment,
			global_identity_id
		FROM global_identity_aliases`)
	if err != nil {
		return inconsistent("read global identity direct aliases", err)
	}
	defer aliasRows.Close()
	persistedAliasCount := 0
	for aliasRows.Next() {
		var key aliasKey
		var globalID string
		if err := aliasRows.Scan(
			&key.version,
			&key.commitment,
			&globalID,
		); err != nil {
			return inconsistent("scan global identity direct alias", err)
		}
		expectedGlobalID, ok := aliases[key]
		if !ok || expectedGlobalID != globalID {
			return inconsistentMessage(
				"global identity direct alias differs from immutable history replay",
			)
		}
		persistedAliasCount++
	}
	if err := aliasRows.Err(); err != nil {
		return inconsistent("iterate global identity direct aliases", err)
	}
	if err := aliasRows.Close(); err != nil {
		return inconsistent("close global identity direct aliases", err)
	}
	if persistedAliasCount != len(aliases) {
		return inconsistentMessage(
			"global identity direct alias count differs from immutable history replay",
		)
	}

	identityRows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT global_identity_id, created_at
		FROM global_identities`)
	if err != nil {
		return inconsistent("read opaque global identities", err)
	}
	defer identityRows.Close()
	persistedIdentityCount := 0
	for identityRows.Next() {
		var globalID, createdAt string
		if err := identityRows.Scan(&globalID, &createdAt); err != nil {
			return inconsistent("scan opaque global identity", err)
		}
		expectedCreatedAt, ok := createdIdentities[globalID]
		if !ok || expectedCreatedAt != createdAt {
			return inconsistentMessage(
				"opaque global identity differs from immutable history replay",
			)
		}
		persistedIdentityCount++
	}
	if err := identityRows.Err(); err != nil {
		return inconsistent("iterate opaque global identities", err)
	}
	if persistedIdentityCount != len(createdIdentities) {
		return inconsistentMessage(
			"opaque global identity count differs from immutable history replay",
		)
	}
	return nil
}

func (sqliteStore *Store) verifyGlobalIdentityBoundary(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	if err := sqliteStore.verifyGlobalIdentityKeys(ctx); err != nil {
		return err
	}
	var count int64
	if err := sqliteStore.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM global_identity_events`,
	).Scan(&count); err != nil {
		return inconsistent("read global identity boundary count", err)
	}
	events := make(map[int64]store.GlobalIdentityEvent)
	if count > 0 {
		verifiedEvents, err := sqliteStore.verifyGlobalIdentityEvents(
			ctx,
			registryPublicKey,
			registryKeyID,
			registryScope,
		)
		if err != nil {
			return err
		}
		events = verifiedEvents
		if int64(len(events)) != count {
			return inconsistentMessage(
				"global identity boundary event count is inconsistent",
			)
		}
	}
	if err := sqliteStore.verifyGlobalIdentityPresenceChunks(
		ctx,
		registryPublicKey,
		registryKeyID,
		registryScope,
		events,
	); err != nil {
		return err
	}
	if err := sqliteStore.verifyGlobalIdentitySnapshots(
		ctx,
		events,
		registryScope,
	); err != nil {
		return err
	}
	return sqliteStore.verifyGlobalIdentityDirectRows(ctx)
}

func (sqliteStore *Store) globalIdentityDeploymentKey(
	ctx context.Context,
	deploymentID string,
) (ed25519.PublicKey, error) {
	var der []byte
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT public_key_der
		FROM deployments
		WHERE deployment_id = ?`,
		deploymentID,
	).Scan(&der); err != nil {
		return nil, inconsistent(
			"read global identity deployment public key",
			err,
		)
	}
	key, err := globalIdentityDeploymentKey(der)
	if err != nil {
		return nil, inconsistent(
			"parse global identity deployment public key",
			err,
		)
	}
	return key, nil
}

func globalIdentityDeploymentKey(
	der []byte,
) (ed25519.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("deployment key is not Ed25519")
	}
	return publicKey, nil
}

func globalIdentityActionPath(action string) string {
	switch action {
	case protocol.GlobalIdentityActionLink:
		return protocol.GlobalIdentityLinkPath
	case protocol.GlobalIdentityActionUnlink,
		protocol.GlobalIdentityActionCorrect:
		return protocol.GlobalIdentityLinkActionPath
	case protocol.GlobalIdentityActionPresence:
		return protocol.GlobalIdentityPresenceBatchPath
	default:
		return ""
	}
}
