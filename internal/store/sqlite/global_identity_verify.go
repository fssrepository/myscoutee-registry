package sqlite

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"

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
			d.public_key_der
		FROM global_identity_evaluations e
		JOIN deployments d ON d.deployment_id = e.deployment_id
		ORDER BY e.evaluated_at, e.evaluation_id`)
	if err != nil {
		return inconsistent("read global identity evaluations", err)
	}
	defer rows.Close()
	for rows.Next() {
		var record store.GlobalIdentityEvaluationRecord
		var deploymentDER []byte
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
		globalIdentityEventSelect+" ORDER BY event_index",
	)
	if err != nil {
		return nil, inconsistent("read global identity events", err)
	}
	defer rows.Close()
	events := make(map[int64]store.GlobalIdentityEvent)
	var previousHash = protocol.ZeroHash
	var previousAcceptedAt string
	var expectedIndex int64 = 1
	for rows.Next() {
		event, err := scanGlobalIdentityEvent(rows)
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
	if err := rows.Err(); err != nil {
		return nil, inconsistent("iterate global identity events", err)
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
		if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT
				batch_id,
				period,
				revision,
				supersedes_batch_id,
				reported_qmau_count,
				key_version,
				suite
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
		); err != nil {
			return nil, "", inconsistent(
				"read global identity presence event source",
				err,
			)
		}
		if batchID != event.SubjectID {
			return nil, "", inconsistentMessage(
				"global identity presence batch does not match event %d",
				event.EventIndex,
			)
		}
		itemRows, err := sqliteStore.db.QueryContext(ctx, `
			SELECT network_identity_commitment
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
		for itemRows.Next() {
			var commitment string
			if err := itemRows.Scan(&commitment); err != nil {
				itemRows.Close()
				return nil, "", inconsistent(
					"scan global identity presence item",
					err,
				)
			}
			request.Commitments = append(request.Commitments, commitment)
		}
		if err := itemRows.Err(); err != nil {
			itemRows.Close()
			return nil, "", inconsistent(
				"iterate global identity presence items",
				err,
			)
		}
		itemRows.Close()
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
				event.PayloadHash,
			),
		)
		return protocol.GlobalIdentityPresenceBatchPayload(request),
			privateHash,
			nil
	default:
		return nil, "", inconsistentMessage(
			"global identity event %d has unsupported action",
			event.EventIndex,
		)
	}
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
		)`).Scan(&inconsistentLinks); err != nil {
		return inconsistent("verify global identity direct links", err)
	}
	if inconsistentLinks != 0 {
		return inconsistentMessage(
			"global identity current links differ from immutable history",
		)
	}
	var inconsistentAliases int64
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM global_identity_aliases a
		WHERE NOT EXISTS (
			SELECT 1
			FROM global_identity_links l
			WHERE l.key_version = a.key_version
			  AND l.network_identity_commitment =
			      a.network_identity_commitment
		)`).Scan(&inconsistentAliases); err != nil {
		return inconsistent("verify global identity aliases", err)
	}
	if inconsistentAliases != 0 {
		return inconsistentMessage(
			"global identity alias has no matching audited direct link",
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
	var count int64
	if err := sqliteStore.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM global_identity_events`,
	).Scan(&count); err != nil {
		return inconsistent("read global identity boundary count", err)
	}
	if count == 0 {
		return nil
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
	if int64(len(events)) != count {
		return inconsistentMessage(
			"global identity boundary event count is inconsistent",
		)
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
