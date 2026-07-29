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

const globalIdentityEventSelect = `
	SELECT
		event_index,
		event_id,
		action,
		deployment_id,
		period,
		aggregate_commitment,
		reported_count,
		deduplicated_count,
		accepted_at,
		previous_event_hash,
		event_hash,
		registry_scope,
		registry_key_id,
		receipt_signature,
		idempotency_key,
		request_nonce,
		request_timestamp,
		request_hash,
		payload_hash,
		request_signature,
		private_event_hash,
		subject_id
	FROM global_identity_events`

const globalIdentityLinkSelect = `
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
		latest_event_index,
		latest_event_hash
	FROM global_identity_links`

func (sqliteStore *Store) ApplyGlobalIdentityMutation(
	ctx context.Context,
	input store.GlobalIdentityMutationInput,
	signEvent store.GlobalIdentityEventSigner,
) (store.GlobalIdentityLink, store.GlobalIdentityEvent, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false,
			fmt.Errorf("begin global identity mutation: %w", err)
	}
	defer tx.Rollback()

	existing, err := globalIdentityEventByIdempotency(
		ctx,
		tx,
		input.DeploymentID,
		input.IdempotencyKey,
	)
	if err == nil {
		if existing.PayloadHash != input.PayloadHash ||
			existing.Action != input.Action {
			return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false,
				store.ErrIdempotencyConflict
		}
		link, linkErr := globalIdentityLinkHistoryAtEvent(
			ctx,
			tx,
			existing.EventIndex,
		)
		if linkErr != nil {
			return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false,
				linkErr
		}
		if err := tx.Commit(); err != nil {
			return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false,
				fmt.Errorf("commit duplicate global identity mutation: %w", err)
		}
		return link, existing, true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false, err
	}
	if err := ensureGlobalIdentityNonceAvailable(
		ctx,
		tx,
		input.DeploymentID,
		input.Nonce,
		input.RequestHash,
	); err != nil {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false, err
	}
	active, err := operatorDeploymentActiveTx(ctx, tx, input.DeploymentID)
	if err != nil {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false, err
	}
	if !active {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false,
			store.ErrDeploymentInactive
	}
	if err := ensureAcceptedAtAfterRegistryCreation(
		ctx,
		tx,
		input.AcceptedAt,
	); err != nil {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false, err
	}
	head, err := globalIdentityEventHead(ctx, tx)
	if err != nil {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false, err
	}
	if err := ensureGlobalIdentityAcceptedAt(
		input.AcceptedAt,
		head.AcceptedAt,
	); err != nil {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false, err
	}

	event := store.GlobalIdentityEvent{
		EventIndex:          head.EventIndex + 1,
		EventID:             input.CandidateEventID,
		Action:              input.Action,
		DeploymentID:        input.DeploymentID,
		Period:              input.EffectivePeriod,
		ReportedCount:       0,
		DeduplicatedCount:   0,
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
	}

	var link store.GlobalIdentityLink
	switch input.Action {
	case protocol.GlobalIdentityActionLink:
		event.SubjectID = input.CandidateLinkID
		link, err = prepareGlobalIdentityLink(ctx, tx, input)
	case protocol.GlobalIdentityActionUnlink:
		event.SubjectID = input.LinkID
		link, err = prepareGlobalIdentityUnlink(ctx, tx, input)
	case protocol.GlobalIdentityActionCorrect:
		event.SubjectID = input.LinkID
		link, err = prepareGlobalIdentityCorrection(ctx, tx, input)
	default:
		err = store.ErrGlobalIdentityLinkConflict
	}
	if err != nil {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false, err
	}
	snapshot, err := calculateGlobalIdentitySnapshot(
		ctx,
		tx,
		input.EffectivePeriod,
		event.EventIndex,
		input.PrivateEventHash,
		nil,
	)
	if err != nil {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false, err
	}
	snapshot.RegistryScope = input.RegistryScope
	event.AggregateCommitment = snapshot.AggregateCommitment
	event.ReportedCount = snapshot.ReportedQMAUCount
	event.DeduplicatedCount = snapshot.DeduplicatedNetworkQMAU

	event.EventHash = protocol.Digest(
		protocol.GlobalIdentityEventHashMessage(
			globalIdentityProtocolEvent(event),
		),
	)
	event.ReceiptSignature, err = signEvent(event)
	if err != nil {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false,
			fmt.Errorf("sign global identity event: %w", err)
	}
	if err := insertGlobalIdentityEvent(ctx, tx, event); err != nil {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false, err
	}
	link.LatestEventIndex = event.EventIndex
	link.LatestEventHash = event.EventHash
	if err := persistGlobalIdentityLinkMutation(ctx, tx, input.Action, link); err != nil {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false, err
	}
	if err := insertGlobalIdentityLinkHistory(
		ctx,
		tx,
		event,
		link,
		input.ReasonCommitment,
	); err != nil {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false, err
	}
	snapshot.ThroughEventHash = event.EventHash
	snapshot.GeneratedAt = event.AcceptedAt
	if err := insertGlobalIdentitySnapshot(ctx, tx, snapshot); err != nil {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return store.GlobalIdentityLink{}, store.GlobalIdentityEvent{}, false,
			fmt.Errorf("commit global identity mutation: %w", err)
	}
	return link, event, false, nil
}

func prepareGlobalIdentityLink(
	ctx context.Context,
	tx *sql.Tx,
	input store.GlobalIdentityMutationInput,
) (store.GlobalIdentityLink, error) {
	if _, err := globalIdentityVOPRFKeyTx(
		ctx,
		tx,
		input.KeyVersion,
		input.Suite,
	); err != nil {
		return store.GlobalIdentityLink{}, err
	}
	globalID, err := globalIdentityAliasTx(
		ctx,
		tx,
		input.KeyVersion,
		input.NetworkIdentityCommitment,
	)
	if errors.Is(err, store.ErrNotFound) {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO global_identities (
				global_identity_id, created_at
			) VALUES (?, ?)`,
			input.CandidateGlobalIdentityID,
			input.AcceptedAt,
		); err != nil {
			return store.GlobalIdentityLink{},
				fmt.Errorf("create opaque global identity: %w", err)
		}
		globalID = input.CandidateGlobalIdentityID
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO global_identity_aliases (
				key_version,
				network_identity_commitment,
				global_identity_id,
				created_at
			) VALUES (?, ?, ?, ?)`,
			input.KeyVersion,
			input.NetworkIdentityCommitment,
			globalID,
			input.AcceptedAt,
		); err != nil {
			return store.GlobalIdentityLink{},
				fmt.Errorf("persist global identity alias: %w", err)
		}
	} else if err != nil {
		return store.GlobalIdentityLink{}, err
	}
	return store.GlobalIdentityLink{
		LinkID:                    input.CandidateLinkID,
		DeploymentID:              input.DeploymentID,
		GlobalIdentityID:          globalID,
		Status:                    protocol.GlobalIdentityLinkActive,
		KeyVersion:                input.KeyVersion,
		Suite:                     input.Suite,
		NetworkIdentityCommitment: input.NetworkIdentityCommitment,
		ConsentVersion:            input.ConsentVersion,
		ConsentEvidenceCommitment: input.ConsentEvidenceCommitment,
		VerifiedAt:                input.VerifiedAt,
		ActiveFromPeriod:          input.EffectivePeriod,
	}, nil
}

func prepareGlobalIdentityUnlink(
	ctx context.Context,
	tx *sql.Tx,
	input store.GlobalIdentityMutationInput,
) (store.GlobalIdentityLink, error) {
	link, err := globalIdentityLinkByID(ctx, tx, input.LinkID)
	if err != nil {
		return store.GlobalIdentityLink{}, err
	}
	if link.DeploymentID != input.DeploymentID ||
		link.Status != protocol.GlobalIdentityLinkActive ||
		input.EffectivePeriod < link.ActiveFromPeriod {
		return store.GlobalIdentityLink{}, store.ErrGlobalIdentityLinkConflict
	}
	link.Status = protocol.GlobalIdentityLinkUnlinked
	link.InactiveFromPeriod = input.EffectivePeriod
	return link, nil
}

func prepareGlobalIdentityCorrection(
	ctx context.Context,
	tx *sql.Tx,
	input store.GlobalIdentityMutationInput,
) (store.GlobalIdentityLink, error) {
	link, err := globalIdentityLinkByID(ctx, tx, input.LinkID)
	if err != nil {
		return store.GlobalIdentityLink{}, err
	}
	if link.DeploymentID != input.DeploymentID ||
		link.Status != protocol.GlobalIdentityLinkActive ||
		input.EffectivePeriod < link.ActiveFromPeriod {
		return store.GlobalIdentityLink{}, store.ErrGlobalIdentityLinkConflict
	}
	if _, err := globalIdentityVOPRFKeyTx(
		ctx,
		tx,
		input.KeyVersion,
		input.Suite,
	); err != nil {
		return store.GlobalIdentityLink{}, err
	}
	targetGlobalID, err := globalIdentityAliasTx(
		ctx,
		tx,
		input.KeyVersion,
		input.NetworkIdentityCommitment,
	)
	if errors.Is(err, store.ErrNotFound) {
		targetGlobalID = link.GlobalIdentityID
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO global_identity_aliases (
				key_version,
				network_identity_commitment,
				global_identity_id,
				created_at
			) VALUES (?, ?, ?, ?)`,
			input.KeyVersion,
			input.NetworkIdentityCommitment,
			targetGlobalID,
			input.AcceptedAt,
		); err != nil {
			return store.GlobalIdentityLink{},
				fmt.Errorf("persist corrected global identity alias: %w", err)
		}
	} else if err != nil {
		return store.GlobalIdentityLink{}, err
	}
	if targetGlobalID != link.GlobalIdentityID {
		if _, err := tx.ExecContext(ctx, `
			UPDATE global_identity_aliases
			SET global_identity_id = ?
			WHERE global_identity_id = ?`,
			targetGlobalID,
			link.GlobalIdentityID,
		); err != nil {
			return store.GlobalIdentityLink{},
				fmt.Errorf("merge global identity aliases: %w", err)
		}
	}
	link.GlobalIdentityID = targetGlobalID
	link.KeyVersion = input.KeyVersion
	link.Suite = input.Suite
	link.NetworkIdentityCommitment = input.NetworkIdentityCommitment
	link.ConsentVersion = input.ConsentVersion
	link.ConsentEvidenceCommitment = input.ConsentEvidenceCommitment
	link.VerifiedAt = input.VerifiedAt
	return link, nil
}

func persistGlobalIdentityLinkMutation(
	ctx context.Context,
	tx *sql.Tx,
	action string,
	link store.GlobalIdentityLink,
) error {
	if action == protocol.GlobalIdentityActionLink {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO global_identity_links (
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
				latest_event_index,
				latest_event_hash
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			link.LinkID,
			link.DeploymentID,
			link.GlobalIdentityID,
			link.Status,
			link.KeyVersion,
			link.Suite,
			link.NetworkIdentityCommitment,
			link.ConsentVersion,
			link.ConsentEvidenceCommitment,
			link.VerifiedAt,
			link.ActiveFromPeriod,
			link.InactiveFromPeriod,
			link.LatestEventIndex,
			link.LatestEventHash,
		); err != nil {
			return fmt.Errorf("persist global identity link: %w", err)
		}
		return nil
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE global_identity_links
		SET global_identity_id = ?,
		    status = ?,
		    key_version = ?,
		    suite = ?,
		    network_identity_commitment = ?,
		    consent_version = ?,
		    consent_evidence_commitment = ?,
		    verified_at = ?,
		    inactive_from_period = ?,
		    latest_event_index = ?,
		    latest_event_hash = ?
		WHERE link_id = ? AND deployment_id = ?`,
		link.GlobalIdentityID,
		link.Status,
		link.KeyVersion,
		link.Suite,
		link.NetworkIdentityCommitment,
		link.ConsentVersion,
		link.ConsentEvidenceCommitment,
		link.VerifiedAt,
		link.InactiveFromPeriod,
		link.LatestEventIndex,
		link.LatestEventHash,
		link.LinkID,
		link.DeploymentID,
	)
	if err != nil {
		return fmt.Errorf("update global identity direct link: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		return store.ErrGlobalIdentityLinkConflict
	}
	return nil
}

func insertGlobalIdentityEvent(
	ctx context.Context,
	tx *sql.Tx,
	event store.GlobalIdentityEvent,
) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO global_identity_events (
			event_index,
			event_id,
			action,
			deployment_id,
			period,
			aggregate_commitment,
			reported_count,
			deduplicated_count,
			accepted_at,
			previous_event_hash,
			event_hash,
			registry_scope,
			registry_key_id,
			receipt_signature,
			idempotency_key,
			request_nonce,
			request_timestamp,
			request_hash,
			payload_hash,
			request_signature,
			private_event_hash,
			subject_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.EventIndex,
		event.EventID,
		event.Action,
		event.DeploymentID,
		event.Period,
		event.AggregateCommitment,
		event.ReportedCount,
		event.DeduplicatedCount,
		event.AcceptedAt,
		event.PreviousEventHash,
		event.EventHash,
		event.RegistryScope,
		event.RegistryKeyID,
		event.ReceiptSignature,
		event.IdempotencyKey,
		event.RequestNonce,
		event.RequestTimestamp,
		event.RequestHash,
		event.PayloadHash,
		event.RequestSignature,
		event.PrivateEventHash,
		event.SubjectID,
	); err != nil {
		return fmt.Errorf("append global identity event: %w", err)
	}
	return nil
}

func insertGlobalIdentityLinkHistory(
	ctx context.Context,
	tx *sql.Tx,
	event store.GlobalIdentityEvent,
	link store.GlobalIdentityLink,
	reasonCommitment string,
) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO global_identity_link_history (
			event_index,
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
			reason_commitment,
			private_event_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.EventIndex,
		link.LinkID,
		link.DeploymentID,
		link.GlobalIdentityID,
		link.Status,
		link.KeyVersion,
		link.Suite,
		link.NetworkIdentityCommitment,
		link.ConsentVersion,
		link.ConsentEvidenceCommitment,
		link.VerifiedAt,
		link.ActiveFromPeriod,
		link.InactiveFromPeriod,
		reasonCommitment,
		event.PrivateEventHash,
	); err != nil {
		return fmt.Errorf("append global identity link history: %w", err)
	}
	return nil
}

func ensureGlobalIdentityNonceAvailable(
	ctx context.Context,
	tx *sql.Tx,
	deploymentID string,
	nonce string,
	requestHash string,
) error {
	var persisted string
	err := tx.QueryRowContext(ctx, `
		SELECT request_hash
		FROM global_identity_events
		WHERE deployment_id = ? AND request_nonce = ?`,
		deploymentID,
		nonce,
	).Scan(&persisted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read global identity event nonce: %w", err)
	}
	if persisted != requestHash {
		return store.ErrReplayConflict
	}
	return store.ErrInconsistentState
}

func globalIdentityEventByIdempotency(
	ctx context.Context,
	queryer queryRower,
	deploymentID string,
	idempotencyKey string,
) (store.GlobalIdentityEvent, error) {
	return scanGlobalIdentityEvent(queryer.QueryRowContext(
		ctx,
		globalIdentityEventSelect+
			" WHERE deployment_id = ? AND idempotency_key = ?",
		deploymentID,
		idempotencyKey,
	))
}

func globalIdentityEventHead(
	ctx context.Context,
	queryer queryRower,
) (store.GlobalIdentityEvent, error) {
	event, err := scanGlobalIdentityEvent(queryer.QueryRowContext(
		ctx,
		globalIdentityEventSelect+" ORDER BY event_index DESC LIMIT 1",
	))
	if errors.Is(err, store.ErrNotFound) {
		return store.GlobalIdentityEvent{
			PreviousEventHash: protocol.ZeroHash,
			EventHash:         protocol.ZeroHash,
		}, nil
	}
	return event, err
}

func scanGlobalIdentityEvent(
	scanner rowScanner,
) (store.GlobalIdentityEvent, error) {
	var event store.GlobalIdentityEvent
	if err := scanner.Scan(
		&event.EventIndex,
		&event.EventID,
		&event.Action,
		&event.DeploymentID,
		&event.Period,
		&event.AggregateCommitment,
		&event.ReportedCount,
		&event.DeduplicatedCount,
		&event.AcceptedAt,
		&event.PreviousEventHash,
		&event.EventHash,
		&event.RegistryScope,
		&event.RegistryKeyID,
		&event.ReceiptSignature,
		&event.IdempotencyKey,
		&event.RequestNonce,
		&event.RequestTimestamp,
		&event.RequestHash,
		&event.PayloadHash,
		&event.RequestSignature,
		&event.PrivateEventHash,
		&event.SubjectID,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.GlobalIdentityEvent{}, store.ErrNotFound
		}
		return store.GlobalIdentityEvent{},
			fmt.Errorf("scan global identity event: %w", err)
	}
	return event, nil
}

func globalIdentityLinkByID(
	ctx context.Context,
	queryer queryRower,
	linkID string,
) (store.GlobalIdentityLink, error) {
	return scanGlobalIdentityLink(queryer.QueryRowContext(
		ctx,
		globalIdentityLinkSelect+" WHERE link_id = ?",
		linkID,
	))
}

func globalIdentityLinkHistoryAtEvent(
	ctx context.Context,
	queryer queryRower,
	eventIndex int64,
) (store.GlobalIdentityLink, error) {
	var link store.GlobalIdentityLink
	if err := queryer.QueryRowContext(ctx, `
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
			(SELECT event_hash FROM global_identity_events WHERE event_index = ?)
		FROM global_identity_link_history
		WHERE event_index = ?`,
		eventIndex,
		eventIndex,
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
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.GlobalIdentityLink{}, store.ErrNotFound
		}
		return store.GlobalIdentityLink{},
			fmt.Errorf("read global identity link history: %w", err)
	}
	return link, nil
}

func scanGlobalIdentityLink(
	scanner rowScanner,
) (store.GlobalIdentityLink, error) {
	var link store.GlobalIdentityLink
	if err := scanner.Scan(
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
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.GlobalIdentityLink{}, store.ErrNotFound
		}
		return store.GlobalIdentityLink{},
			fmt.Errorf("scan global identity link: %w", err)
	}
	return link, nil
}

func globalIdentityAliasTx(
	ctx context.Context,
	tx *sql.Tx,
	keyVersion int64,
	commitment string,
) (string, error) {
	var globalID string
	if err := tx.QueryRowContext(ctx, `
		SELECT global_identity_id
		FROM global_identity_aliases
		WHERE key_version = ? AND network_identity_commitment = ?`,
		keyVersion,
		commitment,
	).Scan(&globalID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", store.ErrNotFound
		}
		return "", fmt.Errorf("read global identity alias: %w", err)
	}
	return globalID, nil
}

func globalIdentityVOPRFKeyTx(
	ctx context.Context,
	tx *sql.Tx,
	keyVersion int64,
	suite string,
) ([]byte, error) {
	var publicKey []byte
	var persistedSuite string
	if err := tx.QueryRowContext(ctx, `
		SELECT suite, public_key
		FROM global_identity_voprf_keys
		WHERE key_version = ?`,
		keyVersion,
	).Scan(&persistedSuite, &publicKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("read global identity VOPRF key: %w", err)
	}
	if persistedSuite != suite {
		return nil, store.ErrGlobalIdentityKeyMismatch
	}
	return publicKey, nil
}

func ensureGlobalIdentityAcceptedAt(acceptedAt, headAt string) error {
	if headAt == "" {
		return nil
	}
	accepted, acceptedErr := time.Parse(time.RFC3339Nano, acceptedAt)
	head, headErr := time.Parse(time.RFC3339Nano, headAt)
	if acceptedErr != nil || headErr != nil || accepted.Before(head) {
		return store.ErrAcceptedAtBeforeHead
	}
	return nil
}

func globalIdentityProtocolEvent(
	event store.GlobalIdentityEvent,
) protocol.GlobalIdentityEvent {
	return protocol.GlobalIdentityEvent{
		EventIndex:          event.EventIndex,
		EventID:             event.EventID,
		Action:              event.Action,
		DeploymentID:        event.DeploymentID,
		Period:              event.Period,
		AggregateCommitment: event.AggregateCommitment,
		ReportedCount:       event.ReportedCount,
		DeduplicatedCount:   event.DeduplicatedCount,
		AcceptedAt:          event.AcceptedAt,
		PreviousEventHash:   event.PreviousEventHash,
		EventHash:           event.EventHash,
		RegistryScope:       event.RegistryScope,
		RegistryKeyID:       event.RegistryKeyID,
		Signature:           protocol.EncodeSignature(event.ReceiptSignature),
	}
}
