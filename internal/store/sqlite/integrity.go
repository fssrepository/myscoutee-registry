package sqlite

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

type verifiedDeployment struct {
	record    store.Deployment
	publicKey ed25519.PublicKey
}

type verifiedBatch struct {
	record           store.BatchRecord
	requestTimestamp string
	requestNonce     string
	requestSignature []byte
}

type verifiedRevenueBatch struct {
	record           store.RevenueBatchRecord
	requestTimestamp string
	requestNonce     string
	requestSignature []byte
}

type persistedIdempotency struct {
	signer         string
	idempotencyKey string
	payloadHash    string
	resultType     string
	resultID       string
}

type persistedNonceProof struct {
	signer           string
	nonce            string
	requestHash      string
	idempotencyKey   string
	payloadHash      string
	requestTimestamp string
	requestSignature []byte
	resultType       string
	resultID         string
	acceptedAt       string
}

func (sqliteStore *Store) VerifyRecords(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	deployments, err := sqliteStore.verifyDeployments(
		ctx,
		registryPublicKey,
		registryKeyID,
		registryScope,
	)
	if err != nil {
		return err
	}
	batches, err := sqliteStore.verifyBatches(
		ctx,
		deployments,
		registryPublicKey,
		registryKeyID,
		registryScope,
	)
	if err != nil {
		return err
	}
	revenueBatches, err := sqliteStore.verifyRevenueBatches(
		ctx,
		deployments,
		registryPublicKey,
		registryKeyID,
		registryScope,
	)
	if err != nil {
		return err
	}
	if err := sqliteStore.verifyIdempotencyRecords(
		ctx,
		deployments,
		batches,
		revenueBatches,
	); err != nil {
		return err
	}
	if err := sqliteStore.verifyNonceRecords(
		ctx,
		deployments,
		batches,
		revenueBatches,
		registryScope,
	); err != nil {
		return err
	}
	return nil
}

func (sqliteStore *Store) verifyDeployments(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) (map[string]verifiedDeployment, error) {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			deployment_id,
			public_key_der,
			public_key_fingerprint,
			key_algorithm,
			software_version,
			registration_timestamp,
			registration_nonce,
			registration_idempotency_key,
			registration_signature,
			registered_at,
			registration_payload_hash,
			registration_receipt_signature
		FROM deployments
		ORDER BY deployment_id`)
	if err != nil {
		return nil, inconsistent("read deployments for verification", err)
	}
	records := make([]store.Deployment, 0)
	for rows.Next() {
		var deployment store.Deployment
		if err := rows.Scan(
			&deployment.DeploymentID,
			&deployment.PublicKeyDER,
			&deployment.PublicKeyFingerprint,
			&deployment.KeyAlgorithm,
			&deployment.SoftwareVersion,
			&deployment.RegistrationTimestamp,
			&deployment.RegistrationNonce,
			&deployment.RegistrationIdempotencyKey,
			&deployment.RegistrationSignature,
			&deployment.RegisteredAt,
			&deployment.PayloadHash,
			&deployment.ReceiptSignature,
		); err != nil {
			rows.Close()
			return nil, inconsistent("scan deployment for verification", err)
		}
		records = append(records, deployment)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, inconsistent("iterate deployments for verification", err)
	}
	if err := rows.Close(); err != nil {
		return nil, inconsistent("close deployment verification rows", err)
	}

	verified := make(map[string]verifiedDeployment, len(records))
	for _, deployment := range records {
		if !validHexID(deployment.DeploymentID, "dep_", 32) {
			return nil, inconsistentMessage("deployment has malformed ID %q", deployment.DeploymentID)
		}
		encodedKey := base64.StdEncoding.EncodeToString(deployment.PublicKeyDER)
		publicKey, canonicalDER, err := protocol.ParsePublicKey(encodedKey)
		if err != nil || len(canonicalDER) != len(deployment.PublicKeyDER) {
			return nil, inconsistentMessage("deployment %s has an invalid public key", deployment.DeploymentID)
		}
		fingerprint := protocol.PublicKeyFingerprint(canonicalDER)
		if fingerprint != deployment.PublicKeyFingerprint {
			return nil, inconsistentMessage("deployment %s has an invalid public-key fingerprint", deployment.DeploymentID)
		}
		if deployment.KeyAlgorithm != protocol.KeyAlgorithmEd25519 {
			return nil, inconsistentMessage("deployment %s has an invalid key algorithm", deployment.DeploymentID)
		}
		expectedPayloadHash := protocol.Digest(protocol.RegistrationPayload(
			deployment.KeyAlgorithm,
			encodedKey,
			deployment.SoftwareVersion,
		))
		if deployment.PayloadHash != expectedPayloadHash {
			return nil, inconsistentMessage("deployment %s registration payload hash verification failed", deployment.DeploymentID)
		}
		if !validPersistedTimestamp(deployment.RegistrationTimestamp) ||
			!validPersistedTimestamp(deployment.RegisteredAt) {
			return nil, inconsistentMessage("deployment %s has an invalid timestamp", deployment.DeploymentID)
		}
		requestMessage := protocol.CanonicalRequest(
			"POST",
			protocol.RegistrationPath,
			protocol.Version,
			registryScope,
			deployment.PublicKeyFingerprint,
			deployment.RegistrationTimestamp,
			deployment.RegistrationNonce,
			deployment.RegistrationIdempotencyKey,
			deployment.PayloadHash,
		)
		if !ed25519.Verify(publicKey, requestMessage, deployment.RegistrationSignature) {
			return nil, inconsistentMessage("deployment %s registration proof verification failed", deployment.DeploymentID)
		}
		receiptMessage := protocol.RegistrationReceipt(
			protocol.Version,
			registryScope,
			deployment.DeploymentID,
			deployment.PublicKeyFingerprint,
			deployment.RegisteredAt,
			registryKeyID,
		)
		if !ed25519.Verify(registryPublicKey, receiptMessage, deployment.ReceiptSignature) {
			return nil, inconsistentMessage("deployment %s central receipt verification failed", deployment.DeploymentID)
		}
		verified[deployment.DeploymentID] = verifiedDeployment{
			record:    deployment,
			publicKey: publicKey,
		}
	}
	return verified, nil
}

func (sqliteStore *Store) verifyBatches(
	ctx context.Context,
	deployments map[string]verifiedDeployment,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) (map[string]verifiedBatch, error) {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			b.batch_id,
			b.deployment_id,
			b.idempotency_key,
			b.request_timestamp,
			b.request_nonce,
			b.deployment_signature,
			b.kind,
			b.period,
			b.ruleset_version,
			b.qualified_mau_count,
			b.commitment_hash,
			b.revision,
			b.supersedes_batch_id,
			b.payload_hash,
			b.accepted_at,
			b.receipt_signature,
			l.protocol_version,
			l.registry_scope,
			l.ledger_index,
			l.entry_type,
			l.deployment_id,
			l.batch_id,
			l.kind,
			l.period,
			l.ruleset_version,
			l.qualified_mau_count,
			l.batch_hash,
			l.previous_entry_hash,
			l.entry_hash,
			l.accepted_at
		FROM mau_batches b
		JOIN ledger_entries l ON l.ledger_index = b.ledger_index
		ORDER BY l.ledger_index`)
	if err != nil {
		return nil, inconsistent("read batches for verification", err)
	}
	verified := make(map[string]verifiedBatch)
	for rows.Next() {
		var batch verifiedBatch
		var ledgerDeploymentID, ledgerBatchID, ledgerKind, ledgerPeriod string
		var ledgerRuleset, ledgerAcceptedAt string
		entry := protocol.LedgerEntry{}
		if err := rows.Scan(
			&batch.record.BatchID,
			&batch.record.DeploymentID,
			&batch.record.IdempotencyKey,
			&batch.requestTimestamp,
			&batch.requestNonce,
			&batch.requestSignature,
			&batch.record.Kind,
			&batch.record.Period,
			&batch.record.RulesetVersion,
			&batch.record.QualifiedMAUCount,
			&batch.record.CommitmentHash,
			&batch.record.Revision,
			&batch.record.SupersedesBatchID,
			&batch.record.PayloadHash,
			&batch.record.AcceptedAt,
			&batch.record.ReceiptSignature,
			&entry.ProtocolVersion,
			&entry.RegistryScope,
			&entry.LedgerIndex,
			&entry.EntryType,
			&ledgerDeploymentID,
			&ledgerBatchID,
			&ledgerKind,
			&ledgerPeriod,
			&ledgerRuleset,
			&entry.QualifiedMAUCount,
			&entry.BatchHash,
			&entry.PreviousEntryHash,
			&entry.EntryHash,
			&ledgerAcceptedAt,
		); err != nil {
			rows.Close()
			return nil, inconsistent("scan batch for verification", err)
		}
		entry.DeploymentID = ledgerDeploymentID
		entry.BatchID = ledgerBatchID
		entry.Kind = ledgerKind
		entry.Period = ledgerPeriod
		entry.RulesetVersion = ledgerRuleset
		entry.AcceptedAt = ledgerAcceptedAt
		batch.record.LedgerEntry = entry
		verified[batch.record.BatchID] = batch
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, inconsistent("iterate batches for verification", err)
	}
	if err := rows.Close(); err != nil {
		return nil, inconsistent("close batch verification rows", err)
	}

	var ledgerCount int
	if err := sqliteStore.db.QueryRowContext(
		ctx,
		"SELECT COUNT(*) FROM ledger_entries WHERE entry_type IN (?, ?)",
		protocol.InstallationEntryType,
		protocol.QualifiedMAUEntryType,
	).Scan(&ledgerCount); err != nil {
		return nil, inconsistent("count ledger entries for batch verification", err)
	}
	if ledgerCount != len(verified) {
		return nil, inconsistentMessage(
			"ledger/batch cardinality mismatch: %d ledger entries and %d batches",
			ledgerCount,
			len(verified),
		)
	}

	for batchID, batch := range verified {
		record := batch.record
		entry := record.LedgerEntry
		deployment, ok := deployments[record.DeploymentID]
		if !ok {
			return nil, inconsistentMessage("batch %s references an unknown deployment", batchID)
		}
		if !validHexID(batchID, "batch_", 32) ||
			entry.ProtocolVersion != protocol.Version ||
			entry.RegistryScope != registryScope ||
			(entry.EntryType != protocol.InstallationEntryType &&
				entry.EntryType != protocol.QualifiedMAUEntryType) ||
			entry.DeploymentID != record.DeploymentID ||
			entry.BatchID != record.BatchID ||
			entry.Kind != record.Kind ||
			entry.Period != record.Period ||
			entry.RulesetVersion != record.RulesetVersion ||
			entry.QualifiedMAUCount != record.QualifiedMAUCount ||
			entry.BatchHash != record.PayloadHash ||
			entry.AcceptedAt != record.AcceptedAt {
			return nil, inconsistentMessage("batch %s does not match its ledger entry", batchID)
		}
		var expectedPayload string
		switch record.Kind {
		case protocol.InstallationTestKind:
			expectedCommitment := protocol.Digest(protocol.InstallationTestCommitment(
				record.DeploymentID,
				record.IdempotencyKey,
			))
			if record.CommitmentHash != expectedCommitment ||
				record.Revision != 0 ||
				record.SupersedesBatchID != "" ||
				entry.EntryType != protocol.InstallationEntryType {
				return nil, inconsistentMessage("batch %s installation commitment verification failed", batchID)
			}
			expectedPayload = protocol.Digest(protocol.BatchPayload(
				record.Kind,
				record.Period,
				record.RulesetVersion,
				record.QualifiedMAUCount,
				record.CommitmentHash,
			))
		case protocol.QualifiedMAUKind:
			if record.RulesetVersion != protocol.QualifiedMAURuleset ||
				record.Revision < 1 ||
				entry.EntryType != protocol.QualifiedMAUEntryType {
				return nil, inconsistentMessage("batch %s has invalid QMAU metadata", batchID)
			}
			expectedPayload = protocol.Digest(protocol.QualifiedMAUPayload(
				record.Period,
				record.RulesetVersion,
				record.QualifiedMAUCount,
				record.CommitmentHash,
				record.Revision,
				record.SupersedesBatchID,
			))
		default:
			return nil, inconsistentMessage("batch %s has unsupported kind %q", batchID, record.Kind)
		}
		if record.PayloadHash != expectedPayload {
			return nil, inconsistentMessage("batch %s payload hash verification failed", batchID)
		}
		if !validPersistedTimestamp(batch.requestTimestamp) ||
			!validPersistedTimestamp(record.AcceptedAt) {
			return nil, inconsistentMessage("batch %s has an invalid timestamp", batchID)
		}
		requestMessage := protocol.CanonicalRequest(
			"POST",
			protocol.BatchPath,
			protocol.Version,
			registryScope,
			record.DeploymentID,
			batch.requestTimestamp,
			batch.requestNonce,
			record.IdempotencyKey,
			record.PayloadHash,
		)
		if !ed25519.Verify(deployment.publicKey, requestMessage, batch.requestSignature) {
			return nil, inconsistentMessage("batch %s deployment proof verification failed", batchID)
		}
		var receiptMessage []byte
		if record.Kind == protocol.QualifiedMAUKind {
			receiptMessage = protocol.QualifiedMAUReceiptMessage(
				protocol.Version,
				registryScope,
				record.BatchID,
				record.DeploymentID,
				entry.LedgerIndex,
				entry.EntryHash,
				entry.PreviousEntryHash,
				entry.BatchHash,
				record.Period,
				record.RulesetVersion,
				record.QualifiedMAUCount,
				record.CommitmentHash,
				record.Revision,
				record.SupersedesBatchID,
				record.AcceptedAt,
				record.AcceptedAt[:len("2006-01-02")],
				registryKeyID,
			)
		} else {
			receiptMessage = protocol.MAUReceiptMessage(
				protocol.Version,
				registryScope,
				record.BatchID,
				record.DeploymentID,
				entry.LedgerIndex,
				entry.EntryHash,
				entry.PreviousEntryHash,
				entry.BatchHash,
				record.Kind,
				record.Period,
				record.RulesetVersion,
				record.QualifiedMAUCount,
				record.AcceptedAt,
				record.AcceptedAt[:len("2006-01-02")],
				registryKeyID,
			)
		}
		if !ed25519.Verify(registryPublicKey, receiptMessage, record.ReceiptSignature) {
			return nil, inconsistentMessage("batch %s central receipt verification failed", batchID)
		}
	}
	if err := sqliteStore.verifyQualifiedMAURevisions(ctx); err != nil {
		return nil, err
	}
	return verified, nil
}

func (sqliteStore *Store) verifyQualifiedMAURevisions(ctx context.Context) error {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT deployment_id, period, batch_id, revision, supersedes_batch_id
		FROM mau_batches
		WHERE kind = ?
		ORDER BY deployment_id, period, revision`,
		protocol.QualifiedMAUKind,
	)
	if err != nil {
		return inconsistent("read QMAU revisions", err)
	}
	defer rows.Close()
	var previousDeployment, previousPeriod, previousBatch string
	var previousRevision int64
	for rows.Next() {
		var deploymentID, period, batchID, supersedes string
		var revision int64
		if err := rows.Scan(
			&deploymentID,
			&period,
			&batchID,
			&revision,
			&supersedes,
		); err != nil {
			return inconsistent("scan QMAU revision", err)
		}
		if deploymentID != previousDeployment || period != previousPeriod {
			if revision != 1 || supersedes != "" {
				return inconsistentMessage("QMAU revision chain for %s/%s has no canonical root", deploymentID, period)
			}
		} else if revision != previousRevision+1 || supersedes != previousBatch {
			return inconsistentMessage("QMAU revision chain for %s/%s branches at revision %d", deploymentID, period, revision)
		}
		previousDeployment = deploymentID
		previousPeriod = period
		previousBatch = batchID
		previousRevision = revision
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate QMAU revisions", err)
	}
	return nil
}

func (sqliteStore *Store) verifyIdempotencyRecords(
	ctx context.Context,
	deployments map[string]verifiedDeployment,
	batches map[string]verifiedBatch,
	revenueBatches map[string]verifiedRevenueBatch,
) error {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT signer, idempotency_key, payload_hash, result_type, result_id
		FROM idempotency_records`)
	if err != nil {
		return inconsistent("read idempotency records for verification", err)
	}
	records := make([]persistedIdempotency, 0)
	for rows.Next() {
		var record persistedIdempotency
		if err := rows.Scan(
			&record.signer,
			&record.idempotencyKey,
			&record.payloadHash,
			&record.resultType,
			&record.resultID,
		); err != nil {
			rows.Close()
			return inconsistent("scan idempotency record for verification", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return inconsistent("iterate idempotency records for verification", err)
	}
	if err := rows.Close(); err != nil {
		return inconsistent("close idempotency verification rows", err)
	}

	foundInitial := make(map[string]bool)
	for _, record := range records {
		if !protocol.IsDigest(record.payloadHash) {
			return inconsistentMessage("idempotency record %q has an invalid payload hash", record.idempotencyKey)
		}
		switch record.resultType {
		case "deployment":
			deployment, ok := deployments[record.resultID]
			if !ok || deployment.record.PublicKeyFingerprint != record.signer {
				return inconsistentMessage("idempotency record %q has an invalid deployment result", record.idempotencyKey)
			}
			if deployment.record.RegistrationIdempotencyKey == record.idempotencyKey {
				if deployment.record.PayloadHash != record.payloadHash {
					return inconsistentMessage("initial deployment idempotency record %q has an invalid payload", record.idempotencyKey)
				}
				foundInitial["deployment\x00"+record.resultID] = true
			}
		case "batch":
			if batch, ok := batches[record.resultID]; ok {
				if batch.record.DeploymentID != record.signer ||
					batch.record.IdempotencyKey != record.idempotencyKey ||
					batch.record.PayloadHash != record.payloadHash {
					return inconsistentMessage("idempotency record %q has an invalid batch result", record.idempotencyKey)
				}
			} else if batch, ok := revenueBatches[record.resultID]; ok {
				if batch.record.DeploymentID != record.signer ||
					batch.record.IdempotencyKey != record.idempotencyKey ||
					batch.record.PayloadHash != record.payloadHash {
					return inconsistentMessage("idempotency record %q has an invalid revenue batch result", record.idempotencyKey)
				}
			} else {
				return inconsistentMessage("idempotency record %q has an invalid batch result", record.idempotencyKey)
			}
			foundInitial["batch\x00"+record.resultID] = true
		default:
			return inconsistentMessage("idempotency record %q has an invalid result type", record.idempotencyKey)
		}
	}
	for deploymentID := range deployments {
		if !foundInitial["deployment\x00"+deploymentID] {
			return inconsistentMessage("deployment %s is missing its initial idempotency record", deploymentID)
		}
	}
	for batchID := range batches {
		if !foundInitial["batch\x00"+batchID] {
			return inconsistentMessage("batch %s is missing its idempotency record", batchID)
		}
	}
	for batchID := range revenueBatches {
		if !foundInitial["batch\x00"+batchID] {
			return inconsistentMessage(
				"revenue batch %s is missing its idempotency record",
				batchID,
			)
		}
	}
	return nil
}

func (sqliteStore *Store) verifyNonceRecords(
	ctx context.Context,
	deployments map[string]verifiedDeployment,
	batches map[string]verifiedBatch,
	revenueBatches map[string]verifiedRevenueBatch,
	registryScope string,
) error {
	idempotencyRows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT signer, idempotency_key, payload_hash, result_type, result_id
		FROM idempotency_records`)
	if err != nil {
		return inconsistent("read nonce idempotency links for verification", err)
	}
	idempotencyRecords := make(map[string]persistedIdempotency)
	for idempotencyRows.Next() {
		var record persistedIdempotency
		if err := idempotencyRows.Scan(
			&record.signer,
			&record.idempotencyKey,
			&record.payloadHash,
			&record.resultType,
			&record.resultID,
		); err != nil {
			idempotencyRows.Close()
			return inconsistent("scan nonce idempotency link for verification", err)
		}
		idempotencyRecords[record.signer+"\x00"+record.idempotencyKey] = record
	}
	if err := idempotencyRows.Err(); err != nil {
		idempotencyRows.Close()
		return inconsistent("iterate nonce idempotency links for verification", err)
	}
	if err := idempotencyRows.Close(); err != nil {
		return inconsistent("close nonce idempotency verification rows", err)
	}

	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			signer,
			nonce,
			request_hash,
			idempotency_key,
			payload_hash,
			request_timestamp,
			request_signature,
			result_type,
			result_id,
			accepted_at
		FROM used_nonces`)
	if err != nil {
		return inconsistent("read nonces for verification", err)
	}
	proofs := make([]persistedNonceProof, 0)
	for rows.Next() {
		var proof persistedNonceProof
		if err := rows.Scan(
			&proof.signer,
			&proof.nonce,
			&proof.requestHash,
			&proof.idempotencyKey,
			&proof.payloadHash,
			&proof.requestTimestamp,
			&proof.requestSignature,
			&proof.resultType,
			&proof.resultID,
			&proof.acceptedAt,
		); err != nil {
			rows.Close()
			return inconsistent("scan nonce for verification", err)
		}
		proofs = append(proofs, proof)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return inconsistent("iterate nonces for verification", err)
	}
	if err := rows.Close(); err != nil {
		return inconsistent("close nonce verification rows", err)
	}

	nonces := make(map[string]string, len(proofs))
	seenIdempotency := make(map[string]bool)
	for _, proof := range proofs {
		if !protocol.IsDigest(proof.requestHash) ||
			!protocol.IsDigest(proof.payloadHash) ||
			!validPersistedTimestamp(proof.requestTimestamp) ||
			!validPersistedTimestamp(proof.acceptedAt) {
			return inconsistentMessage("nonce %q has invalid persisted metadata", proof.nonce)
		}
		idempotencyKey := proof.signer + "\x00" + proof.idempotencyKey
		idempotency, ok := idempotencyRecords[idempotencyKey]
		if !ok ||
			idempotency.payloadHash != proof.payloadHash ||
			idempotency.resultType != proof.resultType ||
			idempotency.resultID != proof.resultID {
			return inconsistentMessage("nonce %q has an invalid idempotency link", proof.nonce)
		}

		var publicKey ed25519.PublicKey
		var path string
		switch proof.resultType {
		case "deployment":
			deployment, ok := deployments[proof.resultID]
			if !ok || deployment.record.PublicKeyFingerprint != proof.signer {
				return inconsistentMessage("nonce %q has an invalid deployment result", proof.nonce)
			}
			publicKey = deployment.publicKey
			path = protocol.RegistrationPath
		case "batch":
			path = protocol.BatchPath
			if batch, ok := batches[proof.resultID]; ok {
				if batch.record.DeploymentID != proof.signer {
					return inconsistentMessage("nonce %q has an invalid batch result", proof.nonce)
				}
			} else if batch, ok := revenueBatches[proof.resultID]; ok {
				if batch.record.DeploymentID != proof.signer {
					return inconsistentMessage("nonce %q has an invalid revenue batch result", proof.nonce)
				}
				path = protocol.RevenueBatchPath
			} else {
				return inconsistentMessage("nonce %q has an invalid batch result", proof.nonce)
			}
			deployment, ok := deployments[proof.signer]
			if !ok {
				return inconsistentMessage("nonce %q has an unknown deployment signer", proof.nonce)
			}
			publicKey = deployment.publicKey
		default:
			return inconsistentMessage("nonce %q has an invalid result type", proof.nonce)
		}
		requestMessage := protocol.CanonicalRequest(
			"POST",
			path,
			protocol.Version,
			registryScope,
			proof.signer,
			proof.requestTimestamp,
			proof.nonce,
			proof.idempotencyKey,
			proof.payloadHash,
		)
		expectedRequestHash := protocol.Digest(requestMessage)
		if proof.requestHash != expectedRequestHash ||
			!ed25519.Verify(publicKey, requestMessage, proof.requestSignature) {
			return inconsistentMessage("nonce %q signed request proof verification failed", proof.nonce)
		}
		nonces[proof.signer+"\x00"+proof.nonce] = proof.requestHash
		seenIdempotency[idempotencyKey] = true
	}
	for key, record := range idempotencyRecords {
		if !seenIdempotency[key] {
			return inconsistentMessage("idempotency record %q has no accepted nonce proof", record.idempotencyKey)
		}
	}

	for _, deployment := range deployments {
		record := deployment.record
		expectedHash := protocol.Digest(protocol.CanonicalRequest(
			"POST",
			protocol.RegistrationPath,
			protocol.Version,
			registryScope,
			record.PublicKeyFingerprint,
			record.RegistrationTimestamp,
			record.RegistrationNonce,
			record.RegistrationIdempotencyKey,
			record.PayloadHash,
		))
		if nonces[record.PublicKeyFingerprint+"\x00"+record.RegistrationNonce] != expectedHash {
			return inconsistentMessage("deployment %s is missing its initial nonce proof", record.DeploymentID)
		}
	}
	for _, batch := range batches {
		record := batch.record
		expectedHash := protocol.Digest(protocol.CanonicalRequest(
			"POST",
			protocol.BatchPath,
			protocol.Version,
			registryScope,
			record.DeploymentID,
			batch.requestTimestamp,
			batch.requestNonce,
			record.IdempotencyKey,
			record.PayloadHash,
		))
		if nonces[record.DeploymentID+"\x00"+batch.requestNonce] != expectedHash {
			return inconsistentMessage("batch %s is missing its initial nonce proof", record.BatchID)
		}
	}
	for _, batch := range revenueBatches {
		record := batch.record
		expectedHash := protocol.Digest(protocol.CanonicalRequest(
			"POST",
			protocol.RevenueBatchPath,
			protocol.Version,
			registryScope,
			record.DeploymentID,
			batch.requestTimestamp,
			batch.requestNonce,
			record.IdempotencyKey,
			record.PayloadHash,
		))
		if nonces[record.DeploymentID+"\x00"+batch.requestNonce] != expectedHash {
			return inconsistentMessage(
				"revenue batch %s is missing its initial nonce proof",
				record.BatchID,
			)
		}
	}
	return nil
}

func validPersistedTimestamp(value string) bool {
	if !strings.HasSuffix(value, "Z") {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}

func validHexID(value, prefix string, hexLength int) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+hexLength {
		return false
	}
	for _, character := range value[len(prefix):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func inconsistent(operation string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", store.ErrInconsistentState, operation)
	}
	return fmt.Errorf("%w: %s: %v", store.ErrInconsistentState, operation, cause)
}

func inconsistentMessage(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", store.ErrInconsistentState, fmt.Sprintf(format, arguments...))
}
