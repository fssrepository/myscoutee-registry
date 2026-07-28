package httpapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/app"
	"github.com/fssrepository/myscoutee-registry/internal/config"
	"github.com/fssrepository/myscoutee-registry/internal/httpapi"
	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

const testRegistryScope = "example:test-primary"

type mutableClock struct {
	mutex sync.RWMutex
	value time.Time
}

func (clock *mutableClock) Now() time.Time {
	clock.mutex.RLock()
	defer clock.mutex.RUnlock()
	return clock.value
}

func (clock *mutableClock) Set(value time.Time) {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	clock.value = value
}

type sequentialIDs struct {
	mutex sync.Mutex
	next  uint64
}

func (ids *sequentialIDs) New(prefix string) (string, error) {
	ids.mutex.Lock()
	defer ids.mutex.Unlock()
	ids.next++
	return fmt.Sprintf("%s%032x", prefix, ids.next), nil
}

type apiErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func TestSignedRegistryFlowOverHTTPWithRealSQLite(t *testing.T) {
	directory := t.TempDir()
	initialNow := time.Date(2026, 7, 28, 12, 0, 0, 100_000_000, time.UTC)
	clock := &mutableClock{value: initialNow}
	ids := &sequentialIDs{}
	cfg := config.Config{
		ListenAddress:       "127.0.0.1:0",
		RegistryScope:       testRegistryScope,
		DatabasePath:        filepath.Join(directory, "registry.db"),
		SigningKeyPath:      filepath.Join(directory, "registry-key.pem"),
		GenerateSigningKey:  true,
		TimestampSkew:       5 * time.Minute,
		MaxRequestBodyBytes: 64 * 1024,
		CheckpointInterval:  time.Minute,
		ShutdownTimeout:     5 * time.Second,
		HealthcheckURL:      "http://127.0.0.1/healthz",
	}
	runtime, err := app.Bootstrap(context.Background(), cfg, app.Options{
		Now:   clock.Now,
		NewID: ids.New,
	})
	if err != nil {
		t.Fatalf("bootstrap registry: %v", err)
	}
	defer runtime.Close()

	server := httptest.NewServer(httpapi.New(runtime.Service, httpapi.Options{
		MaxRequestBodyBytes: cfg.MaxRequestBodyBytes,
	}))
	defer server.Close()

	_, deploymentPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate deployment key: %v", err)
	}

	t.Run("canonical request target", func(t *testing.T) {
		status, body := rawRequest(
			t,
			http.MethodPost,
			server.URL+protocol.RegistrationPath+"?alias=true",
			[]byte("{}"),
			true,
		)
		assertAPIError(t, status, body, http.StatusBadRequest, "invalid_request_target")

		status, body = rawRequest(
			t,
			http.MethodPost,
			server.URL+"/v1/deployments/%72egister",
			[]byte("{}"),
			true,
		)
		assertAPIError(t, status, body, http.StatusBadRequest, "invalid_request_target")
	})

	t.Run("strict JSON decoder", func(t *testing.T) {
		status, body := rawRequest(
			t,
			http.MethodPost,
			server.URL+protocol.RegistrationPath,
			[]byte(`{"protocol_version":"1","unknown":true}`),
			true,
		)
		assertAPIError(t, status, body, http.StatusBadRequest, "invalid_json")

		status, body = rawRequest(
			t,
			http.MethodPost,
			server.URL+protocol.RegistrationPath,
			[]byte(`{} {}`),
			true,
		)
		assertAPIError(t, status, body, http.StatusBadRequest, "invalid_json")

		status, body = rawRequest(
			t,
			http.MethodPost,
			server.URL+protocol.RegistrationPath,
			[]byte(`{"protocol_version":"1","protocol_version":"1"}`),
			true,
		)
		assertAPIError(t, status, body, http.StatusBadRequest, "invalid_json")

		invalidUTF8 := append([]byte(`{"software_version":"`), 0xff)
		invalidUTF8 = append(invalidUTF8, []byte(`"}`)...)
		status, body = rawRequest(
			t,
			http.MethodPost,
			server.URL+protocol.RegistrationPath,
			invalidUTF8,
			true,
		)
		assertAPIError(t, status, body, http.StatusBadRequest, "invalid_json")

		status, body = rawRequestWithContentType(
			t,
			http.MethodPost,
			server.URL+protocol.RegistrationPath,
			[]byte(`{}`),
			"application/json; charset=iso-8859-1",
		)
		assertAPIError(t, status, body, http.StatusUnsupportedMediaType, "unsupported_media_type")

		oversized := bytes.Repeat([]byte("x"), int(cfg.MaxRequestBodyBytes)+1)
		status, body = rawRequest(
			t,
			http.MethodPost,
			server.URL+protocol.BatchPath,
			oversized,
			true,
		)
		assertAPIError(t, status, body, http.StatusRequestEntityTooLarge, "request_too_large")
	})

	t.Run("signed read-only registry identity preflight", func(t *testing.T) {
		status, body := rawRequest(
			t,
			http.MethodGet,
			server.URL+protocol.IdentityPath,
			nil,
			false,
		)
		if status != http.StatusOK {
			t.Fatalf("identity preflight status = %d, body = %s", status, body)
		}
		var identityResponse protocol.RegistryIdentity
		decodeResponse(t, body, &identityResponse)
		if identityResponse.ProtocolVersion != protocol.Version ||
			identityResponse.RegistryScope != testRegistryScope {
			t.Fatalf("unexpected registry identity response: %+v", identityResponse)
		}
		registryPublicKey, publicKeyDER, err := protocol.ParsePublicKey(identityResponse.RegistryPublicKey)
		if err != nil {
			t.Fatalf("parse preflight registry public key: %v", err)
		}
		if identityResponse.RegistryKeyID != protocol.RegistryKeyID(publicKeyDER) {
			t.Fatalf("preflight registry key ID does not match its public key")
		}
		signature, err := protocol.ParseSignature(identityResponse.Signature)
		if err != nil {
			t.Fatalf("parse preflight identity signature: %v", err)
		}
		if !protocol.Verify(
			registryPublicKey,
			protocol.RegistryIdentityMessage(
				identityResponse.ProtocolVersion,
				identityResponse.RegistryScope,
				identityResponse.RegistryKeyID,
				identityResponse.RegistryPublicKey,
			),
			signature,
		) {
			t.Fatalf("registry identity self-signature verification failed")
		}

		retryStatus, retryBody := rawRequest(
			t,
			http.MethodGet,
			server.URL+protocol.IdentityPath,
			nil,
			false,
		)
		if retryStatus != http.StatusOK || !bytes.Equal(body, retryBody) {
			t.Fatalf("read-only identity preflight was not stable")
		}
		status, body = rawRequest(t, http.MethodGet, server.URL+"/healthz", nil, false)
		if status != http.StatusOK {
			t.Fatalf("health after identity preflight = %d, body = %s", status, body)
		}
		var health struct {
			EntryCount int64 `json:"entry_count"`
		}
		decodeResponse(t, body, &health)
		if health.EntryCount != 0 {
			t.Fatalf("identity preflight mutated the ledger")
		}
	})

	registrationTimestamp := "2026-07-28T12:00:00.100Z"
	registration := signedRegistration(
		t,
		deploymentPrivateKey,
		registrationTimestamp,
		"nonce_registration_0001",
		"registration_installation_0001",
		"test-1.0.0",
	)

	t.Run("strict UTC timestamp wire form", func(t *testing.T) {
		offsetTimestamp := "2026-07-28T12:00:00.100+00:00"
		offsetRequest := registration
		offsetRequest.Timestamp = offsetTimestamp
		offsetRequest.Nonce = "nonce_registration_offset"
		offsetRequest.IdempotencyKey = "registration_installation_offset"
		resignRegistration(t, deploymentPrivateKey, &offsetRequest)
		status, body := jsonRequest(t, http.MethodPost, server.URL+protocol.RegistrationPath, offsetRequest)
		assertAPIError(t, status, body, http.StatusBadRequest, "invalid_timestamp")
	})

	t.Run("sovereign scope separation", func(t *testing.T) {
		foreignScopeRequest := registration
		foreignScopeRequest.RegistryScope = "example:other-parent"
		foreignScopeRequest.Nonce = "nonce_registration_cn_scope"
		foreignScopeRequest.IdempotencyKey = "registration_installation_other"
		resignRegistration(t, deploymentPrivateKey, &foreignScopeRequest)
		status, body := jsonRequest(
			t,
			http.MethodPost,
			server.URL+protocol.RegistrationPath,
			foreignScopeRequest,
		)
		assertAPIError(t, status, body, http.StatusBadRequest, "registry_scope_mismatch")
	})

	status, body := jsonRequest(t, http.MethodPost, server.URL+protocol.RegistrationPath, registration)
	if status != http.StatusCreated {
		t.Fatalf("registration status = %d, body = %s", status, body)
	}
	var registrationResponse protocol.RegistrationResponse
	decodeResponse(t, body, &registrationResponse)
	if registrationResponse.Duplicate {
		t.Fatalf("first registration unexpectedly marked duplicate")
	}
	if registrationResponse.RegisteredAt != "2026-07-28T12:00:00Z" {
		t.Fatalf("registered_at = %q", registrationResponse.RegisteredAt)
	}
	if registrationResponse.PublicKeyFingerprint == "" || registrationResponse.DeploymentID == "" {
		t.Fatalf("registration response is missing identity fields: %+v", registrationResponse)
	}
	if registrationResponse.RegistryScope != testRegistryScope {
		t.Fatalf("registration scope = %q", registrationResponse.RegistryScope)
	}
	verifyRegistrationReceipt(t, registrationResponse)

	status, body = jsonRequest(t, http.MethodPost, server.URL+protocol.RegistrationPath, registration)
	if status != http.StatusOK {
		t.Fatalf("duplicate registration status = %d, body = %s", status, body)
	}
	var duplicateRegistration protocol.RegistrationResponse
	decodeResponse(t, body, &duplicateRegistration)
	if !duplicateRegistration.Duplicate {
		t.Fatalf("retry registration was not marked duplicate")
	}
	originalRegistrationAsDuplicate := registrationResponse
	originalRegistrationAsDuplicate.Duplicate = true
	if !reflect.DeepEqual(duplicateRegistration, originalRegistrationAsDuplicate) {
		t.Fatalf("duplicate registration did not return the stored result")
	}

	t.Run("registration idempotency and replay conflicts", func(t *testing.T) {
		conflict := signedRegistration(
			t,
			deploymentPrivateKey,
			registrationTimestamp,
			"nonce_registration_0002",
			registration.IdempotencyKey,
			"test-1.0.1",
		)
		status, body := jsonRequest(t, http.MethodPost, server.URL+protocol.RegistrationPath, conflict)
		assertAPIError(t, status, body, http.StatusConflict, "idempotency_conflict")

		replay := signedRegistration(
			t,
			deploymentPrivateKey,
			registrationTimestamp,
			registration.Nonce,
			"registration_installation_0002",
			"test-1.0.0",
		)
		status, body = jsonRequest(t, http.MethodPost, server.URL+protocol.RegistrationPath, replay)
		assertAPIError(t, status, body, http.StatusConflict, "replay_conflict")
	})

	batchNow := time.Date(2026, 7, 28, 12, 1, 0, 100_000_000, time.UTC)
	clock.Set(batchNow)
	batchTimestamp := "2026-07-28T12:00:01.100Z"
	batch := signedBatch(
		t,
		deploymentPrivateKey,
		registrationResponse.DeploymentID,
		batchTimestamp,
		"nonce_batch_00000001",
		"installation_batch_0001",
		"2026-07",
	)

	t.Run("empty ledger cannot predate registry identity", func(t *testing.T) {
		clock.Set(time.Date(2026, 7, 27, 23, 59, 0, 0, time.UTC))
		preIdentityBatch := signedBatch(
			t,
			deploymentPrivateKey,
			registrationResponse.DeploymentID,
			"2026-07-27T23:59:00Z",
			"nonce_batch_before_identity",
			"installation_before_identity",
			"2026-07",
		)
		status, body := jsonRequest(t, http.MethodPost, server.URL+protocol.BatchPath, preIdentityBatch)
		assertAPIError(
			t,
			status,
			body,
			http.StatusServiceUnavailable,
			"registry_clock_before_identity",
		)
		clock.Set(batchNow)
	})

	t.Run("invalid signature", func(t *testing.T) {
		invalid := signedBatch(
			t,
			deploymentPrivateKey,
			registrationResponse.DeploymentID,
			batchTimestamp,
			"nonce_batch_invalid_sig",
			"installation_batch_invalid_sig",
			"2026-07",
		)
		signature, err := protocol.ParseSignature(invalid.Signature)
		if err != nil {
			t.Fatalf("parse generated test signature: %v", err)
		}
		signature[0] ^= 0xff
		invalid.Signature = protocol.EncodeSignature(signature)
		status, body := jsonRequest(t, http.MethodPost, server.URL+protocol.BatchPath, invalid)
		assertAPIError(t, status, body, http.StatusUnauthorized, "invalid_signature")
	})

	status, body = jsonRequest(t, http.MethodPost, server.URL+protocol.BatchPath, batch)
	if status != http.StatusCreated {
		t.Fatalf("batch status = %d, body = %s", status, body)
	}
	var batchResponse protocol.BatchResponse
	decodeResponse(t, body, &batchResponse)
	if batchResponse.Duplicate {
		t.Fatalf("first batch unexpectedly marked duplicate")
	}
	verifyBatchReceiptAndLedgerEntry(t, batch, batchResponse)

	retryBatch := signedBatch(
		t,
		deploymentPrivateKey,
		registrationResponse.DeploymentID,
		batchTimestamp,
		"nonce_batch_00000002",
		batch.IdempotencyKey,
		batch.Period,
	)
	status, body = jsonRequest(t, http.MethodPost, server.URL+protocol.BatchPath, retryBatch)
	if status != http.StatusOK {
		t.Fatalf("duplicate batch status = %d, body = %s", status, body)
	}
	var duplicateBatch protocol.BatchResponse
	decodeResponse(t, body, &duplicateBatch)
	firstBatchAsDuplicate := batchResponse
	firstBatchAsDuplicate.Duplicate = true
	if !reflect.DeepEqual(duplicateBatch, firstBatchAsDuplicate) {
		t.Fatalf("duplicate batch did not return its immutable stored receipt")
	}

	status, body = rawRequest(
		t,
		http.MethodGet,
		server.URL+protocol.BatchPath+"/"+batchResponse.BatchID+"/receipt",
		nil,
		false,
	)
	if status != http.StatusOK {
		t.Fatalf("receipt lookup status = %d, body = %s", status, body)
	}
	var lookedUpReceipt protocol.BatchResponse
	decodeResponse(t, body, &lookedUpReceipt)
	if !reflect.DeepEqual(lookedUpReceipt, firstBatchAsDuplicate) {
		t.Fatalf("receipt lookup differs from accepted receipt")
	}

	t.Run("batch idempotency and replay conflicts", func(t *testing.T) {
		conflict := signedBatch(
			t,
			deploymentPrivateKey,
			registrationResponse.DeploymentID,
			batchTimestamp,
			"nonce_batch_00000003",
			batch.IdempotencyKey,
			"2026-06",
		)
		status, body := jsonRequest(t, http.MethodPost, server.URL+protocol.BatchPath, conflict)
		assertAPIError(t, status, body, http.StatusConflict, "idempotency_conflict")

		replay := signedBatch(
			t,
			deploymentPrivateKey,
			registrationResponse.DeploymentID,
			batchTimestamp,
			batch.Nonce,
			"installation_batch_0002",
			batch.Period,
		)
		status, body = jsonRequest(t, http.MethodPost, server.URL+protocol.BatchPath, replay)
		assertAPIError(t, status, body, http.StatusConflict, "replay_conflict")
	})

	t.Run("clock rollback cannot reorder the uncheckpointed ledger", func(t *testing.T) {
		clock.Set(time.Date(2026, 7, 28, 12, 0, 30, 0, time.UTC))
		rolledBackBatch := signedBatch(
			t,
			deploymentPrivateKey,
			registrationResponse.DeploymentID,
			"2026-07-28T12:00:30Z",
			"nonce_batch_precheckpoint_rollback",
			"installation_precheckpoint_rollback",
			"2026-07",
		)
		status, body := jsonRequest(t, http.MethodPost, server.URL+protocol.BatchPath, rolledBackBatch)
		assertAPIError(
			t,
			status,
			body,
			http.StatusServiceUnavailable,
			"registry_clock_before_ledger_head",
		)
		clock.Set(batchNow)
	})

	clock.Set(time.Date(2026, 7, 29, 0, 1, 0, 0, time.UTC))
	status, body = rawRequest(
		t,
		http.MethodGet,
		server.URL+"/v1/ledger/checkpoints/2026-07-28",
		nil,
		false,
	)
	if status != http.StatusOK {
		t.Fatalf("checkpoint status = %d, body = %s", status, body)
	}
	var checkpoint protocol.Checkpoint
	decodeResponse(t, body, &checkpoint)
	if checkpoint.EntryCount != 1 ||
		checkpoint.ThroughLedgerIndex != 1 ||
		checkpoint.RegistryScope != testRegistryScope ||
		checkpoint.LedgerHeadHash != batchResponse.Receipt.EntryHash ||
		checkpoint.PreviousCheckpointHash != protocol.ZeroHash {
		t.Fatalf("checkpoint does not commit the completed-day ledger: %+v", checkpoint)
	}
	if checkpoint.CheckpointHash != protocol.Digest(protocol.CheckpointMessage(checkpoint)) {
		t.Fatalf("checkpoint hash verification failed")
	}
	checkpointPublicKey, _, err := protocol.ParsePublicKey(checkpoint.RegistryPublicKey)
	if err != nil {
		t.Fatalf("parse checkpoint registry public key: %v", err)
	}
	checkpointSignature, err := protocol.ParseSignature(checkpoint.Signature)
	if err != nil {
		t.Fatalf("parse checkpoint signature: %v", err)
	}
	if !protocol.Verify(checkpointPublicKey, protocol.CheckpointMessage(checkpoint), checkpointSignature) {
		t.Fatalf("checkpoint signature verification failed")
	}

	t.Run("clock rollback cannot append into finalized day", func(t *testing.T) {
		clock.Set(time.Date(2026, 7, 28, 13, 0, 0, 0, time.UTC))
		rolledBackBatch := signedBatch(
			t,
			deploymentPrivateKey,
			registrationResponse.DeploymentID,
			"2026-07-28T13:00:00Z",
			"nonce_batch_rollback_01",
			"installation_batch_rollback",
			"2026-07",
		)
		status, body := jsonRequest(t, http.MethodPost, server.URL+protocol.BatchPath, rolledBackBatch)
		assertAPIError(
			t,
			status,
			body,
			http.StatusServiceUnavailable,
			"registry_clock_before_checkpoint",
		)
	})

	status, body = rawRequest(t, http.MethodGet, server.URL+"/healthz", nil, false)
	if status != http.StatusOK {
		t.Fatalf("health status = %d, body = %s", status, body)
	}
	var health struct {
		Status         string `json:"status"`
		RegistryScope  string `json:"registry_scope"`
		LedgerIndex    int64  `json:"ledger_index"`
		EntryCount     int64  `json:"entry_count"`
		LedgerHeadHash string `json:"ledger_head_hash"`
	}
	decodeResponse(t, body, &health)
	if health.Status != "ok" ||
		health.RegistryScope != testRegistryScope ||
		health.LedgerIndex != 1 ||
		health.EntryCount != 1 ||
		health.LedgerHeadHash != batchResponse.Receipt.EntryHash {
		t.Fatalf("unexpected health response: %+v", health)
	}
	if err := runtime.Service.VerifyState(context.Background()); err != nil {
		t.Fatalf("verify final registry state: %v", err)
	}

	t.Run("restart verifies existing ledger and fails closed after corruption", func(t *testing.T) {
		server.Close()
		if err := runtime.Close(); err != nil {
			t.Fatalf("close first runtime before restart: %v", err)
		}
		clock.Set(time.Date(2026, 7, 29, 0, 2, 0, 0, time.UTC))
		restarted, err := app.Bootstrap(context.Background(), cfg, app.Options{
			Now:   clock.Now,
			NewID: ids.New,
		})
		if err != nil {
			t.Fatalf("restart with ledger and checkpoint: %v", err)
		}
		defer restarted.Close()
		if restarted.SigningKey.KeyID() != registrationResponse.RegistryKeyID {
			t.Fatalf("registry key changed across populated restart")
		}
		if err := restarted.Service.VerifyState(context.Background()); err != nil {
			t.Fatalf("verify populated state after restart: %v", err)
		}
		restartedServer := httptest.NewServer(httpapi.New(restarted.Service, httpapi.Options{
			MaxRequestBodyBytes: cfg.MaxRequestBodyBytes,
		}))
		defer restartedServer.Close()
		status, body := rawRequest(t, http.MethodGet, restartedServer.URL+"/healthz", nil, false)
		if status != http.StatusOK {
			t.Fatalf("restarted health status = %d, body = %s", status, body)
		}

		tamperDatabase, err := sql.Open("sqlite", cfg.DatabasePath)
		if err != nil {
			t.Fatalf("open independent tamper-test connection: %v", err)
		}
		defer tamperDatabase.Close()
		if _, err := tamperDatabase.Exec("PRAGMA busy_timeout = 5000"); err != nil {
			t.Fatalf("set tamper-test busy timeout: %v", err)
		}
		if _, err := tamperDatabase.Exec("DROP TRIGGER mau_batches_no_update"); err != nil {
			t.Fatalf("drop append-only trigger for corruption simulation: %v", err)
		}
		if _, err := tamperDatabase.Exec(
			"UPDATE mau_batches SET payload_hash = ? WHERE batch_id = ?",
			protocol.ZeroHash,
			batchResponse.BatchID,
		); err != nil {
			t.Fatalf("simulate cross-table batch corruption: %v", err)
		}

		status, body = rawRequest(t, http.MethodGet, restartedServer.URL+"/healthz", nil, false)
		assertAPIError(t, status, body, http.StatusServiceUnavailable, "registry_unavailable")
		status, body = rawRequest(t, http.MethodGet, restartedServer.URL+protocol.IdentityPath, nil, false)
		assertAPIError(
			t,
			status,
			body,
			http.StatusServiceUnavailable,
			"registry_integrity_unavailable",
		)

		_, anotherPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate post-corruption deployment key: %v", err)
		}
		postCorruptionRegistration := signedRegistration(
			t,
			anotherPrivateKey,
			"2026-07-29T00:02:00Z",
			"nonce_registration_corrupt",
			"registration_after_corruption",
			"test-1.0.0",
		)
		status, body = jsonRequest(
			t,
			http.MethodPost,
			restartedServer.URL+protocol.RegistrationPath,
			postCorruptionRegistration,
		)
		assertAPIError(
			t,
			status,
			body,
			http.StatusServiceUnavailable,
			"registry_integrity_unavailable",
		)

		postCorruptionBatch := signedBatch(
			t,
			deploymentPrivateKey,
			registrationResponse.DeploymentID,
			"2026-07-29T00:02:00Z",
			"nonce_batch_after_corruption",
			"installation_after_corruption",
			"2026-07",
		)
		status, body = jsonRequest(
			t,
			http.MethodPost,
			restartedServer.URL+protocol.BatchPath,
			postCorruptionBatch,
		)
		assertAPIError(
			t,
			status,
			body,
			http.StatusServiceUnavailable,
			"registry_integrity_unavailable",
		)
	})
}

func signedRegistration(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	timestamp string,
	nonce string,
	idempotencyKey string,
	softwareVersion string,
) protocol.RegistrationRequest {
	t.Helper()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	encodedPublicKey, _, err := protocol.EncodePublicKey(publicKey)
	if err != nil {
		t.Fatalf("encode deployment public key: %v", err)
	}
	request := protocol.RegistrationRequest{
		ProtocolVersion: protocol.Version,
		RegistryScope:   testRegistryScope,
		Timestamp:       timestamp,
		Nonce:           nonce,
		IdempotencyKey:  idempotencyKey,
		KeyAlgorithm:    protocol.KeyAlgorithmEd25519,
		PublicKey:       encodedPublicKey,
		SoftwareVersion: softwareVersion,
	}
	request.PayloadHash = protocol.Digest(protocol.RegistrationPayload(
		request.KeyAlgorithm,
		request.PublicKey,
		request.SoftwareVersion,
	))
	resignRegistration(t, privateKey, &request)
	return request
}

func resignRegistration(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	request *protocol.RegistrationRequest,
) {
	t.Helper()
	_, publicKeyDER, err := protocol.ParsePublicKey(request.PublicKey)
	if err != nil {
		t.Fatalf("parse deployment public key: %v", err)
	}
	fingerprint := protocol.PublicKeyFingerprint(publicKeyDER)
	request.Signature = protocol.EncodeSignature(ed25519.Sign(
		privateKey,
		protocol.CanonicalRequest(
			http.MethodPost,
			protocol.RegistrationPath,
			request.ProtocolVersion,
			request.RegistryScope,
			fingerprint,
			request.Timestamp,
			request.Nonce,
			request.IdempotencyKey,
			request.PayloadHash,
		),
	))
}

func signedBatch(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	deploymentID string,
	timestamp string,
	nonce string,
	idempotencyKey string,
	period string,
) protocol.BatchRequest {
	t.Helper()
	request := protocol.BatchRequest{
		ProtocolVersion:   protocol.Version,
		RegistryScope:     testRegistryScope,
		DeploymentID:      deploymentID,
		Timestamp:         timestamp,
		Nonce:             nonce,
		IdempotencyKey:    idempotencyKey,
		Kind:              protocol.InstallationTestKind,
		Period:            period,
		RulesetVersion:    protocol.InstallationTestRuleset,
		QualifiedMAUCount: 0,
	}
	request.CommitmentHash = protocol.Digest(protocol.InstallationTestCommitment(
		request.DeploymentID,
		request.IdempotencyKey,
	))
	request.PayloadHash = protocol.Digest(protocol.BatchPayload(
		request.Kind,
		request.Period,
		request.RulesetVersion,
		request.QualifiedMAUCount,
		request.CommitmentHash,
	))
	request.Signature = protocol.EncodeSignature(ed25519.Sign(
		privateKey,
		protocol.CanonicalRequest(
			http.MethodPost,
			protocol.BatchPath,
			request.ProtocolVersion,
			request.RegistryScope,
			request.DeploymentID,
			request.Timestamp,
			request.Nonce,
			request.IdempotencyKey,
			request.PayloadHash,
		),
	))
	return request
}

func verifyRegistrationReceipt(t *testing.T, response protocol.RegistrationResponse) {
	t.Helper()
	registryPublicKey, _, err := protocol.ParsePublicKey(response.RegistryPublicKey)
	if err != nil {
		t.Fatalf("parse registry public key: %v", err)
	}
	signature, err := protocol.ParseSignature(response.ReceiptSignature)
	if err != nil {
		t.Fatalf("parse registration receipt signature: %v", err)
	}
	if !protocol.Verify(
		registryPublicKey,
		protocol.RegistrationReceipt(
			response.ProtocolVersion,
			response.RegistryScope,
			response.DeploymentID,
			response.PublicKeyFingerprint,
			response.RegisteredAt,
			response.RegistryKeyID,
		),
		signature,
	) {
		t.Fatalf("registration receipt signature verification failed")
	}
}

func verifyBatchReceiptAndLedgerEntry(
	t *testing.T,
	request protocol.BatchRequest,
	response protocol.BatchResponse,
) {
	t.Helper()
	receipt := response.Receipt
	entry := protocol.LedgerEntry{
		ProtocolVersion:   response.ProtocolVersion,
		RegistryScope:     response.RegistryScope,
		LedgerIndex:       receipt.LedgerIndex,
		EntryType:         protocol.InstallationEntryType,
		DeploymentID:      response.DeploymentID,
		BatchID:           response.BatchID,
		Kind:              receipt.Kind,
		Period:            receipt.Period,
		RulesetVersion:    receipt.RulesetVersion,
		QualifiedMAUCount: receipt.QualifiedMAUCount,
		BatchHash:         receipt.BatchHash,
		PreviousEntryHash: receipt.PreviousEntryHash,
		AcceptedAt:        receipt.AcceptedAt,
	}
	if receipt.LedgerIndex != 1 ||
		receipt.PreviousEntryHash != protocol.ZeroHash ||
		receipt.BatchHash != request.PayloadHash ||
		receipt.EntryHash != protocol.Digest(protocol.LedgerEntryMessage(entry)) {
		t.Fatalf("receipt does not contain a valid first ledger entry: %+v", receipt)
	}
	registryPublicKey, _, err := protocol.ParsePublicKey(receipt.RegistryPublicKey)
	if err != nil {
		t.Fatalf("parse receipt registry public key: %v", err)
	}
	signature, err := protocol.ParseSignature(receipt.Signature)
	if err != nil {
		t.Fatalf("parse receipt signature: %v", err)
	}
	message := protocol.MAUReceiptMessage(
		response.ProtocolVersion,
		response.RegistryScope,
		response.BatchID,
		response.DeploymentID,
		receipt.LedgerIndex,
		receipt.EntryHash,
		receipt.PreviousEntryHash,
		receipt.BatchHash,
		receipt.Kind,
		receipt.Period,
		receipt.RulesetVersion,
		receipt.QualifiedMAUCount,
		receipt.AcceptedAt,
		receipt.CheckpointDate,
		receipt.RegistryKeyID,
	)
	if !protocol.Verify(registryPublicKey, message, signature) {
		t.Fatalf("MAU receipt signature verification failed")
	}
}

func jsonRequest(t *testing.T, method, url string, value any) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return rawRequest(t, method, url, body, true)
}

func rawRequest(
	t *testing.T,
	method string,
	url string,
	body []byte,
	contentTypeJSON bool,
) (int, []byte) {
	t.Helper()
	contentType := ""
	if contentTypeJSON {
		contentType = "application/json"
	}
	return rawRequestWithContentType(t, method, url, body, contentType)
}

func rawRequestWithContentType(
	t *testing.T,
	method string,
	url string,
	body []byte,
	contentType string,
) (int, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build HTTP request: %v", err)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("perform HTTP request: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read HTTP response: %v", err)
	}
	return response.StatusCode, responseBody
}

func decodeResponse(t *testing.T, body []byte, destination any) {
	t.Helper()
	if err := json.Unmarshal(body, destination); err != nil {
		t.Fatalf("decode response %s: %v", body, err)
	}
}

func assertAPIError(
	t *testing.T,
	status int,
	body []byte,
	expectedStatus int,
	expectedCode string,
) {
	t.Helper()
	if status != expectedStatus {
		t.Fatalf("status = %d, want %d; body = %s", status, expectedStatus, body)
	}
	var response apiErrorResponse
	decodeResponse(t, body, &response)
	if response.Error.Code != expectedCode {
		t.Fatalf("error code = %q, want %q; body = %s", response.Error.Code, expectedCode, body)
	}
}
