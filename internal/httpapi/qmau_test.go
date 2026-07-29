package httpapi_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/app"
	"github.com/fssrepository/myscoutee-registry/internal/config"
	"github.com/fssrepository/myscoutee-registry/internal/httpapi"
	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

func TestSignedQualifiedMAURevisionsReceiptsAndLeaderboard(t *testing.T) {
	directory := t.TempDir()
	clock := &mutableClock{
		value: time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC),
	}
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
	fullAuditsAtBootstrap := runtime.Service.FullVerificationRuns()
	if fullAuditsAtBootstrap != 1 {
		t.Fatalf(
			"bootstrap full verification runs = %d, want 1",
			fullAuditsAtBootstrap,
		)
	}
	server := httptest.NewServer(httpapi.New(runtime.Service, httpapi.Options{
		MaxRequestBodyBytes: cfg.MaxRequestBodyBytes,
	}))
	defer server.Close()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate deployment key: %v", err)
	}
	registration := signedRegistration(
		t,
		privateKey,
		"2026-07-28T15:00:00Z",
		"nonce_qmau_registration_0001",
		"qmau_registration_0001",
		"test-qmau-1.0.0",
	)
	status, body := jsonRequest(
		t,
		http.MethodPost,
		server.URL+protocol.RegistrationPath,
		registration,
	)
	if status != http.StatusCreated {
		t.Fatalf("registration status = %d, body = %s", status, body)
	}
	var registered protocol.RegistrationResponse
	decodeResponse(t, body, &registered)

	revisionOne := signedQualifiedMAU(
		t,
		privateKey,
		registered.DeploymentID,
		"2026-07-28T15:00:01Z",
		"nonce_qmau_batch_000001",
		"qmau_2026_06_revision_1",
		"2026-06",
		100,
		protocol.Digest([]byte("private-evidence-v1")),
		1,
		"",
	)
	status, body = jsonRequest(
		t,
		http.MethodPost,
		server.URL+protocol.BatchPath,
		revisionOne,
	)
	if status != http.StatusCreated {
		t.Fatalf("QMAU revision 1 status = %d, body = %s", status, body)
	}
	var first protocol.BatchResponse
	decodeResponse(t, body, &first)
	verifyQualifiedMAUReceipt(t, revisionOne, first)

	retry := revisionOne
	retry.Nonce = "nonce_qmau_batch_retry01"
	resignQualifiedMAU(privateKey, &retry)
	status, body = jsonRequest(
		t,
		http.MethodPost,
		server.URL+protocol.BatchPath,
		retry,
	)
	if status != http.StatusOK {
		t.Fatalf("QMAU retry status = %d, body = %s", status, body)
	}
	var duplicate protocol.BatchResponse
	decodeResponse(t, body, &duplicate)
	expectedDuplicate := first
	expectedDuplicate.Duplicate = true
	if !reflect.DeepEqual(duplicate, expectedDuplicate) {
		t.Fatalf("QMAU retry did not return the exact stored receipt")
	}

	revisionTwo := signedQualifiedMAU(
		t,
		privateKey,
		registered.DeploymentID,
		"2026-07-28T15:00:02Z",
		"nonce_qmau_batch_000002",
		"qmau_2026_06_revision_2",
		"2026-06",
		150,
		protocol.Digest([]byte("private-evidence-v2")),
		2,
		first.BatchID,
	)
	status, body = jsonRequest(
		t,
		http.MethodPost,
		server.URL+protocol.BatchPath,
		revisionTwo,
	)
	if status != http.StatusCreated {
		t.Fatalf("QMAU revision 2 status = %d, body = %s", status, body)
	}
	var second protocol.BatchResponse
	decodeResponse(t, body, &second)
	verifyQualifiedMAUReceipt(t, revisionTwo, second)

	staleBranch := signedQualifiedMAU(
		t,
		privateKey,
		registered.DeploymentID,
		"2026-07-28T15:00:03Z",
		"nonce_qmau_stale_branch",
		"qmau_2026_06_stale_branch",
		"2026-06",
		175,
		protocol.Digest([]byte("private-evidence-stale")),
		3,
		first.BatchID,
	)
	status, body = jsonRequest(
		t,
		http.MethodPost,
		server.URL+protocol.BatchPath,
		staleBranch,
	)
	assertAPIError(
		t,
		status,
		body,
		http.StatusConflict,
		"qmau_revision_conflict",
	)

	status, body = rawRequest(
		t,
		http.MethodGet,
		server.URL+protocol.BatchPath+"/"+second.BatchID+"/receipt",
		nil,
		false,
	)
	if status != http.StatusOK {
		t.Fatalf("QMAU receipt lookup status = %d, body = %s", status, body)
	}
	var stored protocol.BatchResponse
	decodeResponse(t, body, &stored)
	expectedStored := second
	expectedStored.Duplicate = true
	if !reflect.DeepEqual(stored, expectedStored) {
		t.Fatalf("QMAU receipt lookup did not return the stored receipt")
	}

	page, err := runtime.Service.Leaderboard(
		context.Background(),
		"unclaimed",
		"2026-06",
		100,
		"",
	)
	if err != nil {
		t.Fatalf("query QMAU leaderboard: %v", err)
	}
	if len(page.Items) != 1 ||
		page.Items[0].RowID != registered.DeploymentID ||
		page.Items[0].WeightNumerator != "25" ||
		page.Items[0].WeightDenominator != "1" {
		t.Fatalf("leaderboard did not select the latest QMAU revision: %+v", page.Items)
	}

	proof, err := runtime.Service.MerkleConsistencyProof(
		context.Background(),
		1,
		2,
	)
	if err != nil {
		t.Fatalf("generate QMAU ledger consistency proof: %v", err)
	}
	if err := protocol.VerifyMerkleConsistencyProof(proof); err != nil {
		t.Fatalf("verify QMAU ledger consistency proof: %v", err)
	}

	status, body = rawRequest(
		t,
		http.MethodGet,
		server.URL+"/v1/ledger/merkle/inclusion/0/1",
		nil,
		false,
	)
	if status != http.StatusOK {
		t.Fatalf("current-head inclusion HTTP status = %d, body = %s", status, body)
	}
	var inclusion protocol.MerkleInclusionProof
	decodeResponse(t, body, &inclusion)
	if inclusion.TreeHead.TreeSize != 2 {
		t.Fatalf("current-head inclusion selected size %d, want 2", inclusion.TreeHead.TreeSize)
	}
	if err := protocol.VerifyMerkleInclusionProof(inclusion); err != nil {
		t.Fatalf("verify HTTP inclusion proof: %v", err)
	}

	status, body = rawRequest(
		t,
		http.MethodGet,
		server.URL+"/v1/ledger/merkle/consistency/1/0",
		nil,
		false,
	)
	if status != http.StatusOK {
		t.Fatalf("current-head consistency HTTP status = %d, body = %s", status, body)
	}
	var consistency protocol.MerkleConsistencyProof
	decodeResponse(t, body, &consistency)
	if consistency.TreeHead.TreeSize != 2 {
		t.Fatalf(
			"current-head consistency selected size %d, want 2",
			consistency.TreeHead.TreeSize,
		)
	}
	if err := protocol.VerifyMerkleConsistencyProof(consistency); err != nil {
		t.Fatalf("verify HTTP consistency proof: %v", err)
	}
	if got := runtime.Service.FullVerificationRuns(); got != fullAuditsAtBootstrap {
		t.Fatalf(
			"ordinary registration/QMAU/read/proof paths ran %d additional full audits",
			got-fullAuditsAtBootstrap,
		)
	}
	if _, err := runtime.Service.Health(context.Background()); err != nil {
		t.Fatalf("run explicit full health audit: %v", err)
	}
	if got := runtime.Service.FullVerificationRuns(); got != fullAuditsAtBootstrap+1 {
		t.Fatalf(
			"explicit health full verification runs = %d, want %d",
			got,
			fullAuditsAtBootstrap+1,
		)
	}
}

func signedQualifiedMAU(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	deploymentID string,
	timestamp string,
	nonce string,
	idempotencyKey string,
	period string,
	count int64,
	commitmentHash string,
	revision int64,
	supersedesBatchID string,
) protocol.BatchRequest {
	t.Helper()
	request := protocol.BatchRequest{
		ProtocolVersion:   protocol.Version,
		RegistryScope:     testRegistryScope,
		DeploymentID:      deploymentID,
		Timestamp:         timestamp,
		Nonce:             nonce,
		IdempotencyKey:    idempotencyKey,
		Kind:              protocol.QualifiedMAUKind,
		Period:            period,
		RulesetVersion:    protocol.QualifiedMAURuleset,
		QualifiedMAUCount: count,
		CommitmentHash:    commitmentHash,
		Revision:          revision,
		SupersedesBatchID: supersedesBatchID,
	}
	request.PayloadHash = protocol.Digest(protocol.QualifiedMAUPayload(
		request.Period,
		request.RulesetVersion,
		request.QualifiedMAUCount,
		request.CommitmentHash,
		request.Revision,
		request.SupersedesBatchID,
	))
	resignQualifiedMAU(privateKey, &request)
	return request
}

func resignQualifiedMAU(
	privateKey ed25519.PrivateKey,
	request *protocol.BatchRequest,
) {
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
}

func verifyQualifiedMAUReceipt(
	t *testing.T,
	request protocol.BatchRequest,
	response protocol.BatchResponse,
) {
	t.Helper()
	receipt := response.Receipt
	if receipt.Kind != protocol.QualifiedMAUKind ||
		receipt.Period != request.Period ||
		receipt.RulesetVersion != request.RulesetVersion ||
		receipt.QualifiedMAUCount != request.QualifiedMAUCount ||
		receipt.CommitmentHash != request.CommitmentHash ||
		receipt.Revision != request.Revision ||
		receipt.SupersedesBatchID != request.SupersedesBatchID {
		t.Fatalf("QMAU receipt omitted or changed canonical fields: %+v", receipt)
	}
	registryPublicKey, _, err := protocol.ParsePublicKey(
		receipt.RegistryPublicKey,
	)
	if err != nil {
		t.Fatalf("parse QMAU receipt registry key: %v", err)
	}
	signature, err := protocol.ParseSignature(receipt.Signature)
	if err != nil {
		t.Fatalf("parse QMAU receipt signature: %v", err)
	}
	if !protocol.Verify(
		registryPublicKey,
		protocol.QualifiedMAUReceiptMessage(
			response.ProtocolVersion,
			response.RegistryScope,
			response.BatchID,
			response.DeploymentID,
			receipt.LedgerIndex,
			receipt.EntryHash,
			receipt.PreviousEntryHash,
			receipt.BatchHash,
			receipt.Period,
			receipt.RulesetVersion,
			receipt.QualifiedMAUCount,
			receipt.CommitmentHash,
			receipt.Revision,
			receipt.SupersedesBatchID,
			receipt.AcceptedAt,
			receipt.CheckpointDate,
			receipt.RegistryKeyID,
		),
		signature,
	) {
		t.Fatal("QMAU registry receipt signature verification failed")
	}
}
