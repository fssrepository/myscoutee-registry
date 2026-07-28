package httpapi_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
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

func TestSignedRevenueBatchesCorrectionsReceiptsAndGlobalPool(t *testing.T) {
	directory := t.TempDir()
	clock := &mutableClock{
		value: time.Date(2026, 7, 28, 14, 0, 0, 0, time.UTC),
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
	server := httptest.NewServer(httpapi.New(runtime.Service, httpapi.Options{
		MaxRequestBodyBytes: cfg.MaxRequestBodyBytes,
	}))
	defer server.Close()

	deployments := make([]struct {
		id         string
		privateKey ed25519.PrivateKey
	}, 0, 2)
	for index := 1; index <= 2; index++ {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate deployment key: %v", err)
		}
		registration := signedRegistration(
			t,
			privateKey,
			"2026-07-28T14:00:00Z",
			fmt.Sprintf("nonce_revenue_registration_%02d", index),
			fmt.Sprintf("revenue_registration_%04d", index),
			"test-revenue-1.0.0",
		)
		status, body := jsonRequest(
			t,
			http.MethodPost,
			server.URL+protocol.RegistrationPath,
			registration,
		)
		if status != http.StatusCreated {
			t.Fatalf("registration %d status = %d, body = %s", index, status, body)
		}
		var response protocol.RegistrationResponse
		decodeResponse(t, body, &response)
		deployments = append(deployments, struct {
			id         string
			privateKey ed25519.PrivateKey
		}{
			id:         response.DeploymentID,
			privateKey: privateKey,
		})
	}

	period := "2026-07-27"
	firstResponses := make([]protocol.RevenueBatchResponse, 0, 2)
	for index, deployment := range deployments {
		request := signedRevenueBatch(
			t,
			deployment.privateKey,
			deployment.id,
			"2026-07-28T14:00:01Z",
			fmt.Sprintf("nonce_revenue_batch_%04d", index+1),
			fmt.Sprintf("revenue_batch_%08d", index+1),
			period,
			1,
			"",
			[]protocol.RevenueCurrency{
				revenueCurrency("EUR", 19, 0, 1),
			},
		)
		status, body := jsonRequest(
			t,
			http.MethodPost,
			server.URL+protocol.RevenueBatchPath,
			request,
		)
		if status != http.StatusCreated {
			t.Fatalf("revenue batch %d status = %d, body = %s", index, status, body)
		}
		var response protocol.RevenueBatchResponse
		decodeResponse(t, body, &response)
		verifyRevenueReceipt(t, request, response)
		firstResponses = append(firstResponses, response)
	}

	summary, err := runtime.Service.RevenueSummary(
		context.Background(),
		period,
		"EUR",
		"",
		"",
	)
	if err != nil {
		t.Fatalf("query global revenue summary: %v", err)
	}
	if summary.NetMinor != 38 ||
		summary.NetworkCommissionPoolMinor != 1 ||
		summary.ReportedEstimatedCommissionMinor != 0 ||
		summary.ActiveBatchCount != 2 ||
		summary.CurrencyBatchCount != 2 {
		t.Fatalf("unexpected global revenue summary: %+v", summary)
	}

	first := signedRevenueBatch(
		t,
		deployments[0].privateKey,
		deployments[0].id,
		"2026-07-28T14:00:01Z",
		"nonce_revenue_duplicate_01",
		"revenue_batch_00000001",
		period,
		1,
		"",
		[]protocol.RevenueCurrency{
			revenueCurrency("EUR", 19, 0, 1),
		},
	)
	status, body := jsonRequest(
		t,
		http.MethodPost,
		server.URL+protocol.RevenueBatchPath,
		first,
	)
	if status != http.StatusOK {
		t.Fatalf("duplicate revenue batch status = %d, body = %s", status, body)
	}
	var duplicate protocol.RevenueBatchResponse
	decodeResponse(t, body, &duplicate)
	expectedDuplicate := firstResponses[0]
	expectedDuplicate.Duplicate = true
	if !reflect.DeepEqual(duplicate, expectedDuplicate) {
		t.Fatalf("duplicate revenue receipt changed:\nwant %+v\n got %+v", expectedDuplicate, duplicate)
	}

	correction := signedRevenueBatch(
		t,
		deployments[0].privateKey,
		deployments[0].id,
		"2026-07-28T14:00:02Z",
		"nonce_revenue_correction_01",
		"revenue_correction_000001",
		period,
		2,
		firstResponses[0].BatchID,
		[]protocol.RevenueCurrency{
			revenueCurrency("EUR", 100, 20, 2),
		},
	)
	status, body = jsonRequest(
		t,
		http.MethodPost,
		server.URL+protocol.RevenueBatchPath,
		correction,
	)
	if status != http.StatusCreated {
		t.Fatalf("revenue correction status = %d, body = %s", status, body)
	}
	var correctionResponse protocol.RevenueBatchResponse
	decodeResponse(t, body, &correctionResponse)
	verifyRevenueReceipt(t, correction, correctionResponse)

	stale := correction
	stale.Nonce = "nonce_revenue_stale_0001"
	stale.IdempotencyKey = "revenue_stale_revision_01"
	resignRevenueBatch(deployments[0].privateKey, &stale)
	status, body = jsonRequest(
		t,
		http.MethodPost,
		server.URL+protocol.RevenueBatchPath,
		stale,
	)
	assertAPIError(
		t,
		status,
		body,
		http.StatusConflict,
		"revenue_revision_conflict",
	)

	status, body = rawRequest(
		t,
		http.MethodGet,
		server.URL+protocol.RevenueBatchPath+"/"+correctionResponse.BatchID+"/receipt",
		nil,
		false,
	)
	if status != http.StatusOK {
		t.Fatalf("revenue receipt lookup status = %d, body = %s", status, body)
	}
	var lookedUp protocol.RevenueBatchResponse
	decodeResponse(t, body, &lookedUp)
	expectedLookup := correctionResponse
	expectedLookup.Duplicate = true
	if !reflect.DeepEqual(lookedUp, expectedLookup) {
		t.Fatalf("revenue receipt lookup changed the immutable result")
	}

	emptyPeriod := "2026-07-26"
	empty := signedRevenueBatch(
		t,
		deployments[0].privateKey,
		deployments[0].id,
		"2026-07-28T14:00:03Z",
		"nonce_revenue_empty_0001",
		"revenue_empty_batch_0001",
		emptyPeriod,
		1,
		"",
		[]protocol.RevenueCurrency{},
	)
	status, body = jsonRequest(
		t,
		http.MethodPost,
		server.URL+protocol.RevenueBatchPath,
		empty,
	)
	if status != http.StatusCreated {
		t.Fatalf("empty revenue batch status = %d, body = %s", status, body)
	}
	emptySummary, err := runtime.Service.RevenueSummary(
		context.Background(),
		emptyPeriod,
		"USD",
		"",
		"",
	)
	if err != nil {
		t.Fatalf("query empty revenue summary: %v", err)
	}
	if emptySummary.ActiveBatchCount != 1 ||
		emptySummary.CurrencyBatchCount != 0 ||
		emptySummary.DeploymentCount != 1 ||
		emptySummary.FractionDigits != 2 ||
		emptySummary.NetworkCommissionPoolMinor != 0 {
		t.Fatalf("explicit zero-revenue day was not preserved: %+v", emptySummary)
	}
}

func revenueCurrency(
	code string,
	capturedMinor int64,
	refundedMinor int64,
	paymentCount int64,
) protocol.RevenueCurrency {
	fractionDigits, _ := protocol.ISO4217FractionDigits(code)
	netMinor := capturedMinor - refundedMinor
	return protocol.RevenueCurrency{
		CurrencyCode:             code,
		FractionDigits:           fractionDigits,
		CapturedMinor:            capturedMinor,
		RefundedMinor:            refundedMinor,
		NetMinor:                 netMinor,
		CommissionBasisMinor:     netMinor,
		EstimatedCommissionMinor: protocol.RevenueCommissionMinor(netMinor),
		PaymentCount:             paymentCount,
	}
}

func signedRevenueBatch(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	deploymentID string,
	timestamp string,
	nonce string,
	idempotencyKey string,
	period string,
	revision int64,
	supersedesBatchID string,
	currencies []protocol.RevenueCurrency,
) protocol.RevenueBatchRequest {
	t.Helper()
	request := protocol.RevenueBatchRequest{
		ProtocolVersion:           protocol.Version,
		RegistryScope:             testRegistryScope,
		DeploymentID:              deploymentID,
		Timestamp:                 timestamp,
		Nonce:                     nonce,
		IdempotencyKey:            idempotencyKey,
		Kind:                      protocol.RevenueKind,
		Period:                    period,
		Revision:                  revision,
		SupersedesBatchID:         supersedesBatchID,
		RulesetVersion:            protocol.RevenueRulesetVersion,
		CommissionRateBasisPoints: protocol.RevenueCommissionBasisPoints,
		Currencies:                currencies,
	}
	request.PayloadHash = protocol.Digest(protocol.RevenuePayload(
		request.Kind,
		request.Period,
		request.Revision,
		request.SupersedesBatchID,
		request.RulesetVersion,
		request.CommissionRateBasisPoints,
		request.Currencies,
	))
	resignRevenueBatch(privateKey, &request)
	return request
}

func resignRevenueBatch(
	privateKey ed25519.PrivateKey,
	request *protocol.RevenueBatchRequest,
) {
	request.Signature = protocol.EncodeSignature(ed25519.Sign(
		privateKey,
		protocol.CanonicalRequest(
			http.MethodPost,
			protocol.RevenueBatchPath,
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

func verifyRevenueReceipt(
	t *testing.T,
	request protocol.RevenueBatchRequest,
	response protocol.RevenueBatchResponse,
) {
	t.Helper()
	receipt := response.Receipt
	entry := protocol.LedgerEntry{
		ProtocolVersion:   response.ProtocolVersion,
		RegistryScope:     response.RegistryScope,
		LedgerIndex:       receipt.LedgerIndex,
		EntryType:         protocol.RevenueEntryType,
		DeploymentID:      response.DeploymentID,
		BatchID:           response.BatchID,
		Kind:              receipt.Kind,
		Period:            receipt.Period,
		RulesetVersion:    receipt.RulesetVersion,
		QualifiedMAUCount: 0,
		BatchHash:         receipt.BatchHash,
		PreviousEntryHash: receipt.PreviousEntryHash,
		AcceptedAt:        receipt.AcceptedAt,
	}
	if receipt.BatchHash != request.PayloadHash ||
		receipt.EntryHash != protocol.Digest(protocol.LedgerEntryMessage(entry)) {
		t.Fatalf("revenue receipt does not commit the accepted ledger entry: %+v", receipt)
	}
	registryPublicKey, _, err := protocol.ParsePublicKey(receipt.RegistryPublicKey)
	if err != nil {
		t.Fatalf("parse revenue receipt registry public key: %v", err)
	}
	signature, err := protocol.ParseSignature(receipt.Signature)
	if err != nil {
		t.Fatalf("parse revenue receipt signature: %v", err)
	}
	if !protocol.Verify(
		registryPublicKey,
		protocol.RevenueReceiptMessage(
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
			receipt.Revision,
			receipt.SupersedesBatchID,
			receipt.RulesetVersion,
			receipt.CommissionRateBasisPoints,
			receipt.CurrencyCount,
			receipt.AcceptedAt,
			receipt.CheckpointDate,
			receipt.RegistryKeyID,
		),
		signature,
	) {
		t.Fatalf("revenue receipt signature verification failed")
	}
}
