package httpapi_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/service"
)

func TestSettlementCalculationAndSignedHistoricalBeneficiaryQuery(t *testing.T) {
	fixture := newOperatorAPIFixture(t)
	source := fixture.registerDeployment(t, "settlement-source")
	laterMember := fixture.registerDeployment(t, "settlement-later-member")

	claimDraft := operatorClaimRequest("Settlement Cooperative")
	claimDraft.Nonce = "nonce_settlement_claim_0001"
	claimDraft.IdempotencyKey = "settlement_claim_0001"
	claim := fixture.acceptOperatorAction(
		t,
		fixture.operatorAction(t, source, claimDraft),
		http.StatusCreated,
	)
	if _, err := fixture.runtime.Service.ApproveOperatorClaim(
		context.Background(),
		service.OperatorClaimApproval{
			DeploymentID:    source.id,
			ClaimActionID:   claim.Receipt.ActionID,
			GroupID:         claim.Receipt.GroupID,
			LegalName:       claimDraft.LegalName,
			ReviewerID:      "settlement-reviewer",
			ReviewReference: "case:settlement-source",
			IdempotencyKey:  "approve_settlement_source",
		},
	); err != nil {
		t.Fatalf("approve settlement source claim: %v", err)
	}

	qmau := signedQualifiedMAU(
		t,
		source.privateKey,
		source.id,
		fixture.now.Format("2006-01-02T15:04:05Z07:00"),
		"nonce_settlement_qmau_0001",
		"settlement_qmau_0001",
		"2026-06",
		600_000,
		protocol.Digest([]byte("settlement-private-qmau-evidence")),
		1,
		"",
	)
	status, body := jsonRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.BatchPath,
		qmau,
	)
	if status != http.StatusCreated {
		t.Fatalf("settlement QMAU status = %d, body = %s", status, body)
	}

	revenue := signedRevenueBatch(
		t,
		source.privateKey,
		source.id,
		fixture.now.Format("2006-01-02T15:04:05Z07:00"),
		"nonce_settlement_revenue_0001",
		"settlement_revenue_0001",
		"2026-06-30",
		1,
		"",
		[]protocol.RevenueCurrency{
			revenueCurrency("USD", 10_000, 0, 1),
		},
	)
	status, body = jsonRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.RevenueBatchPath,
		revenue,
	)
	if status != http.StatusCreated {
		t.Fatalf("settlement revenue status = %d, body = %s", status, body)
	}

	calculated, err := fixture.runtime.Service.CalculateSettlement(
		context.Background(),
		"2026-06",
		"USD",
	)
	if err != nil {
		t.Fatalf("calculate settlement: %v", err)
	}
	if calculated.Duplicate {
		t.Fatal("first settlement calculation reported a duplicate")
	}
	receipt := calculated.Receipt
	if receipt.NetworkCommissionPoolMinor != 500 ||
		receipt.TTMCommissionBasisMinor != 10_000 ||
		receipt.RecentThreeMonthAverageMinor != 3_333 ||
		receipt.ValuationAdjustmentBasisPoints != 2_500 ||
		receipt.EffectiveValuationMultiplierBasisPoints != 37_500 ||
		receipt.IndicativeNetworkValueMinor != 37_500 ||
		!receipt.ValuationIsNonBinding ||
		len(receipt.Allocations) != 2 {
		t.Fatalf("unexpected settlement receipt: %+v", receipt)
	}
	var allocatedPool, allocatedValue int64
	for _, allocation := range receipt.Allocations {
		allocatedPool += allocation.NetworkPoolAllocationMinor
		allocatedValue += allocation.IndicativeValueAllocationMinor
	}
	if allocatedPool != receipt.NetworkCommissionPoolMinor ||
		allocatedValue != receipt.IndicativeNetworkValueMinor {
		t.Fatalf(
			"settlement allocations do not conserve totals: pool %d/%d, value %d/%d",
			allocatedPool,
			receipt.NetworkCommissionPoolMinor,
			allocatedValue,
			receipt.IndicativeNetworkValueMinor,
		)
	}
	verifySettlementReceipt(t, receipt)

	duplicate, err := fixture.runtime.Service.CalculateSettlement(
		context.Background(),
		"2026-06",
		"USD",
	)
	if err != nil {
		t.Fatalf("recalculate unchanged settlement: %v", err)
	}
	if !duplicate.Duplicate ||
		duplicate.Receipt.SettlementID != receipt.SettlementID {
		t.Fatalf("unchanged settlement did not return its immutable revision")
	}

	sourceQuery := signedSettlementQuery(
		source,
		fixture.now.Format("2006-01-02T15:04:05Z07:00"),
		"nonce_settlement_query_source",
		"settlement_query_source",
	)
	sourceResponse := requestSettlementHistory(
		t,
		fixture,
		sourceQuery,
		http.StatusOK,
	)
	if len(sourceResponse.Items) != 1 ||
		sourceResponse.Items[0].BeneficiaryType !=
			protocol.SettlementBeneficiaryOperator ||
		sourceResponse.Items[0].BeneficiaryID != claim.Receipt.GroupID {
		t.Fatalf("source settlement history = %+v", sourceResponse.Items)
	}
	verifySettlementHistoryResponse(t, fixture, sourceQuery, sourceResponse)

	issued := fixture.acceptOperatorAction(
		t,
		fixture.operatorAction(
			t,
			source,
			protocol.OperatorActionRequest{
				Nonce:           "nonce_settlement_issue_client_code",
				IdempotencyKey:  "settlement_issue_client_code",
				Action:          protocol.OperatorActionIssueClientToken,
				TokenTTLSeconds: 300,
			},
		),
		http.StatusCreated,
	)
	redeemed := fixture.acceptOperatorAction(
		t,
		fixture.operatorAction(
			t,
			laterMember,
			protocol.OperatorActionRequest{
				Nonce:          "nonce_settlement_redeem_client_code",
				IdempotencyKey: "settlement_redeem_client_code",
				Action:         protocol.OperatorActionRedeemClientToken,
				ClientToken:    issued.Receipt.ClientToken,
			},
		),
		http.StatusCreated,
	)
	if _, err := fixture.runtime.Service.ApproveOperatorClaim(
		context.Background(),
		service.OperatorClaimApproval{
			DeploymentID:    laterMember.id,
			ClaimActionID:   redeemed.Receipt.ActionID,
			GroupID:         claim.Receipt.GroupID,
			LegalName:       claimDraft.LegalName,
			ReviewerID:      "settlement-reviewer",
			ReviewReference: "case:settlement-later-member",
			IdempotencyKey:  "approve_settlement_later_member",
		},
	); err != nil {
		t.Fatalf("approve later settlement member: %v", err)
	}

	laterQuery := signedSettlementQuery(
		laterMember,
		fixture.now.Format("2006-01-02T15:04:05Z07:00"),
		"nonce_settlement_query_later",
		"settlement_query_later",
	)
	laterResponse := requestSettlementHistory(
		t,
		fixture,
		laterQuery,
		http.StatusOK,
	)
	if len(laterResponse.Items) != 0 {
		t.Fatalf(
			"later group member received pre-membership settlement history: %+v",
			laterResponse.Items,
		)
	}
	verifySettlementHistoryResponse(t, fixture, laterQuery, laterResponse)

	if err := fixture.runtime.Service.VerifyState(context.Background()); err != nil {
		t.Fatalf("verify full registry state with settlement: %v", err)
	}
}

func signedSettlementQuery(
	deployment operatorDeployment,
	timestamp string,
	nonce string,
	queryID string,
) protocol.SettlementQueryRequest {
	request := protocol.SettlementQueryRequest{
		ProtocolVersion: protocol.Version,
		RegistryScope:   testRegistryScope,
		DeploymentID:    deployment.id,
		Timestamp:       timestamp,
		Nonce:           nonce,
		QueryID:         queryID,
		CurrencyCode:    "USD",
		FromPeriod:      "2026-06",
		ThroughPeriod:   "2026-06",
		Limit:           20,
	}
	request.PayloadHash = protocol.Digest(
		protocol.SettlementQueryPayload(request),
	)
	request.Signature = protocol.EncodeSignature(ed25519.Sign(
		deployment.privateKey,
		protocol.CanonicalRequest(
			http.MethodPost,
			protocol.SettlementQueryPath,
			request.ProtocolVersion,
			request.RegistryScope,
			request.DeploymentID,
			request.Timestamp,
			request.Nonce,
			request.QueryID,
			request.PayloadHash,
		),
	))
	return request
}

func requestSettlementHistory(
	t *testing.T,
	fixture *operatorAPIFixture,
	request protocol.SettlementQueryRequest,
	wantStatus int,
) protocol.SettlementQueryResponse {
	t.Helper()
	status, body := jsonRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.SettlementQueryPath,
		request,
	)
	if status != wantStatus {
		t.Fatalf(
			"settlement query status = %d, want %d; body = %s",
			status,
			wantStatus,
			body,
		)
	}
	var response protocol.SettlementQueryResponse
	decodeResponse(t, body, &response)
	return response
}

func verifySettlementReceipt(
	t *testing.T,
	receipt protocol.SettlementReceipt,
) {
	t.Helper()
	publicKey, _, err := protocol.ParsePublicKey(receipt.RegistryPublicKey)
	if err != nil {
		t.Fatalf("parse settlement registry public key: %v", err)
	}
	signature, err := protocol.ParseSignature(receipt.Signature)
	if err != nil {
		t.Fatalf("parse settlement receipt signature: %v", err)
	}
	if receipt.SettlementHash != protocol.Digest(
		protocol.SettlementHashMessage(receipt),
	) || !protocol.Verify(
		publicKey,
		protocol.SettlementReceiptMessage(receipt),
		signature,
	) {
		t.Fatal("settlement hash or receipt signature verification failed")
	}
}

func verifySettlementHistoryResponse(
	t *testing.T,
	fixture *operatorAPIFixture,
	request protocol.SettlementQueryRequest,
	response protocol.SettlementQueryResponse,
) {
	t.Helper()
	requestMessage := protocol.CanonicalRequest(
		http.MethodPost,
		protocol.SettlementQueryPath,
		request.ProtocolVersion,
		request.RegistryScope,
		request.DeploymentID,
		request.Timestamp,
		request.Nonce,
		request.QueryID,
		request.PayloadHash,
	)
	if response.QueryHash != protocol.Digest(requestMessage) ||
		response.ItemsHash != protocol.SettlementHistoryItemsHash(
			response.Items,
		) {
		t.Fatalf("settlement query response hashes are invalid: %+v", response)
	}
	signature, err := protocol.ParseSignature(response.Signature)
	if err != nil {
		t.Fatalf("parse settlement query response signature: %v", err)
	}
	if !protocol.Verify(
		fixture.runtime.SigningKey.PublicKey(),
		protocol.SettlementQueryResponseMessage(response),
		signature,
	) {
		t.Fatal("settlement query response signature verification failed")
	}
}
