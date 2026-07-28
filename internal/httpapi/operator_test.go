package httpapi_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/app"
	"github.com/fssrepository/myscoutee-registry/internal/config"
	"github.com/fssrepository/myscoutee-registry/internal/httpapi"
	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/service"
	_ "modernc.org/sqlite"
)

type operatorAPIFixture struct {
	now     time.Time
	clock   *mutableClock
	ids     *sequentialIDs
	cfg     config.Config
	runtime *app.Runtime
	server  *httptest.Server
}

type operatorDeployment struct {
	id         string
	privateKey ed25519.PrivateKey
}

func TestSignedOperatorActionsAndLeaderboard(t *testing.T) {
	fixture := newOperatorAPIFixture(t)
	alpha := fixture.registerDeployment(t, "alpha")
	beta := fixture.registerDeployment(t, "beta")
	charlie := fixture.registerDeployment(t, "charlie")
	delta := fixture.registerDeployment(t, "delta")
	echo := fixture.registerDeployment(t, "echo")

	alphaClaimDraft := operatorClaimRequest("Alpha Cooperative")
	alphaClaimDraft.Nonce = "nonce_operator_alpha_claim_01"
	alphaClaimDraft.IdempotencyKey = "operator_alpha_claim_01"
	alphaClaimDraft.OperatorAvatarURL = "https://example.test/alpha.png"
	alphaClaim := fixture.operatorAction(t, alpha, alphaClaimDraft)
	invalidClaim := alphaClaim
	resignOperatorAction(t, beta.privateKey, &invalidClaim)
	status, body := jsonRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.OperatorActionPath,
		invalidClaim,
	)
	assertAPIError(t, status, body, http.StatusUnauthorized, "invalid_signature")

	alphaClaimResponse := fixture.acceptOperatorAction(
		t,
		alphaClaim,
		http.StatusCreated,
	)
	assertOperatorReceipt(
		t,
		fixture,
		alphaClaim,
		alphaClaimResponse.Receipt,
		1,
		protocol.OperatorAuditZeroHash,
	)
	if alphaClaimResponse.Duplicate ||
		alphaClaimResponse.Receipt.ClaimState != protocol.OperatorClaimStatePendingReview ||
		alphaClaimResponse.Receipt.GroupID == "" {
		t.Fatalf("unexpected alpha claim response: %+v", alphaClaimResponse)
	}
	alphaGroupID := alphaClaimResponse.Receipt.GroupID
	if _, err := fixture.runtime.Service.ApproveOperatorClaim(
		context.Background(),
		service.OperatorClaimApproval{
			DeploymentID:    alpha.id,
			ClaimActionID:   alphaClaimResponse.Receipt.ActionID,
			GroupID:         alphaGroupID,
			LegalName:       alphaClaimDraft.LegalName,
			ReviewerID:      "network-review-team",
			ReviewReference: "case:operator-alpha",
			IdempotencyKey:  "approve_operator_alpha",
		},
	); err != nil {
		t.Fatalf("approve alpha operator claim: %v", err)
	}

	alphaClaimRetry := alphaClaim
	alphaClaimRetry.Nonce = "nonce_operator_alpha_claim_02"
	resignOperatorAction(t, alpha.privateKey, &alphaClaimRetry)
	alphaClaimDuplicate := fixture.acceptOperatorAction(
		t,
		alphaClaimRetry,
		http.StatusOK,
	)
	if !alphaClaimDuplicate.Duplicate ||
		alphaClaimDuplicate.Receipt != alphaClaimResponse.Receipt {
		t.Fatalf(
			"idempotent claim did not return the original receipt: first=%+v retry=%+v",
			alphaClaimResponse,
			alphaClaimDuplicate,
		)
	}

	idempotencyConflict := alphaClaim
	idempotencyConflict.Nonce = "nonce_operator_alpha_claim_03"
	idempotencyConflict.LegalName = "Changed Alpha"
	signOperatorActionPayload(t, alpha.privateKey, &idempotencyConflict)
	status, body = jsonRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.OperatorActionPath,
		idempotencyConflict,
	)
	assertAPIError(t, status, body, http.StatusConflict, "idempotency_conflict")

	replayConflict := alphaClaim
	replayConflict.IdempotencyKey = "operator_alpha_claim_replay"
	resignOperatorAction(t, alpha.privateKey, &replayConflict)
	status, body = jsonRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.OperatorActionPath,
		replayConflict,
	)
	assertAPIError(t, status, body, http.StatusConflict, "replay_conflict")

	previousAuditHash := alphaClaimResponse.Receipt.AuditHash
	nextAuditIndex := int64(2)
	claim := func(
		deployment operatorDeployment,
		name string,
		suffix string,
	) protocol.OperatorActionResponse {
		t.Helper()
		draft := operatorClaimRequest(name)
		draft.Nonce = "nonce_operator_" + suffix + "_claim"
		draft.IdempotencyKey = "operator_" + suffix + "_claim"
		request := fixture.operatorAction(t, deployment, draft)
		response := fixture.acceptOperatorAction(t, request, http.StatusCreated)
		assertOperatorReceipt(
			t,
			fixture,
			request,
			response.Receipt,
			nextAuditIndex,
			previousAuditHash,
		)
		nextAuditIndex++
		previousAuditHash = response.Receipt.AuditHash
		return response
	}
	betaClaimResponse := claim(beta, "Beta Forum", "beta")
	charlieClaimResponse := claim(charlie, "Charlie Board", "charlie")
	deltaClaimResponse := claim(delta, "Delta Community", "delta")

	revokedTokenRequest := fixture.operatorAction(t, alpha, protocol.OperatorActionRequest{
		Nonce:           "nonce_operator_token_revoked_01",
		IdempotencyKey:  "operator_token_revoked_01",
		Action:          protocol.OperatorActionIssueClientToken,
		TokenTTLSeconds: 600,
	})
	revokedTokenResponse := fixture.acceptOperatorAction(
		t,
		revokedTokenRequest,
		http.StatusCreated,
	)
	assertOperatorReceipt(
		t,
		fixture,
		revokedTokenRequest,
		revokedTokenResponse.Receipt,
		nextAuditIndex,
		previousAuditHash,
	)
	nextAuditIndex++
	previousAuditHash = revokedTokenResponse.Receipt.AuditHash
	assertIssuedClientToken(t, fixture, revokedTokenResponse)

	revokedTokenRetry := revokedTokenRequest
	revokedTokenRetry.Nonce = "nonce_operator_token_revoked_02"
	resignOperatorAction(t, alpha.privateKey, &revokedTokenRetry)
	duplicateTokenResponse := fixture.acceptOperatorAction(
		t,
		revokedTokenRetry,
		http.StatusOK,
	)
	if !duplicateTokenResponse.Duplicate ||
		duplicateTokenResponse.Receipt.ClientToken != "" ||
		duplicateTokenResponse.Receipt.TokenID != revokedTokenResponse.Receipt.TokenID {
		t.Fatalf(
			"token issue retry must return the receipt without re-exposing the secret: %+v",
			duplicateTokenResponse,
		)
	}

	revokeTokenRequest := fixture.operatorAction(t, alpha, protocol.OperatorActionRequest{
		Nonce:          "nonce_operator_revoke_token_01",
		IdempotencyKey: "operator_revoke_token_01",
		Action:         protocol.OperatorActionRevokeClientToken,
		TokenID:        revokedTokenResponse.Receipt.TokenID,
	})
	revokeTokenResponse := fixture.acceptOperatorAction(
		t,
		revokeTokenRequest,
		http.StatusCreated,
	)
	assertOperatorReceipt(
		t,
		fixture,
		revokeTokenRequest,
		revokeTokenResponse.Receipt,
		nextAuditIndex,
		previousAuditHash,
	)
	nextAuditIndex++
	previousAuditHash = revokeTokenResponse.Receipt.AuditHash

	redeemRevoked := fixture.operatorAction(t, beta, protocol.OperatorActionRequest{
		Nonce:          "nonce_operator_redeem_revoked",
		IdempotencyKey: "operator_redeem_revoked",
		Action:         protocol.OperatorActionRedeemClientToken,
		ClientToken:    revokedTokenResponse.Receipt.ClientToken,
	})
	status, body = jsonRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.OperatorActionPath,
		redeemRevoked,
	)
	assertAPIError(t, status, body, http.StatusConflict, "client_token_revoked")

	activeTokenRequest := fixture.operatorAction(t, alpha, protocol.OperatorActionRequest{
		Nonce:           "nonce_operator_token_active_01",
		IdempotencyKey:  "operator_token_active_01",
		Action:          protocol.OperatorActionIssueClientToken,
		TokenTTLSeconds: 900,
	})
	activeTokenResponse := fixture.acceptOperatorAction(
		t,
		activeTokenRequest,
		http.StatusCreated,
	)
	assertOperatorReceipt(
		t,
		fixture,
		activeTokenRequest,
		activeTokenResponse.Receipt,
		nextAuditIndex,
		previousAuditHash,
	)
	nextAuditIndex++
	previousAuditHash = activeTokenResponse.Receipt.AuditHash
	assertIssuedClientToken(t, fixture, activeTokenResponse)

	redeemRequest := fixture.operatorAction(t, beta, protocol.OperatorActionRequest{
		Nonce:          "nonce_operator_redeem_active",
		IdempotencyKey: "operator_redeem_active",
		Action:         protocol.OperatorActionRedeemClientToken,
		ClientToken:    activeTokenResponse.Receipt.ClientToken,
	})
	redeemResponse := fixture.acceptOperatorAction(
		t,
		redeemRequest,
		http.StatusCreated,
	)
	assertOperatorReceipt(
		t,
		fixture,
		redeemRequest,
		redeemResponse.Receipt,
		nextAuditIndex,
		previousAuditHash,
	)
	nextAuditIndex++
	previousAuditHash = redeemResponse.Receipt.AuditHash
	if redeemResponse.Receipt.GroupID != alphaGroupID ||
		redeemResponse.Receipt.RelatedDeploymentID != alpha.id ||
		redeemResponse.Receipt.LinkID == "" {
		t.Fatalf("redeem did not join beta to alpha's group: %+v", redeemResponse)
	}

	revokeActiveTokenRequest := fixture.operatorAction(
		t,
		alpha,
		protocol.OperatorActionRequest{
			Nonce:          "nonce_operator_revoke_token_02",
			IdempotencyKey: "operator_revoke_token_02",
			Action:         protocol.OperatorActionRevokeClientToken,
			TokenID:        activeTokenResponse.Receipt.TokenID,
		},
	)
	revokeActiveTokenResponse := fixture.acceptOperatorAction(
		t,
		revokeActiveTokenRequest,
		http.StatusCreated,
	)
	assertOperatorReceipt(
		t,
		fixture,
		revokeActiveTokenRequest,
		revokeActiveTokenResponse.Receipt,
		nextAuditIndex,
		previousAuditHash,
	)
	nextAuditIndex++
	previousAuditHash = revokeActiveTokenResponse.Receipt.AuditHash

	redeemAfterRevocation := fixture.operatorAction(t, delta, protocol.OperatorActionRequest{
		Nonce:          "nonce_operator_redeem_after_revoke",
		IdempotencyKey: "operator_redeem_after_revoke",
		Action:         protocol.OperatorActionRedeemClientToken,
		ClientToken:    activeTokenResponse.Receipt.ClientToken,
	})
	status, body = jsonRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.OperatorActionPath,
		redeemAfterRevocation,
	)
	assertAPIError(t, status, body, http.StatusConflict, "client_token_revoked")

	claimedPage := fixture.leaderboard(t, "view=claimed&through_period=2026-06&limit=1")
	if len(claimedPage.Items) != 1 ||
		claimedPage.Items[0].GroupID != alphaGroupID ||
		claimedPage.Items[0].Label != "Alpha Cooperative" ||
		claimedPage.Items[0].AvatarURL != "https://example.test/alpha.png" ||
		claimedPage.Items[0].DeploymentCount != 2 ||
		claimedPage.Items[0].WeightNumerator != "0" ||
		claimedPage.Items[0].WeightDenominator != "1" ||
		claimedPage.NextCursor == "" {
		t.Fatalf("unexpected first claimed leaderboard page: %+v", claimedPage)
	}
	assertLeaderboardSnapshot(t, fixture, claimedPage.Snapshot)

	repeatedClaimedPage := fixture.leaderboard(
		t,
		"view=claimed&through_period=2026-06&limit=1",
	)
	if !reflect.DeepEqual(repeatedClaimedPage, claimedPage) {
		t.Fatalf(
			"unchanged leaderboard boundary did not produce a stable page:\nfirst=%+v\nsecond=%+v",
			claimedPage,
			repeatedClaimedPage,
		)
	}

	tamperedCursor := tamperCursor(claimedPage.NextCursor)
	status, body = rawRequest(
		t,
		http.MethodGet,
		fixture.server.URL+protocol.LeaderboardPath+
			"?view=claimed&limit=1&cursor="+url.QueryEscape(tamperedCursor),
		nil,
		false,
	)
	assertAPIError(t, status, body, http.StatusBadRequest, "invalid_cursor")

	status, body = rawRequest(
		t,
		http.MethodGet,
		fixture.server.URL+protocol.LeaderboardPath+
			"?view=unclaimed&limit=1&cursor="+
			url.QueryEscape(claimedPage.NextCursor),
		nil,
		false,
	)
	assertAPIError(t, status, body, http.StatusBadRequest, "invalid_cursor")

	groupPath := fixture.server.URL + "/v1/leaderboard/groups/" +
		alphaGroupID + "/deployments"
	groupPage := fixture.groupDeployments(t, groupPath, "through_period=2026-06&limit=1")
	if len(groupPage.Items) != 1 ||
		groupPage.Items[0].DeploymentID != alpha.id ||
		groupPage.Items[0].MembershipState != "owner" ||
		groupPage.NextCursor == "" {
		t.Fatalf("unexpected first group deployment page: %+v", groupPage)
	}
	assertLeaderboardSnapshot(t, fixture, groupPage.Snapshot)

	revokeLinkRequest := fixture.operatorAction(t, beta, protocol.OperatorActionRequest{
		Nonce:          "nonce_operator_revoke_link",
		IdempotencyKey: "operator_revoke_link",
		Action:         protocol.OperatorActionRevokeGroupLink,
		LinkID:         redeemResponse.Receipt.LinkID,
	})
	revokeLinkResponse := fixture.acceptOperatorAction(
		t,
		revokeLinkRequest,
		http.StatusCreated,
	)
	assertOperatorReceipt(
		t,
		fixture,
		revokeLinkRequest,
		revokeLinkResponse.Receipt,
		nextAuditIndex,
		previousAuditHash,
	)
	if revokeLinkResponse.Receipt.SubjectDeploymentID != beta.id ||
		revokeLinkResponse.Receipt.RelatedDeploymentID != alpha.id ||
		revokeLinkResponse.Receipt.GroupID != alphaGroupID {
		t.Fatalf("unexpected group-link revocation receipt: %+v", revokeLinkResponse)
	}

	oldGroupPageTwo := fixture.groupDeployments(
		t,
		groupPath,
		"limit=1&cursor="+url.QueryEscape(groupPage.NextCursor),
	)
	if oldGroupPageTwo.Snapshot != groupPage.Snapshot ||
		len(oldGroupPageTwo.Items) != 1 ||
		oldGroupPageTwo.Items[0].DeploymentID != beta.id ||
		oldGroupPageTwo.Items[0].MembershipState != "linked" {
		t.Fatalf(
			"signed group cursor did not preserve the pre-revocation snapshot: %+v",
			oldGroupPageTwo,
		)
	}

	oldClaimedGroups := []string{alphaGroupID}
	cursor := claimedPage.NextCursor
	for cursor != "" {
		page := fixture.leaderboard(
			t,
			"view=claimed&limit=1&cursor="+url.QueryEscape(cursor),
		)
		if page.Snapshot != claimedPage.Snapshot {
			t.Fatalf("cursor page changed immutable snapshot: %+v", page.Snapshot)
		}
		if len(page.Items) != 1 {
			t.Fatalf("cursor page item count = %d, want 1", len(page.Items))
		}
		oldClaimedGroups = append(oldClaimedGroups, page.Items[0].GroupID)
		cursor = page.NextCursor
	}
	expectedOldGroups := []string{
		alphaGroupID,
		charlieClaimResponse.Receipt.GroupID,
		deltaClaimResponse.Receipt.GroupID,
	}
	if !reflect.DeepEqual(oldClaimedGroups, expectedOldGroups) {
		t.Fatalf(
			"snapshot-pinned groups = %v, want %v",
			oldClaimedGroups,
			expectedOldGroups,
		)
	}

	freshClaimedPage := fixture.leaderboard(
		t,
		"view=claimed&through_period=2026-06&limit=10",
	)
	freshGroupIDs := leaderboardGroupIDs(freshClaimedPage.Items)
	expectedFreshGroups := []string{
		alphaGroupID,
		betaClaimResponse.Receipt.GroupID,
		charlieClaimResponse.Receipt.GroupID,
		deltaClaimResponse.Receipt.GroupID,
	}
	if !reflect.DeepEqual(freshGroupIDs, expectedFreshGroups) {
		t.Fatalf("fresh claimed groups = %v, want %v", freshGroupIDs, expectedFreshGroups)
	}
	if freshClaimedPage.Items[0].DeploymentCount != 1 ||
		freshClaimedPage.Items[1].Label != "Beta Forum" {
		t.Fatalf("revoked link did not restore separate operator rows: %+v", freshClaimedPage)
	}

	freshAlphaDeployments := fixture.groupDeployments(
		t,
		groupPath,
		"through_period=2026-06&limit=10",
	)
	if len(freshAlphaDeployments.Items) != 1 ||
		freshAlphaDeployments.Items[0].DeploymentID != alpha.id {
		t.Fatalf(
			"fresh alpha group still contains revoked deployment: %+v",
			freshAlphaDeployments,
		)
	}

	unclaimedPage := fixture.leaderboard(
		t,
		"view=unclaimed&through_period=2026-06&limit=10",
	)
	if len(unclaimedPage.Items) != 1 ||
		unclaimedPage.Items[0].RowID != echo.id ||
		unclaimedPage.Items[0].ClaimState != "unclaimed" {
		t.Fatalf("unexpected unclaimed leaderboard: %+v", unclaimedPage)
	}

	founderPage := fixture.leaderboard(
		t,
		"view=founder&through_period=2026-06&limit=10",
	)
	if len(founderPage.Items) != 1 ||
		founderPage.Items[0].RowID != "founder" ||
		founderPage.Items[0].ShareNumerator != "1" ||
		founderPage.Items[0].ShareDenominator != "1" {
		t.Fatalf("unexpected founder leaderboard: %+v", founderPage)
	}

	queryValidationCases := []struct {
		name string
		path string
		code string
	}{
		{
			name: "unsupported parameter",
			path: protocol.LeaderboardPath + "?sort=weight",
			code: "invalid_request",
		},
		{
			name: "repeated parameter",
			path: protocol.LeaderboardPath + "?view=claimed&view=unclaimed",
			code: "invalid_request",
		},
		{
			name: "invalid limit",
			path: protocol.LeaderboardPath + "?limit=0",
			code: "invalid_request",
		},
		{
			name: "invalid view",
			path: protocol.LeaderboardPath + "?view=verified",
			code: "invalid_request",
		},
		{
			name: "incomplete month",
			path: protocol.LeaderboardPath + "?through_period=2026-07",
			code: "invalid_request",
		},
		{
			name: "malformed cursor",
			path: protocol.LeaderboardPath + "?cursor=not-a-signed-cursor",
			code: "invalid_cursor",
		},
		{
			name: "malformed group",
			path: "/v1/leaderboard/groups/not-a-group/deployments",
			code: "invalid_request",
		},
		{
			name: "group view is unsupported",
			path: "/v1/leaderboard/groups/" + alphaGroupID +
				"/deployments?view=claimed",
			code: "invalid_request",
		},
	}
	for _, testCase := range queryValidationCases {
		t.Run("query validation/"+testCase.name, func(t *testing.T) {
			status, body := rawRequest(
				t,
				http.MethodGet,
				fixture.server.URL+testCase.path,
				nil,
				false,
			)
			assertAPIError(t, status, body, http.StatusBadRequest, testCase.code)
		})
	}

	if err := fixture.runtime.Service.VerifyState(context.Background()); err != nil {
		t.Fatalf("verify final operator and leaderboard state: %v", err)
	}
}

func TestOperatorAuditTamperingFailsClosed(t *testing.T) {
	testCases := []struct {
		name       string
		trigger    string
		statement  string
		wantDetail string
		approve    bool
	}{
		{
			name:       "private claim submission",
			trigger:    "operator_claim_verification_no_update",
			statement:  "UPDATE operator_claim_verification_submissions SET registered_address = 'Tampered address'",
			wantDetail: "private payload",
		},
		{
			name:       "audit hash",
			trigger:    "operator_audit_events_no_update",
			statement:  "UPDATE operator_audit_events SET audit_hash = '" + protocol.ZeroHash + "'",
			wantDetail: "audit hash verification failed",
		},
		{
			name:       "registry receipt",
			trigger:    "operator_audit_events_no_update",
			statement:  "UPDATE operator_audit_events SET receipt_signature = zeroblob(64)",
			wantDetail: "registry receipt verification failed",
		},
		{
			name:       "accepted nonce proof",
			trigger:    "operator_action_nonces_no_update",
			statement:  "UPDATE operator_action_nonces SET deployment_signature = zeroblob(64)",
			wantDetail: "request proof verification failed",
		},
		{
			name:       "signed review receipt",
			trigger:    "operator_claim_reviews_no_update",
			statement:  "UPDATE operator_claim_reviews SET signature = zeroblob(64)",
			wantDetail: "signature verification failed",
			approve:    true,
		},
		{
			name:       "direct claim status",
			statement:  "UPDATE operator_claim_status SET legal_name = 'Tampered legal name'",
			wantDetail: "direct operator claim status",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newOperatorAPIFixture(t)
			deployment := fixture.registerDeployment(t, "tamper")
			draft := operatorClaimRequest("Tamper Test Operator")
			draft.Nonce = "nonce_operator_tamper_claim"
			draft.IdempotencyKey = "operator_tamper_claim"
			request := fixture.operatorAction(t, deployment, draft)
			claim := fixture.acceptOperatorAction(t, request, http.StatusCreated)
			if testCase.approve {
				if _, err := fixture.runtime.Service.ApproveOperatorClaim(
					context.Background(),
					service.OperatorClaimApproval{
						DeploymentID:    deployment.id,
						ClaimActionID:   claim.Receipt.ActionID,
						GroupID:         claim.Receipt.GroupID,
						LegalName:       draft.LegalName,
						ReviewerID:      "tamper-reviewer",
						ReviewReference: "case:tamper-review",
						IdempotencyKey:  "approve_tamper_review_01",
					},
				); err != nil {
					t.Fatalf("approve claim before tamper: %v", err)
				}
			}

			tamperDatabase, err := sql.Open("sqlite", fixture.cfg.DatabasePath)
			if err != nil {
				t.Fatalf("open independent tamper-test connection: %v", err)
			}
			defer tamperDatabase.Close()
			if _, err := tamperDatabase.Exec("PRAGMA busy_timeout = 5000"); err != nil {
				t.Fatalf("set tamper-test busy timeout: %v", err)
			}
			if testCase.trigger != "" {
				if _, err := tamperDatabase.Exec("DROP TRIGGER " + testCase.trigger); err != nil {
					t.Fatalf("drop append-only trigger for corruption simulation: %v", err)
				}
			}
			if _, err := tamperDatabase.Exec(testCase.statement); err != nil {
				t.Fatalf("simulate operator audit corruption: %v", err)
			}

			err = fixture.runtime.Service.VerifyState(context.Background())
			if err == nil || !strings.Contains(err.Error(), testCase.wantDetail) {
				t.Fatalf(
					"operator corruption verification error = %v, want detail %q",
					err,
					testCase.wantDetail,
				)
			}
			status, body := rawRequest(
				t,
				http.MethodGet,
				fixture.server.URL+"/healthz",
				nil,
				false,
			)
			assertAPIError(
				t,
				status,
				body,
				http.StatusServiceUnavailable,
				"registry_unavailable",
			)
			status, body = rawRequest(
				t,
				http.MethodGet,
				fixture.server.URL+protocol.LeaderboardPath,
				nil,
				false,
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
}

func TestStructuredOperatorClaimValidationStatusApprovalAndPrivacy(t *testing.T) {
	fixture := newOperatorAPIFixture(t)
	deployment := fixture.registerDeployment(t, "structured-claim")

	invalidCases := []struct {
		name   string
		mutate func(*protocol.OperatorActionRequest)
	}{
		{
			name: "uppercase email",
			mutate: func(request *protocol.OperatorActionRequest) {
				request.VerificationContactEmail = "Review@example.test"
			},
		},
		{
			name: "http website",
			mutate: func(request *protocol.OperatorActionRequest) {
				request.Website = "http://operator.example.test"
			},
		},
		{
			name: "missing website",
			mutate: func(request *protocol.OperatorActionRequest) {
				request.Website = ""
			},
		},
		{
			name: "false authority attestation",
			mutate: func(request *protocol.OperatorActionRequest) {
				request.AuthorityAttested = false
			},
		},
	}
	for index, testCase := range invalidCases {
		t.Run(testCase.name, func(t *testing.T) {
			draft := operatorClaimRequest("Structured Cooperative")
			draft.Nonce = fmt.Sprintf("nonce_invalid_structured_claim_%02d", index)
			draft.IdempotencyKey = fmt.Sprintf("invalid_structured_claim_%02d", index)
			testCase.mutate(&draft)
			request := fixture.operatorAction(t, deployment, draft)
			status, body := jsonRequest(
				t,
				http.MethodPost,
				fixture.server.URL+protocol.OperatorActionPath,
				request,
			)
			assertAPIError(t, status, body, http.StatusBadRequest, "invalid_request")
		})
	}

	draft := operatorClaimRequest("Structured Cooperative")
	draft.Nonce = "nonce_structured_claim_valid"
	draft.IdempotencyKey = "structured_claim_valid"
	request := fixture.operatorAction(t, deployment, draft)
	claim := fixture.acceptOperatorAction(t, request, http.StatusCreated)

	status, body := rawRequest(
		t,
		http.MethodGet,
		fixture.server.URL+protocol.OperatorClaimStatusPathPrefix+deployment.id,
		nil,
		false,
	)
	if status != http.StatusOK {
		t.Fatalf("claim status = %d, body = %s", status, body)
	}
	for _, privateValue := range []string{
		draft.RegisteredAddress,
		draft.VerificationContactName,
		draft.VerificationContactEmail,
	} {
		if strings.Contains(string(body), privateValue) {
			t.Fatalf("public claim status exposed private value %q: %s", privateValue, body)
		}
	}
	var pending protocol.OperatorClaimStatusResponse
	decodeResponse(t, body, &pending)
	if pending.Status.VerificationStatus != protocol.OperatorVerificationStatusPendingReview ||
		pending.Status.ClaimActionID != claim.Receipt.ActionID ||
		pending.Status.GroupID != claim.Receipt.GroupID ||
		pending.Status.LegalName != draft.LegalName {
		t.Fatalf("unexpected pending status: %+v", pending)
	}
	assertOperatorClaimStatusSignature(t, fixture, pending.Status)

	review, err := fixture.runtime.Service.ApproveOperatorClaim(
		context.Background(),
		service.OperatorClaimApproval{
			DeploymentID:    deployment.id,
			ClaimActionID:   claim.Receipt.ActionID,
			GroupID:         claim.Receipt.GroupID,
			LegalName:       draft.LegalName,
			ReviewerID:      "network-review-team",
			ReviewReference: "case:2026-0001",
			IdempotencyKey:  "approve_structured_claim_01",
		},
	)
	if err != nil {
		t.Fatalf("approve structured claim: %v", err)
	}
	if review.Duplicate ||
		review.Receipt.Decision != protocol.OperatorClaimReviewApproved ||
		review.Receipt.ReviewerID != "network-review-team" ||
		review.Receipt.ReviewReference != "case:2026-0001" {
		t.Fatalf("unexpected review receipt: %+v", review)
	}
	duplicate, err := fixture.runtime.Service.ApproveOperatorClaim(
		context.Background(),
		service.OperatorClaimApproval{
			DeploymentID:    deployment.id,
			ClaimActionID:   claim.Receipt.ActionID,
			GroupID:         claim.Receipt.GroupID,
			LegalName:       draft.LegalName,
			ReviewerID:      "network-review-team",
			ReviewReference: "case:2026-0001",
			IdempotencyKey:  "approve_structured_claim_01",
		},
	)
	if err != nil || !duplicate.Duplicate ||
		duplicate.Receipt.ReviewID != review.Receipt.ReviewID {
		t.Fatalf("idempotent review = %+v, error = %v", duplicate, err)
	}

	status, body = rawRequest(
		t,
		http.MethodGet,
		fixture.server.URL+protocol.OperatorClaimStatusPathPrefix+deployment.id,
		nil,
		false,
	)
	if status != http.StatusOK {
		t.Fatalf("approved claim status = %d, body = %s", status, body)
	}
	var approved protocol.OperatorClaimStatusResponse
	decodeResponse(t, body, &approved)
	if approved.Status.VerificationStatus != protocol.OperatorVerificationStatusApproved ||
		approved.Status.ReviewID != review.Receipt.ReviewID ||
		approved.Status.ApprovedAt == "" {
		t.Fatalf("unexpected approved status: %+v", approved)
	}
	assertOperatorClaimStatusSignature(t, fixture, approved.Status)

	page := fixture.leaderboard(t, "view=claimed&through_period=2026-06&limit=10")
	encodedPage, err := json.Marshal(page)
	if err != nil {
		t.Fatalf("encode leaderboard privacy check: %v", err)
	}
	for _, privateValue := range []string{
		draft.RegisteredAddress,
		draft.VerificationContactName,
		draft.VerificationContactEmail,
	} {
		if strings.Contains(string(encodedPage), privateValue) {
			t.Fatalf("leaderboard exposed private value %q: %s", privateValue, encodedPage)
		}
	}
	if len(page.Items) != 1 || page.Items[0].Label != draft.LegalName {
		t.Fatalf("legal name is not the provisional leaderboard label: %+v", page)
	}

	stale := operatorClaimRequest("Structured Cooperative Updated")
	stale.Nonce = "nonce_structured_claim_updated"
	stale.IdempotencyKey = "structured_claim_updated"
	updated := fixture.acceptOperatorAction(
		t,
		fixture.operatorAction(t, deployment, stale),
		http.StatusCreated,
	)
	if updated.Receipt.GroupID != claim.Receipt.GroupID {
		t.Fatalf("resubmission did not retain group: old=%+v new=%+v", claim, updated)
	}
	_, err = fixture.runtime.Service.ApproveOperatorClaim(
		context.Background(),
		service.OperatorClaimApproval{
			DeploymentID:    deployment.id,
			ClaimActionID:   claim.Receipt.ActionID,
			GroupID:         claim.Receipt.GroupID,
			LegalName:       draft.LegalName,
			ReviewerID:      "network-review-team",
			ReviewReference: "case:2026-stale",
			IdempotencyKey:  "approve_structured_stale",
		},
	)
	if err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale claim approval error = %v", err)
	}
}

func TestClientTokenCreatesReviewedClaimWithoutRepeatedCompanyForm(t *testing.T) {
	fixture := newOperatorAPIFixture(t)
	issuer := fixture.registerDeployment(t, "token-issuer")
	target := fixture.registerDeployment(t, "token-target")
	replayTarget := fixture.registerDeployment(t, "token-replay-target")

	claimDraft := operatorClaimRequest("Shared Operator Cooperative")
	claimDraft.Nonce = "nonce_client_code_issuer_claim"
	claimDraft.IdempotencyKey = "client_code_issuer_claim"
	claimRequest := fixture.operatorAction(t, issuer, claimDraft)
	claim := fixture.acceptOperatorAction(t, claimRequest, http.StatusCreated)

	prematureIssue := fixture.operatorAction(t, issuer, protocol.OperatorActionRequest{
		Nonce:           "nonce_issue_client_code_before_approval",
		IdempotencyKey:  "issue_client_code_before_approval",
		Action:          protocol.OperatorActionIssueClientToken,
		TokenTTLSeconds: 300,
	})
	statusCode, body := jsonRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.OperatorActionPath,
		prematureIssue,
	)
	assertAPIError(
		t,
		statusCode,
		body,
		http.StatusConflict,
		"operator_claim_required",
	)

	if _, err := fixture.runtime.Service.ApproveOperatorClaim(
		context.Background(),
		service.OperatorClaimApproval{
			DeploymentID:    issuer.id,
			ClaimActionID:   claim.Receipt.ActionID,
			GroupID:         claim.Receipt.GroupID,
			LegalName:       claimDraft.LegalName,
			ReviewerID:      "network-review-team",
			ReviewReference: "case:client-code-issuer",
			IdempotencyKey:  "approve_client_code_issuer",
		},
	); err != nil {
		t.Fatalf("approve client-code issuer: %v", err)
	}

	issueRequest := fixture.operatorAction(t, issuer, protocol.OperatorActionRequest{
		Nonce:           "nonce_issue_client_code",
		IdempotencyKey:  "issue_client_code",
		Action:          protocol.OperatorActionIssueClientToken,
		TokenTTLSeconds: 300,
	})
	issued := fixture.acceptOperatorAction(t, issueRequest, http.StatusCreated)
	assertIssuedClientToken(t, fixture, issued)

	redeemRequest := fixture.operatorAction(t, target, protocol.OperatorActionRequest{
		Nonce:          "nonce_redeem_client_code",
		IdempotencyKey: "redeem_client_code",
		Action:         protocol.OperatorActionRedeemClientToken,
		ClientToken:    issued.Receipt.ClientToken,
	})
	redeemed := fixture.acceptOperatorAction(t, redeemRequest, http.StatusCreated)
	sourceSubmission, _, err := fixture.runtime.Store.OperatorClaimSubmission(
		context.Background(),
		issuer.id,
	)
	if err != nil {
		t.Fatalf("read approved source submission: %v", err)
	}
	if redeemed.Receipt.ClaimState != protocol.OperatorClaimStatePendingReview ||
		redeemed.Receipt.GroupID != claim.Receipt.GroupID ||
		redeemed.Receipt.RelatedDeploymentID != issuer.id ||
		redeemed.Receipt.SourceClaimActionID != claim.Receipt.ActionID ||
		redeemed.Receipt.SourcePrivateRecordHash != sourceSubmission.PrivateRecordHash ||
		redeemed.Receipt.LinkID != "" {
		t.Fatalf("unexpected token-derived pending claim: %+v", redeemed)
	}

	statusCode, body = rawRequest(
		t,
		http.MethodGet,
		fixture.server.URL+protocol.OperatorClaimStatusPathPrefix+target.id,
		nil,
		false,
	)
	if statusCode != http.StatusOK {
		t.Fatalf("token-derived claim status = %d, body = %s", statusCode, body)
	}
	var pending protocol.OperatorClaimStatusResponse
	decodeResponse(t, body, &pending)
	if pending.Status.ClaimActionID != redeemed.Receipt.ActionID ||
		pending.Status.VerificationStatus != protocol.OperatorVerificationStatusPendingReview ||
		pending.Status.GroupID != claim.Receipt.GroupID ||
		pending.Status.LegalName != claimDraft.LegalName {
		t.Fatalf("unexpected token-derived claim status: %+v", pending)
	}
	assertOperatorClaimStatusSignature(t, fixture, pending.Status)

	detail, err := fixture.runtime.Service.OperatorClaimForReview(
		context.Background(),
		target.id,
	)
	if err != nil {
		t.Fatalf("show token-derived claim: %v", err)
	}
	if detail.Website != claimDraft.Website ||
		detail.RegisteredAddress != claimDraft.RegisteredAddress ||
		detail.VerificationContactEmail != claimDraft.VerificationContactEmail {
		t.Fatalf("token-derived review detail did not retain approved company data: %+v", detail)
	}

	derivedPrematureIssue := fixture.operatorAction(t, target, protocol.OperatorActionRequest{
		Nonce:           "nonce_issue_from_pending_derived_claim",
		IdempotencyKey:  "issue_from_pending_derived_claim",
		Action:          protocol.OperatorActionIssueClientToken,
		TokenTTLSeconds: 300,
	})
	statusCode, body = jsonRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.OperatorActionPath,
		derivedPrematureIssue,
	)
	assertAPIError(
		t,
		statusCode,
		body,
		http.StatusConflict,
		"operator_claim_required",
	)

	redeemRetry := redeemRequest
	redeemRetry.Nonce = "nonce_redeem_client_code_retry"
	resignOperatorAction(t, target.privateKey, &redeemRetry)
	retried := fixture.acceptOperatorAction(t, redeemRetry, http.StatusOK)
	if !retried.Duplicate ||
		retried.Receipt.ActionID != redeemed.Receipt.ActionID ||
		retried.Receipt.AuditHash != redeemed.Receipt.AuditHash {
		t.Fatalf("token redemption retry did not return its original receipt: %+v", retried)
	}

	replayRequest := fixture.operatorAction(t, replayTarget, protocol.OperatorActionRequest{
		Nonce:          "nonce_reuse_client_code",
		IdempotencyKey: "reuse_client_code",
		Action:         protocol.OperatorActionRedeemClientToken,
		ClientToken:    issued.Receipt.ClientToken,
	})
	statusCode, body = jsonRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.OperatorActionPath,
		replayRequest,
	)
	assertAPIError(t, statusCode, body, http.StatusConflict, "client_token_used")

	if _, err := fixture.runtime.Service.ApproveOperatorClaim(
		context.Background(),
		service.OperatorClaimApproval{
			DeploymentID:    target.id,
			ClaimActionID:   redeemed.Receipt.ActionID,
			GroupID:         redeemed.Receipt.GroupID,
			LegalName:       claimDraft.LegalName,
			ReviewerID:      "network-review-team",
			ReviewReference: "case:client-code-target",
			IdempotencyKey:  "approve_client_code_target",
		},
	); err != nil {
		t.Fatalf("approve token-derived claim: %v", err)
	}
}

func TestClientTokenApprovalCannotAuthorizePastIssue(t *testing.T) {
	fixture := newOperatorAPIFixture(t)
	issuer := fixture.registerDeployment(t, "clock-issuer")
	claimDraft := operatorClaimRequest("Clock Boundary Cooperative")
	claimDraft.Nonce = "nonce_clock_boundary_claim"
	claimDraft.IdempotencyKey = "clock_boundary_claim"
	claim := fixture.acceptOperatorAction(
		t,
		fixture.operatorAction(t, issuer, claimDraft),
		http.StatusCreated,
	)

	fixture.clock.Set(fixture.now.Add(2 * time.Hour))
	if _, err := fixture.runtime.Service.ApproveOperatorClaim(
		context.Background(),
		service.OperatorClaimApproval{
			DeploymentID:    issuer.id,
			ClaimActionID:   claim.Receipt.ActionID,
			GroupID:         claim.Receipt.GroupID,
			LegalName:       claimDraft.LegalName,
			ReviewerID:      "network-review-team",
			ReviewReference: "case:clock-boundary",
			IdempotencyKey:  "approve_clock_boundary",
		},
	); err != nil {
		t.Fatalf("approve future-boundary claim: %v", err)
	}

	fixture.clock.Set(fixture.now.Add(time.Hour))
	request := fixture.operatorAction(t, issuer, protocol.OperatorActionRequest{
		Nonce:           "nonce_clock_boundary_issue",
		IdempotencyKey:  "clock_boundary_issue",
		Action:          protocol.OperatorActionIssueClientToken,
		TokenTTLSeconds: 300,
	})
	statusCode, body := jsonRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.OperatorActionPath,
		request,
	)
	assertAPIError(
		t,
		statusCode,
		body,
		http.StatusConflict,
		"operator_claim_required",
	)
}

func TestTokenDerivedClaimSourceIntegrityFailsClosed(t *testing.T) {
	t.Run("source reference", func(t *testing.T) {
		fixture, _, _, _, redeemed := createTokenDerivedClaim(t, "source-reference")
		database, err := sql.Open("sqlite", fixture.cfg.DatabasePath)
		if err != nil {
			t.Fatalf("open source-reference tamper database: %v", err)
		}
		if _, err := database.Exec("DROP TRIGGER operator_audit_events_no_update"); err != nil {
			database.Close()
			t.Fatalf("drop operator audit append-only trigger: %v", err)
		}
		if _, err := database.Exec(`
			UPDATE operator_audit_events
			SET source_claim_action_id = 'opa_ffffffffffffffffffffffffffffffff'
			WHERE action_id = ?`,
			redeemed.Receipt.ActionID,
		); err != nil {
			database.Close()
			t.Fatalf("tamper source claim reference: %v", err)
		}
		if err := database.Close(); err != nil {
			t.Fatalf("close source-reference tamper database: %v", err)
		}
		if err := fixture.runtime.Service.VerifyState(context.Background()); err == nil ||
			!strings.Contains(err.Error(), "audit hash verification failed") {
			t.Fatalf("source-reference corruption verification error = %v", err)
		}
	})

	t.Run("copied company data", func(t *testing.T) {
		fixture, _, target, _, redeemed := createTokenDerivedClaim(t, "copied-data")
		submission, _, err := fixture.runtime.Store.OperatorClaimSubmission(
			context.Background(),
			target.id,
		)
		if err != nil {
			t.Fatalf("read copied submission before tamper: %v", err)
		}
		submission.RegisteredAddress = "Tampered copied address"
		privateRecordHash := protocol.Digest(protocol.OperatorClaimPrivateRecordMessage(
			submission.ClaimActionID,
			submission.DeploymentID,
			submission.GroupID,
			submission.PayloadHash,
			submission.LegalName,
			submission.RegistrationNumber,
			submission.Jurisdiction,
			submission.RegisteredAddress,
			submission.Website,
			submission.VerificationContactName,
			submission.VerificationContactRole,
			submission.VerificationContactEmail,
			submission.AuthorityAttested,
			submission.OperatorAvatarURL,
			submission.SubmittedAt,
		))

		database, err := sql.Open("sqlite", fixture.cfg.DatabasePath)
		if err != nil {
			t.Fatalf("open copied-data tamper database: %v", err)
		}
		if _, err := database.Exec(
			"DROP TRIGGER operator_claim_verification_no_update",
		); err != nil {
			database.Close()
			t.Fatalf("drop private submission append-only trigger: %v", err)
		}
		if _, err := database.Exec(`
			UPDATE operator_claim_verification_submissions
			SET registered_address = ?, private_record_hash = ?
			WHERE claim_action_id = ?`,
			submission.RegisteredAddress,
			privateRecordHash,
			redeemed.Receipt.ActionID,
		); err != nil {
			database.Close()
			t.Fatalf("tamper copied private submission: %v", err)
		}
		if _, err := database.Exec(`
			UPDATE operator_claim_status
			SET private_record_hash = ?
			WHERE deployment_id = ?`,
			privateRecordHash,
			target.id,
		); err != nil {
			database.Close()
			t.Fatalf("align copied direct status hash: %v", err)
		}
		if err := database.Close(); err != nil {
			t.Fatalf("close copied-data tamper database: %v", err)
		}
		if err := fixture.runtime.Service.VerifyState(context.Background()); err == nil ||
			!strings.Contains(err.Error(), "does not match its approved source") {
			t.Fatalf("copied-data corruption verification error = %v", err)
		}
	})
}

func createTokenDerivedClaim(
	t *testing.T,
	suffix string,
) (*operatorAPIFixture, operatorDeployment, operatorDeployment, protocol.OperatorActionResponse, protocol.OperatorActionResponse) {
	t.Helper()
	fixture := newOperatorAPIFixture(t)
	issuer := fixture.registerDeployment(t, suffix+"-issuer")
	target := fixture.registerDeployment(t, suffix+"-target")
	claimDraft := operatorClaimRequest("Source Integrity Cooperative")
	claimDraft.Nonce = "nonce_" + suffix + "_claim"
	claimDraft.IdempotencyKey = suffix + "_claim"
	claim := fixture.acceptOperatorAction(
		t,
		fixture.operatorAction(t, issuer, claimDraft),
		http.StatusCreated,
	)
	if _, err := fixture.runtime.Service.ApproveOperatorClaim(
		context.Background(),
		service.OperatorClaimApproval{
			DeploymentID:    issuer.id,
			ClaimActionID:   claim.Receipt.ActionID,
			GroupID:         claim.Receipt.GroupID,
			LegalName:       claimDraft.LegalName,
			ReviewerID:      "network-review-team",
			ReviewReference: "case:" + suffix,
			IdempotencyKey:  "approve_" + suffix,
		},
	); err != nil {
		t.Fatalf("approve source-integrity issuer: %v", err)
	}
	issued := fixture.acceptOperatorAction(
		t,
		fixture.operatorAction(t, issuer, protocol.OperatorActionRequest{
			Nonce:           "nonce_" + suffix + "_issue",
			IdempotencyKey:  suffix + "_issue",
			Action:          protocol.OperatorActionIssueClientToken,
			TokenTTLSeconds: 300,
		}),
		http.StatusCreated,
	)
	redeemed := fixture.acceptOperatorAction(
		t,
		fixture.operatorAction(t, target, protocol.OperatorActionRequest{
			Nonce:          "nonce_" + suffix + "_redeem",
			IdempotencyKey: suffix + "_redeem",
			Action:         protocol.OperatorActionRedeemClientToken,
			ClientToken:    issued.Receipt.ClientToken,
		}),
		http.StatusCreated,
	)
	return fixture, issuer, target, claim, redeemed
}

func newOperatorAPIFixture(t *testing.T) *operatorAPIFixture {
	t.Helper()
	directory := t.TempDir()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	clock := &mutableClock{value: now}
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
		t.Fatalf("bootstrap operator registry: %v", err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("close operator registry: %v", err)
		}
	})
	server := httptest.NewServer(httpapi.New(runtime.Service, httpapi.Options{
		MaxRequestBodyBytes: cfg.MaxRequestBodyBytes,
	}))
	t.Cleanup(server.Close)
	return &operatorAPIFixture{
		now:     now,
		clock:   clock,
		ids:     ids,
		cfg:     cfg,
		runtime: runtime,
		server:  server,
	}
}

func (fixture *operatorAPIFixture) registerDeployment(
	t *testing.T,
	suffix string,
) operatorDeployment {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate %s deployment key: %v", suffix, err)
	}
	request := signedRegistration(
		t,
		privateKey,
		fixture.now.Format(time.RFC3339),
		"nonce_registration_operator_"+suffix,
		"registration_operator_"+suffix,
		"operator-test-1.0.0",
	)
	status, body := jsonRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.RegistrationPath,
		request,
	)
	if status != http.StatusCreated {
		t.Fatalf(
			"register %s deployment status = %d, body = %s",
			suffix,
			status,
			body,
		)
	}
	var response protocol.RegistrationResponse
	decodeResponse(t, body, &response)
	verifyRegistrationReceipt(t, response)
	return operatorDeployment{
		id:         response.DeploymentID,
		privateKey: privateKey,
	}
}

func (fixture *operatorAPIFixture) operatorAction(
	t *testing.T,
	deployment operatorDeployment,
	request protocol.OperatorActionRequest,
) protocol.OperatorActionRequest {
	t.Helper()
	request.ProtocolVersion = protocol.Version
	request.RegistryScope = testRegistryScope
	request.DeploymentID = deployment.id
	request.Timestamp = fixture.now.Format(time.RFC3339)
	signOperatorActionPayload(t, deployment.privateKey, &request)
	return request
}

func signOperatorActionPayload(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	request *protocol.OperatorActionRequest,
) {
	t.Helper()
	clientTokenHash := ""
	if request.Action == protocol.OperatorActionRedeemClientToken {
		clientTokenHash = protocol.Digest([]byte(request.ClientToken))
	}
	request.PayloadHash = protocol.Digest(protocol.OperatorActionPayload(
		request.Action,
		request.OperatorName,
		request.OperatorAvatarURL,
		clientTokenHash,
		request.TokenTTLSeconds,
		request.TokenID,
		request.LinkID,
	))
	if request.Action == protocol.OperatorActionClaim {
		request.PayloadHash = protocol.Digest(protocol.OperatorClaimPayload(
			request.LegalName,
			request.RegistrationNumber,
			request.Jurisdiction,
			request.RegisteredAddress,
			request.Website,
			request.VerificationContactName,
			request.VerificationContactRole,
			request.VerificationContactEmail,
			request.AuthorityAttested,
			request.OperatorAvatarURL,
		))
	}
	resignOperatorAction(t, privateKey, request)
}

func operatorClaimRequest(legalName string) protocol.OperatorActionRequest {
	return protocol.OperatorActionRequest{
		Action:                   protocol.OperatorActionClaim,
		LegalName:                legalName,
		RegistrationNumber:       "REG-2026-001",
		Jurisdiction:             "Slovakia",
		RegisteredAddress:        "Main Street 1, 811 01 Bratislava, Slovakia",
		Website:                  "https://operator.example.test",
		VerificationContactName:  "Review Contact",
		VerificationContactRole:  "Director",
		VerificationContactEmail: "review@example.test",
		AuthorityAttested:        true,
	}
}

func resignOperatorAction(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	request *protocol.OperatorActionRequest,
) {
	t.Helper()
	request.Signature = protocol.EncodeSignature(ed25519.Sign(
		privateKey,
		protocol.CanonicalRequest(
			http.MethodPost,
			protocol.OperatorActionPath,
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

func (fixture *operatorAPIFixture) acceptOperatorAction(
	t *testing.T,
	request protocol.OperatorActionRequest,
	expectedStatus int,
) protocol.OperatorActionResponse {
	t.Helper()
	status, body := jsonRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.OperatorActionPath,
		request,
	)
	if status != expectedStatus {
		t.Fatalf(
			"operator action %s status = %d, want %d; body = %s",
			request.Action,
			status,
			expectedStatus,
			body,
		)
	}
	var response protocol.OperatorActionResponse
	decodeResponse(t, body, &response)
	if response.ProtocolVersion != protocol.Version ||
		response.RegistryScope != testRegistryScope {
		t.Fatalf("unexpected operator action envelope: %+v", response)
	}
	return response
}

func assertOperatorReceipt(
	t *testing.T,
	fixture *operatorAPIFixture,
	request protocol.OperatorActionRequest,
	receipt protocol.OperatorActionReceipt,
	expectedAuditIndex int64,
	expectedPreviousHash string,
) {
	t.Helper()
	if receipt.AuditIndex != expectedAuditIndex ||
		receipt.PreviousAuditHash != expectedPreviousHash ||
		receipt.DeploymentID != request.DeploymentID ||
		receipt.Action != request.Action ||
		receipt.RegistryScope != testRegistryScope ||
		receipt.RegistryKeyID != fixture.runtime.SigningKey.KeyID() {
		t.Fatalf("unexpected operator receipt: %+v", receipt)
	}
	expectedAuditHash := protocol.Digest(protocol.OperatorAuditMessage(
		receipt.AuditIndex,
		receipt.ActionID,
		receipt.DeploymentID,
		receipt.SubjectDeploymentID,
		receipt.RelatedDeploymentID,
		receipt.Action,
		request.PayloadHash,
		receipt.AcceptedAt,
		receipt.ClaimState,
		receipt.GroupID,
		receipt.LinkID,
		receipt.TokenID,
		receipt.ClientTokenHash,
		receipt.SourceClaimActionID,
		receipt.SourcePrivateRecordHash,
		receipt.TokenExpiresAt,
		receipt.PreviousAuditHash,
	))
	if receipt.AuditHash != expectedAuditHash {
		t.Fatalf(
			"operator receipt audit hash = %q, want %q",
			receipt.AuditHash,
			expectedAuditHash,
		)
	}
	signature, err := protocol.ParseSignature(receipt.Signature)
	if err != nil {
		t.Fatalf("parse operator receipt signature: %v", err)
	}
	if !protocol.Verify(
		fixture.runtime.SigningKey.PublicKey(),
		protocol.OperatorActionReceiptMessage(receipt),
		signature,
	) {
		t.Fatalf("operator action receipt signature verification failed")
	}
}

func assertIssuedClientToken(
	t *testing.T,
	fixture *operatorAPIFixture,
	response protocol.OperatorActionResponse,
) {
	t.Helper()
	receipt := response.Receipt
	if !strings.HasPrefix(receipt.ClientToken, "opc_") ||
		!strings.HasPrefix(receipt.TokenID, "opt_") ||
		receipt.ClientTokenHash != protocol.Digest([]byte(receipt.ClientToken)) {
		t.Fatalf("unexpected issued client token receipt: %+v", receipt)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, receipt.TokenExpiresAt)
	if err != nil {
		t.Fatalf("parse client token expiry: %v", err)
	}
	if !expiresAt.After(fixture.now) {
		t.Fatalf("client token expiry %s is not after issue time", receipt.TokenExpiresAt)
	}
}

func assertOperatorClaimStatusSignature(
	t *testing.T,
	fixture *operatorAPIFixture,
	status protocol.OperatorClaimStatusReceipt,
) {
	t.Helper()
	signature, err := protocol.ParseSignature(status.Signature)
	if err != nil {
		t.Fatalf("parse operator claim status signature: %v", err)
	}
	if !protocol.Verify(
		fixture.runtime.SigningKey.PublicKey(),
		protocol.OperatorClaimStatusReceiptMessage(status),
		signature,
	) {
		t.Fatalf("operator claim status signature verification failed: %+v", status)
	}
}

func (fixture *operatorAPIFixture) leaderboard(
	t *testing.T,
	rawQuery string,
) protocol.LeaderboardPageDto {
	t.Helper()
	endpoint := fixture.server.URL + protocol.LeaderboardPath
	if rawQuery != "" {
		endpoint += "?" + rawQuery
	}
	status, body := rawRequest(t, http.MethodGet, endpoint, nil, false)
	if status != http.StatusOK {
		t.Fatalf("leaderboard status = %d, body = %s", status, body)
	}
	var page protocol.LeaderboardPageDto
	decodeResponse(t, body, &page)
	return page
}

func (fixture *operatorAPIFixture) groupDeployments(
	t *testing.T,
	path string,
	rawQuery string,
) protocol.LeaderboardDeploymentPageDto {
	t.Helper()
	endpoint := path
	if rawQuery != "" {
		endpoint += "?" + rawQuery
	}
	status, body := rawRequest(t, http.MethodGet, endpoint, nil, false)
	if status != http.StatusOK {
		t.Fatalf("leaderboard group status = %d, body = %s", status, body)
	}
	var page protocol.LeaderboardDeploymentPageDto
	decodeResponse(t, body, &page)
	return page
}

func assertLeaderboardSnapshot(
	t *testing.T,
	fixture *operatorAPIFixture,
	snapshot protocol.LeaderboardSnapshotDto,
) {
	t.Helper()
	if snapshot.FormulaVersion != protocol.LeaderboardFormulaVersion ||
		snapshot.RulesetVersion != protocol.LeaderboardRulesetVersion ||
		snapshot.ThroughPeriod != "2026-06" ||
		snapshot.RegistryScope != testRegistryScope ||
		snapshot.RegistryKeyID != fixture.runtime.SigningKey.KeyID() {
		t.Fatalf("unexpected leaderboard snapshot: %+v", snapshot)
	}
	expectedHash := protocol.Digest(protocol.LeaderboardSnapshotHashMessage(snapshot))
	if snapshot.SnapshotHash != expectedHash {
		t.Fatalf(
			"leaderboard snapshot hash = %q, want %q",
			snapshot.SnapshotHash,
			expectedHash,
		)
	}
	signature, err := protocol.ParseSignature(snapshot.Signature)
	if err != nil {
		t.Fatalf("parse leaderboard snapshot signature: %v", err)
	}
	if !protocol.Verify(
		fixture.runtime.SigningKey.PublicKey(),
		protocol.LeaderboardSnapshotMessage(snapshot),
		signature,
	) {
		t.Fatalf("leaderboard snapshot signature verification failed")
	}
}

func tamperCursor(cursor string) string {
	if cursor == "" {
		return "tampered"
	}
	replacement := byte('A')
	if cursor[0] == replacement {
		replacement = 'B'
	}
	return string(replacement) + cursor[1:]
}

func leaderboardGroupIDs(items []protocol.LeaderboardRowDto) []string {
	groupIDs := make([]string, 0, len(items))
	for _, item := range items {
		groupIDs = append(groupIDs, item.GroupID)
	}
	return groupIDs
}
