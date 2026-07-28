package httpapi_test

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
	_ "modernc.org/sqlite"
)

func TestOperatorNetworkStateRowsAreTransactionalAndHistorical(t *testing.T) {
	fixture := newOperatorAPIFixture(t)
	alpha := fixture.registerDeployment(t, "state-alpha")
	beta := fixture.registerDeployment(t, "state-beta")

	alphaClaimDraft := operatorClaimRequest("State Alpha Cooperative")
	alphaClaimDraft.Nonce = "nonce_state_alpha_claim"
	alphaClaimDraft.IdempotencyKey = "state_alpha_claim"
	alphaClaim := fixture.acceptOperatorAction(
		t,
		fixture.operatorAction(t, alpha, alphaClaimDraft),
		http.StatusCreated,
	)

	betaClaimDraft := operatorClaimRequest("State Beta Cooperative")
	betaClaimDraft.Nonce = "nonce_state_beta_claim"
	betaClaimDraft.IdempotencyKey = "state_beta_claim"
	fixture.acceptOperatorAction(
		t,
		fixture.operatorAction(t, beta, betaClaimDraft),
		http.StatusCreated,
	)

	beforeLink, err := fixture.runtime.Store.LeaderboardRows(
		context.Background(),
		operatorStateLeaderboardQuery(2),
	)
	if err != nil {
		t.Fatalf("read historical operator state before link: %v", err)
	}
	if len(beforeLink) != 2 ||
		beforeLink[0].DeploymentCount != 1 ||
		beforeLink[1].DeploymentCount != 1 {
		t.Fatalf("historical pre-link groups = %+v, want two independent groups", beforeLink)
	}

	issued := fixture.acceptOperatorAction(
		t,
		fixture.operatorAction(t, alpha, protocol.OperatorActionRequest{
			Nonce:           "nonce_state_issue_token",
			IdempotencyKey:  "state_issue_token",
			Action:          protocol.OperatorActionIssueClientToken,
			TokenTTLSeconds: 600,
		}),
		http.StatusCreated,
	)
	redeemed := fixture.acceptOperatorAction(
		t,
		fixture.operatorAction(t, beta, protocol.OperatorActionRequest{
			Nonce:          "nonce_state_redeem_token",
			IdempotencyKey: "state_redeem_token",
			Action:         protocol.OperatorActionRedeemClientToken,
			ClientToken:    issued.Receipt.ClientToken,
		}),
		http.StatusCreated,
	)

	afterLink, err := fixture.runtime.Store.LeaderboardRows(
		context.Background(),
		operatorStateLeaderboardQuery(redeemed.Receipt.AuditIndex),
	)
	if err != nil {
		t.Fatalf("read historical operator state after link: %v", err)
	}
	if len(afterLink) != 1 ||
		afterLink[0].GroupID != alphaClaim.Receipt.GroupID ||
		afterLink[0].DeploymentCount != 2 {
		t.Fatalf("historical linked group = %+v, want one two-deployment group", afterLink)
	}

	beforeLinkAgain, err := fixture.runtime.Store.LeaderboardRows(
		context.Background(),
		operatorStateLeaderboardQuery(2),
	)
	if err != nil {
		t.Fatalf("repeat historical operator state before link: %v", err)
	}
	if len(beforeLinkAgain) != 2 {
		t.Fatalf(
			"newer operator actions changed the frozen pre-link boundary: %+v",
			beforeLinkAgain,
		)
	}

	database, err := sql.Open("sqlite", fixture.cfg.DatabasePath)
	if err != nil {
		t.Fatalf("open operator state database: %v", err)
	}
	defer database.Close()
	var auditCount, stateCount int
	if err := database.QueryRow(`
		SELECT
			(SELECT COUNT(*) FROM operator_audit_events),
			(SELECT COUNT(*) FROM operator_network_state_rows)`,
	).Scan(&auditCount, &stateCount); err != nil {
		t.Fatalf("count operator audit/state rows: %v", err)
	}
	if auditCount != 4 || stateCount != auditCount {
		t.Fatalf("audit/state counts = %d/%d, want 4/4", auditCount, stateCount)
	}

	var deploymentID, effectiveGroupID, linkID, relatedDeploymentID string
	if err := database.QueryRow(`
		SELECT deployment_id, effective_group_id, link_id, related_deployment_id
		FROM operator_network_state_rows
		WHERE audit_index = ?`,
		redeemed.Receipt.AuditIndex,
	).Scan(
		&deploymentID,
		&effectiveGroupID,
		&linkID,
		&relatedDeploymentID,
	); err != nil {
		t.Fatalf("read redeemed direct operator state row: %v", err)
	}
	if deploymentID != beta.id ||
		effectiveGroupID != alphaClaim.Receipt.GroupID ||
		linkID != redeemed.Receipt.LinkID ||
		relatedDeploymentID != alpha.id {
		t.Fatalf(
			"redeemed direct state = deployment=%q group=%q link=%q related=%q",
			deploymentID,
			effectiveGroupID,
			linkID,
			relatedDeploymentID,
		)
	}
}

func TestOperatorNetworkStateWriteFailureRollsBackAudit(t *testing.T) {
	fixture := newOperatorAPIFixture(t)
	deployment := fixture.registerDeployment(t, "state-rollback")

	database, err := sql.Open("sqlite", fixture.cfg.DatabasePath)
	if err != nil {
		t.Fatalf("open operator rollback database: %v", err)
	}
	if _, err := database.Exec(`
		CREATE TRIGGER fail_operator_network_state_insert
		BEFORE INSERT ON operator_network_state_rows BEGIN
			SELECT RAISE(ABORT, 'forced operator state failure');
		END`); err != nil {
		database.Close()
		t.Fatalf("install operator state failure trigger: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close operator rollback setup database: %v", err)
	}

	draft := operatorClaimRequest("Rollback Cooperative")
	draft.Nonce = "nonce_state_rollback_claim"
	draft.IdempotencyKey = "state_rollback_claim"
	request := fixture.operatorAction(t, deployment, draft)
	status, body := jsonRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.OperatorActionPath,
		request,
	)
	if status != http.StatusInternalServerError {
		t.Fatalf("state-write failure status = %d, body = %s", status, body)
	}

	database, err = sql.Open("sqlite", fixture.cfg.DatabasePath)
	if err != nil {
		t.Fatalf("reopen operator rollback database: %v", err)
	}
	defer database.Close()
	var auditCount, stateCount, nonceCount, privateCount, statusCount int
	if err := database.QueryRow(`
		SELECT
			(SELECT COUNT(*) FROM operator_audit_events),
			(SELECT COUNT(*) FROM operator_network_state_rows),
			(SELECT COUNT(*) FROM operator_action_nonces),
			(SELECT COUNT(*) FROM operator_claim_verification_submissions),
			(SELECT COUNT(*) FROM operator_claim_status)`,
	).Scan(
		&auditCount,
		&stateCount,
		&nonceCount,
		&privateCount,
		&statusCount,
	); err != nil {
		t.Fatalf("count rolled-back operator records: %v", err)
	}
	if auditCount != 0 ||
		stateCount != 0 ||
		nonceCount != 0 ||
		privateCount != 0 ||
		statusCount != 0 {
		t.Fatalf(
			"operator action partially committed audit/state/nonce/private/status = %d/%d/%d/%d/%d",
			auditCount,
			stateCount,
			nonceCount,
			privateCount,
			statusCount,
		)
	}
}

func TestOperatorNetworkStateTamperingFailsClosed(t *testing.T) {
	fixture := newOperatorAPIFixture(t)
	deployment := fixture.registerDeployment(t, "state-tamper")
	draft := operatorClaimRequest("State Tamper Cooperative")
	draft.Nonce = "nonce_state_tamper_claim"
	draft.IdempotencyKey = "state_tamper_claim"
	fixture.acceptOperatorAction(
		t,
		fixture.operatorAction(t, deployment, draft),
		http.StatusCreated,
	)

	database, err := sql.Open("sqlite", fixture.cfg.DatabasePath)
	if err != nil {
		t.Fatalf("open operator state tamper database: %v", err)
	}
	if _, err := database.Exec(
		"DROP TRIGGER operator_network_state_rows_no_update",
	); err != nil {
		database.Close()
		t.Fatalf("drop operator state append-only trigger: %v", err)
	}
	if _, err := database.Exec(`
		UPDATE operator_network_state_rows
		SET effective_group_id = 'opg_ffffffffffffffffffffffffffffffff'`,
	); err != nil {
		database.Close()
		t.Fatalf("tamper operator network state row: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close operator state tamper database: %v", err)
	}

	err = fixture.runtime.Service.VerifyState(context.Background())
	if err == nil || !strings.Contains(err.Error(), "operator network state row") {
		t.Fatalf("operator state corruption verification error = %v", err)
	}
	status, body := rawRequest(
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
}

func operatorStateLeaderboardQuery(
	throughAuditIndex int64,
) store.LeaderboardQuery {
	return store.LeaderboardQuery{
		View:               "claimed",
		FromPeriod:         "2026-01",
		ThroughPeriod:      "2026-06",
		ThroughLedgerIndex: 0,
		ThroughAuditIndex:  throughAuditIndex,
		Limit:              10,
	}
}
