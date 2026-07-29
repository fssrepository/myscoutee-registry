package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

func TestRejectOperatorClaimCLIHelpIsLocalAndPrivacyBounded(t *testing.T) {
	var output bytes.Buffer
	if err := runRejectOperatorClaim(
		[]string{"--help"},
		&output,
	); err != nil {
		t.Fatalf("reject-operator-claim --help: %v", err)
	}
	for _, expected := range []string{
		"--reason-code",
		"non-personal",
		"do not enter names, email addresses, notes, or evidence bodies",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf(
				"rejection help omitted %q: %s",
				expected,
				output.String(),
			)
		}
	}
}

func TestRejectOperatorClaimCLIIsSignedIdempotentAndShareIneligible(
	t *testing.T,
) {
	deploymentID, claim := seedStructuredCLIClaim(t)
	args := []string{
		"--deployment-id", deploymentID,
		"--claim-action-id", claim.Receipt.ActionID,
		"--group-id", claim.Receipt.GroupID,
		"--legal-name", "CLI Cooperative",
		"--reviewer-id", "network-review-team",
		"--review-reference", "case:cli-reject-0001",
		"--reason-code", "identity-not-verified",
		"--idempotency-key", "reject_cli_claim_0001",
	}

	var output bytes.Buffer
	if err := runRejectOperatorClaim(args, &output); err != nil {
		t.Fatalf("reject operator claim: %v", err)
	}
	var rejected protocol.OperatorClaimReviewResult
	if err := json.Unmarshal(output.Bytes(), &rejected); err != nil {
		t.Fatalf(
			"decode rejection result: %v; output=%s",
			err,
			output.String(),
		)
	}
	if rejected.Duplicate ||
		rejected.Receipt.Decision != protocol.OperatorClaimReviewRejected ||
		rejected.Receipt.ReasonCode != "identity-not-verified" ||
		rejected.Receipt.ReviewerID != "network-review-team" ||
		rejected.Receipt.ReviewReference != "case:cli-reject-0001" ||
		rejected.Receipt.ReviewHash == "" ||
		rejected.Receipt.Signature == "" {
		t.Fatalf("unexpected rejection receipt: %+v", rejected)
	}

	output.Reset()
	if err := runRejectOperatorClaim(args, &output); err != nil {
		t.Fatalf("repeat idempotent rejection: %v", err)
	}
	var duplicate protocol.OperatorClaimReviewResult
	if err := json.Unmarshal(output.Bytes(), &duplicate); err != nil ||
		!duplicate.Duplicate ||
		duplicate.Receipt != rejected.Receipt {
		t.Fatalf(
			"rejection retry was not the same duplicate: %+v, error=%v",
			duplicate,
			err,
		)
	}

	var detailOutput bytes.Buffer
	if err := runShowOperatorClaim(
		[]string{"--deployment-id", deploymentID},
		&detailOutput,
	); err != nil {
		t.Fatalf("show rejected claim: %v", err)
	}
	var detail protocol.OperatorClaimReviewDetail
	if err := json.Unmarshal(detailOutput.Bytes(), &detail); err != nil ||
		detail.VerificationStatus !=
			protocol.OperatorVerificationStatusRejected ||
		detail.ApprovedAt != "" {
		t.Fatalf(
			"show did not expose the rejected status boundary: %+v, error=%v",
			detail,
			err,
		)
	}

	var leaderboardOutput bytes.Buffer
	if err := runLeaderboard(
		[]string{"--view", "claimed", "--limit", "10"},
		&leaderboardOutput,
	); err != nil {
		t.Fatalf("query rejected claim leaderboard: %v", err)
	}
	var leaderboard protocol.LeaderboardPageDto
	if err := json.Unmarshal(
		leaderboardOutput.Bytes(),
		&leaderboard,
	); err != nil {
		t.Fatalf("decode rejected leaderboard: %v", err)
	}
	if len(leaderboard.Items) != 1 ||
		leaderboard.Items[0].ClaimState !=
			protocol.OperatorClaimStateRejected ||
		leaderboard.Items[0].ShareNumerator != "0" ||
		leaderboard.Items[0].ShareDenominator != "1" {
		t.Fatalf(
			"rejected claim retained share eligibility: %+v",
			leaderboard,
		)
	}

	conflictArgs := append([]string(nil), args...)
	for index := range conflictArgs {
		if conflictArgs[index] == "identity-not-verified" {
			conflictArgs[index] = "authority-not-verified"
		}
	}
	if err := runRejectOperatorClaim(conflictArgs, &output); err == nil ||
		!strings.Contains(err.Error(), "idempotency_key") {
		t.Fatalf(
			"changed rejection reused an idempotency key: %v",
			err,
		)
	}
}
