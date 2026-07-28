package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/app"
	"github.com/fssrepository/myscoutee-registry/internal/config"
	"github.com/fssrepository/myscoutee-registry/internal/httpapi"
	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

func TestPublishAnnouncementCLIHelpDoesNotRequireConfiguration(t *testing.T) {
	var output bytes.Buffer
	if err := runPublishAnnouncement(
		[]string{"--help"},
		strings.NewReader(""),
		&output,
	); err != nil {
		t.Fatalf("publish-announcement --help: %v", err)
	}
	if !strings.Contains(
		output.String(),
		"publish-announcement --file PATH|-",
	) || !strings.Contains(output.String(), "--file -") {
		t.Fatalf("help output does not document file/stdin usage: %s", output.String())
	}
}

func TestPublishAnnouncementCLIUsesStrictFileAndLiveSQLiteVolume(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("REGISTRY_SCOPE", "example:cli-announcements")
	t.Setenv("REGISTRY_DATABASE_PATH", filepath.Join(directory, "registry.db"))
	t.Setenv(
		"REGISTRY_SIGNING_KEY_PATH",
		filepath.Join(directory, "registry-signing-key.pem"),
	)
	t.Setenv("REGISTRY_GENERATE_SIGNING_KEY", "true")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load CLI test config: %v", err)
	}
	liveRuntime, err := app.Bootstrap(
		context.Background(),
		cfg,
		app.Options{},
	)
	if err != nil {
		t.Fatalf("bootstrap concurrently running registry: %v", err)
	}
	liveServer := httptest.NewServer(httpapi.New(
		liveRuntime.Service,
		httpapi.Options{MaxRequestBodyBytes: cfg.MaxRequestBodyBytes},
	))
	defer liveServer.Close()

	now := time.Now().UTC().Truncate(time.Second)
	draft := protocol.AnnouncementDraft{
		ProtocolVersion: protocol.Version,
		PublicationID:   "publication_cli_live_0001",
		Kind:            protocol.AnnouncementKindGeneral,
		Severity:        protocol.AnnouncementSeverityNotice,
		PublishedAt:     now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:       now.Add(24 * time.Hour).Format(time.RFC3339),
		TitleKey:        "operator.announcement.cli.title",
		BodyKey:         "operator.announcement.cli.body",
		Links: []protocol.AnnouncementLink{{
			Relation: "details",
			URL:      "https://community.example.test/cli-announcement",
		}},
	}
	encodedDraft, err := json.Marshal(draft)
	if err != nil {
		t.Fatalf("encode CLI draft: %v", err)
	}
	filePath := filepath.Join(directory, "announcement.json")
	if err := os.WriteFile(filePath, encodedDraft, 0o600); err != nil {
		t.Fatalf("write announcement file: %v", err)
	}

	var output bytes.Buffer
	if err := runPublishAnnouncement(
		[]string{"--file", filePath},
		strings.NewReader(""),
		&output,
	); err != nil {
		t.Fatalf("publish from strict JSON file while registry is live: %v", err)
	}
	var result protocol.AnnouncementPublishResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode CLI output: %v; output=%s", err, output.String())
	}
	if result.Duplicate || result.Announcement.PublicationID != draft.PublicationID {
		t.Fatalf("unexpected CLI result: %+v", result)
	}

	response, err := http.Get(liveServer.URL + protocol.AnnouncementPath)
	if err != nil {
		t.Fatalf("read CLI publication through running HTTP server: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("running HTTP server returned %s", response.Status)
	}
	var page protocol.AnnouncementPage
	if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
		t.Fatalf("decode running HTTP announcement feed: %v", err)
	}
	if len(page.Items) != 1 ||
		page.Items[0].AnnouncementID != result.Announcement.AnnouncementID {
		t.Fatalf("live service did not see CLI publication: %+v", page)
	}

	output.Reset()
	if err := runPublishAnnouncement(
		[]string{"--file", "-"},
		bytes.NewReader(encodedDraft),
		&output,
	); err != nil {
		t.Fatalf("idempotent publication from stdin: %v", err)
	}
	var duplicate protocol.AnnouncementPublishResult
	if err := json.Unmarshal(output.Bytes(), &duplicate); err != nil {
		t.Fatalf("decode duplicate CLI output: %v", err)
	}
	if !duplicate.Duplicate ||
		duplicate.Announcement.AnnouncementID != result.Announcement.AnnouncementID {
		t.Fatalf("stdin retry did not return signed duplicate: %+v", duplicate)
	}

	response.Body.Close()
	liveServer.Close()
	if err := liveRuntime.Close(); err != nil {
		t.Fatalf("close live registry: %v", err)
	}
	restarted, err := app.Bootstrap(context.Background(), cfg, app.Options{})
	if err != nil {
		t.Fatalf("restart registry after CLI publication: %v", err)
	}
	defer restarted.Close()
	restartedServer := httptest.NewServer(httpapi.New(
		restarted.Service,
		httpapi.Options{MaxRequestBodyBytes: cfg.MaxRequestBodyBytes},
	))
	defer restartedServer.Close()
	response, err = http.Get(restartedServer.URL + protocol.AnnouncementPath)
	if err != nil {
		t.Fatalf("read persisted announcement after restart: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("restarted HTTP server returned %s", response.Status)
	}
	var restartedPage protocol.AnnouncementPage
	if err := json.NewDecoder(response.Body).Decode(&restartedPage); err != nil {
		t.Fatalf("decode restarted announcement feed: %v", err)
	}
	if len(restartedPage.Items) != 1 ||
		restartedPage.Items[0].PublicationID != draft.PublicationID {
		t.Fatalf("announcement did not persist across restart: %+v", restartedPage)
	}
}

func TestPublishAnnouncementCLIRejectsUnknownAndDuplicateJSONFields(t *testing.T) {
	t.Setenv("REGISTRY_SCOPE", "example:strict-announcements")
	var output bytes.Buffer
	for _, contents := range []string{
		`{"protocol_version":"1","unknown":true}`,
		`{"protocol_version":"1","protocol_version":"1"}`,
	} {
		output.Reset()
		err := runPublishAnnouncement(
			[]string{"--file", "-"},
			strings.NewReader(contents),
			&output,
		)
		if err == nil {
			t.Fatalf("strict CLI accepted invalid JSON: %s", contents)
		}
	}
}

func TestDocumentedAnnouncementExamplesAreStrictlyPublishable(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("REGISTRY_SCOPE", "example:documented-announcements")
	t.Setenv("REGISTRY_DATABASE_PATH", filepath.Join(directory, "registry.db"))
	t.Setenv(
		"REGISTRY_SIGNING_KEY_PATH",
		filepath.Join(directory, "registry-signing-key.pem"),
	)
	t.Setenv("REGISTRY_GENERATE_SIGNING_KEY", "true")

	for _, name := range []string{
		"announcement-general.json",
		"announcement-update.json",
	} {
		var output bytes.Buffer
		err := runPublishAnnouncement(
			[]string{
				"--file",
				filepath.Join("..", "..", "examples", name),
			},
			strings.NewReader(""),
			&output,
		)
		if err != nil {
			t.Fatalf("publish documented example %s: %v", name, err)
		}
		var result protocol.AnnouncementPublishResult
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatalf("decode documented example output %s: %v", name, err)
		}
		if result.Duplicate {
			t.Fatalf("documented example %s was unexpectedly duplicate", name)
		}
	}
}

func TestOperatorClaimReviewAndLeaderboardCLIFlow(t *testing.T) {
	deploymentID, claim := seedStructuredCLIClaim(t)

	var summaries bytes.Buffer
	if err := runListOperatorClaims(
		[]string{"--status", "PENDING_REVIEW", "--limit", "10"},
		&summaries,
	); err != nil {
		t.Fatalf("list pending operator claims: %v", err)
	}
	var list protocol.OperatorClaimReviewListPage
	if err := json.Unmarshal(summaries.Bytes(), &list); err != nil {
		t.Fatalf("decode pending list: %v; output=%s", err, summaries.String())
	}
	if len(list.Items) != 1 ||
		list.Items[0].DeploymentID != deploymentID ||
		list.Items[0].ClaimActionID != claim.Receipt.ActionID ||
		list.Items[0].VerificationStatus != protocol.OperatorVerificationStatusPendingReview {
		t.Fatalf("unexpected pending claim summaries: %+v", list)
	}
	if strings.Contains(summaries.String(), "reviewer@example.test") ||
		strings.Contains(summaries.String(), "Private Street") {
		t.Fatalf("summary CLI leaked private verification data: %s", summaries.String())
	}

	var detailOutput bytes.Buffer
	if err := runShowOperatorClaim(
		[]string{"--deployment-id", deploymentID},
		&detailOutput,
	); err != nil {
		t.Fatalf("show private operator claim: %v", err)
	}
	var detail protocol.OperatorClaimReviewDetail
	if err := json.Unmarshal(detailOutput.Bytes(), &detail); err != nil {
		t.Fatalf("decode private claim detail: %v", err)
	}
	if detail.VerificationContactEmail != "reviewer@example.test" ||
		detail.RegisteredAddress != "Private Street 7, Bratislava" {
		t.Fatalf("show command omitted private review fields: %+v", detail)
	}

	approveArgs := []string{
		"--deployment-id", deploymentID,
		"--claim-action-id", detail.ClaimActionID,
		"--group-id", detail.GroupID,
		"--legal-name", detail.LegalName,
		"--reviewer-id", "network-review-team",
		"--review-reference", "case:cli-0001",
		"--idempotency-key", "approve_cli_claim_0001",
	}
	var approvalOutput bytes.Buffer
	if err := runApproveOperatorClaim(approveArgs, &approvalOutput); err != nil {
		t.Fatalf("approve operator claim: %v", err)
	}
	var approval protocol.OperatorClaimReviewResult
	if err := json.Unmarshal(approvalOutput.Bytes(), &approval); err != nil {
		t.Fatalf("decode approval result: %v", err)
	}
	if approval.Duplicate ||
		approval.Receipt.ReviewerID != "network-review-team" ||
		approval.Receipt.ReviewReference != "case:cli-0001" {
		t.Fatalf("unexpected approval receipt: %+v", approval)
	}
	approvalOutput.Reset()
	if err := runApproveOperatorClaim(approveArgs, &approvalOutput); err != nil {
		t.Fatalf("repeat idempotent approval: %v", err)
	}
	if err := json.Unmarshal(approvalOutput.Bytes(), &approval); err != nil ||
		!approval.Duplicate {
		t.Fatalf("approval retry was not duplicate: %+v, error=%v", approval, err)
	}

	detailOutput.Reset()
	if err := runShowOperatorClaim(
		[]string{"--deployment-id", deploymentID},
		&detailOutput,
	); err != nil {
		t.Fatalf("show approved claim: %v", err)
	}
	if err := json.Unmarshal(detailOutput.Bytes(), &detail); err != nil ||
		detail.VerificationStatus != protocol.OperatorVerificationStatusApproved {
		t.Fatalf("show did not observe approval: %+v, error=%v", detail, err)
	}

	var leaderboardOutput bytes.Buffer
	if err := runLeaderboard(
		[]string{"--view", "claimed", "--limit", "1"},
		&leaderboardOutput,
	); err != nil {
		t.Fatalf("query leaderboard CLI: %v", err)
	}
	var leaderboard protocol.LeaderboardPageDto
	if err := json.Unmarshal(leaderboardOutput.Bytes(), &leaderboard); err != nil {
		t.Fatalf("decode leaderboard CLI output: %v", err)
	}
	if len(leaderboard.Items) != 1 ||
		leaderboard.Items[0].Label != "CLI Cooperative" ||
		leaderboard.Items[0].GroupID != claim.Receipt.GroupID {
		t.Fatalf("CLI leaderboard differs from API shape/data: %+v", leaderboard)
	}
}

func TestOperatorOperationalCLIFailsClosedWithoutInitializedRegistry(t *testing.T) {
	directory := t.TempDir()
	stateDirectory := filepath.Join(directory, "mistyped-volume")
	databasePath := filepath.Join(stateDirectory, "registry.db")
	keyPath := filepath.Join(stateDirectory, "registry-signing-key.pem")
	t.Setenv("REGISTRY_SCOPE", "example:operator-cli-preflight")
	t.Setenv("REGISTRY_DATABASE_PATH", databasePath)
	t.Setenv("REGISTRY_SIGNING_KEY_PATH", keyPath)
	t.Setenv("REGISTRY_GENERATE_SIGNING_KEY", "true")

	commands := []struct {
		name string
		run  func() error
	}{
		{
			name: "list",
			run: func() error {
				return runListOperatorClaims(nil, io.Discard)
			},
		},
		{
			name: "show",
			run: func() error {
				return runShowOperatorClaim(
					[]string{"--deployment-id", "dep_0123456789abcdef0123456789abcdef"},
					io.Discard,
				)
			},
		},
		{
			name: "approve",
			run: func() error {
				return runApproveOperatorClaim(
					[]string{
						"--deployment-id", "dep_0123456789abcdef0123456789abcdef",
						"--claim-action-id", "opa_0123456789abcdef0123456789abcdef",
						"--group-id", "opg_0123456789abcdef0123456789abcdef",
						"--legal-name", "Example Cooperative",
						"--reviewer-id", "reviewer-1",
						"--review-reference", "case-1",
						"--idempotency-key", "approval-12345678",
					},
					io.Discard,
				)
			},
		},
		{
			name: "leaderboard",
			run: func() error {
				return runLeaderboard(nil, io.Discard)
			},
		},
	}
	for _, command := range commands {
		if err := command.run(); err == nil {
			t.Fatalf("%s unexpectedly initialized a missing registry", command.name)
		}
		if _, err := os.Lstat(stateDirectory); !os.IsNotExist(err) {
			t.Fatalf(
				"%s created state on a missing registry path: %v",
				command.name,
				err,
			)
		}
	}

	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		t.Fatalf("create pristine state directory: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not-used-before-db-preflight"), 0o600); err != nil {
		t.Fatalf("write existing key sentinel: %v", err)
	}
	if err := os.WriteFile(databasePath, nil, 0o600); err != nil {
		t.Fatalf("write pristine database sentinel: %v", err)
	}
	if err := runLeaderboard(nil, io.Discard); err == nil {
		t.Fatalf("leaderboard accepted a pristine database without an identity")
	}
	info, err := os.Stat(databasePath)
	if err != nil {
		t.Fatalf("stat pristine database after rejection: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("preflight mutated pristine database to %d bytes", info.Size())
	}
	entries, err := os.ReadDir(stateDirectory)
	if err != nil {
		t.Fatalf("read pristine state directory: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("preflight created unexpected files: %+v", entries)
	}
}

func seedStructuredCLIClaim(
	t *testing.T,
) (string, protocol.OperatorActionResponse) {
	t.Helper()
	directory := t.TempDir()
	t.Setenv("REGISTRY_SCOPE", "example:cli-claims")
	t.Setenv("REGISTRY_DATABASE_PATH", filepath.Join(directory, "registry.db"))
	t.Setenv(
		"REGISTRY_SIGNING_KEY_PATH",
		filepath.Join(directory, "registry-signing-key.pem"),
	)
	t.Setenv("REGISTRY_GENERATE_SIGNING_KEY", "true")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load claim CLI config: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	runtime, err := app.Bootstrap(
		context.Background(),
		cfg,
		app.Options{Now: func() time.Time { return now }},
	)
	if err != nil {
		t.Fatalf("bootstrap claim CLI registry: %v", err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CLI deployment key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal CLI deployment key: %v", err)
	}
	encodedPublicKey := base64.StdEncoding.EncodeToString(publicDER)
	registration := protocol.RegistrationRequest{
		ProtocolVersion: protocol.Version,
		RegistryScope:   cfg.RegistryScope,
		Timestamp:       now.Format(time.RFC3339),
		Nonce:           "nonce_cli_claim_registration",
		IdempotencyKey:  "cli_claim_registration",
		KeyAlgorithm:    protocol.KeyAlgorithmEd25519,
		PublicKey:       encodedPublicKey,
		SoftwareVersion: "cli-claim-test",
	}
	registration.PayloadHash = protocol.Digest(protocol.RegistrationPayload(
		registration.KeyAlgorithm,
		registration.PublicKey,
		registration.SoftwareVersion,
	))
	registration.Signature = protocol.EncodeSignature(ed25519.Sign(
		privateKey,
		protocol.CanonicalRequest(
			"POST",
			protocol.RegistrationPath,
			registration.ProtocolVersion,
			registration.RegistryScope,
			protocol.PublicKeyFingerprint(publicDER),
			registration.Timestamp,
			registration.Nonce,
			registration.IdempotencyKey,
			registration.PayloadHash,
		),
	))
	registered, err := runtime.Service.RegisterDeployment(
		context.Background(),
		registration,
	)
	if err != nil {
		runtime.Close()
		t.Fatalf("register CLI claim deployment: %v", err)
	}
	claimRequest := protocol.OperatorActionRequest{
		ProtocolVersion:          protocol.Version,
		RegistryScope:            cfg.RegistryScope,
		DeploymentID:             registered.DeploymentID,
		Timestamp:                now.Format(time.RFC3339),
		Nonce:                    "nonce_cli_structured_claim",
		IdempotencyKey:           "cli_structured_claim",
		Action:                   protocol.OperatorActionClaim,
		LegalName:                "CLI Cooperative",
		RegistrationNumber:       "CLI-REG-1",
		Jurisdiction:             "Slovakia",
		RegisteredAddress:        "Private Street 7, Bratislava",
		Website:                  "https://cli.example.test",
		VerificationContactName:  "CLI Reviewer",
		VerificationContactRole:  "Director",
		VerificationContactEmail: "reviewer@example.test",
		AuthorityAttested:        true,
	}
	claimRequest.PayloadHash = protocol.Digest(protocol.OperatorClaimPayload(
		claimRequest.LegalName,
		claimRequest.RegistrationNumber,
		claimRequest.Jurisdiction,
		claimRequest.RegisteredAddress,
		claimRequest.Website,
		claimRequest.VerificationContactName,
		claimRequest.VerificationContactRole,
		claimRequest.VerificationContactEmail,
		claimRequest.AuthorityAttested,
		claimRequest.OperatorAvatarURL,
	))
	claimRequest.Signature = protocol.EncodeSignature(ed25519.Sign(
		privateKey,
		protocol.CanonicalRequest(
			"POST",
			protocol.OperatorActionPath,
			claimRequest.ProtocolVersion,
			claimRequest.RegistryScope,
			claimRequest.DeploymentID,
			claimRequest.Timestamp,
			claimRequest.Nonce,
			claimRequest.IdempotencyKey,
			claimRequest.PayloadHash,
		),
	))
	claim, err := runtime.Service.ApplyOperatorAction(
		context.Background(),
		claimRequest,
	)
	if err != nil {
		runtime.Close()
		t.Fatalf("submit CLI structured claim: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close claim seed runtime: %v", err)
	}
	return registered.DeploymentID, claim
}
