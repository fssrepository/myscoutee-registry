//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

const (
	e2eScope       = "e2e:standalone-registry"
	e2eOtherScope  = "e2e:wrong-sovereign-scope"
	processTimeout = 15 * time.Second
)

type registryFiles struct {
	scope        string
	databasePath string
	keyPath      string
	directory    string
}

type registryProcess struct {
	baseURL string
	address string
	files   registryFiles
	command *exec.Cmd
	logPath string
	exited  chan struct{}
	mutex   sync.Mutex
	waitErr error
	stop    sync.Once
}

type healthResponse struct {
	Status          string `json:"status"`
	ProtocolVersion string `json:"protocol_version"`
	RegistryScope   string `json:"registry_scope"`
	RegistryKeyID   string `json:"registry_key_id"`
	LedgerIndex     int64  `json:"ledger_index"`
	EntryCount      int64  `json:"entry_count"`
	LedgerHeadHash  string `json:"ledger_head_hash"`
}

type errorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type httpResult struct {
	status int
	header http.Header
	body   []byte
}

func TestStandaloneRegistryBlackBox(t *testing.T) {
	repositoryRoot := registryRepositoryRoot(t)
	binary := buildRegistryBinary(t, repositoryRoot)

	t.Run("process identity and HTTP boundary", func(t *testing.T) {
		testProcessIdentityAndHTTPBoundary(t, binary)
	})
	t.Run("signed registration and receipt persistence", func(t *testing.T) {
		testSignedRegistrationAndReceiptPersistence(t, binary)
	})
	t.Run("scope and signing key remain bound to the database", func(t *testing.T) {
		testScopeAndSigningKeyBinding(t, binary)
	})
	t.Run("announcement CLI and HTTP server share durable state", func(t *testing.T) {
		testAnnouncementCLIAndHTTPPersistence(t, binary)
	})
}

func testProcessIdentityAndHTTPBoundary(t *testing.T, binary string) {
	files := newRegistryFiles(t, e2eScope)
	process := startRegistry(t, binary, files)

	health := readHealth(t, process)
	if health.Status != "ok" ||
		health.ProtocolVersion != protocol.Version ||
		health.RegistryScope != files.scope ||
		health.RegistryKeyID == "" ||
		health.LedgerIndex != 0 ||
		health.EntryCount != 0 ||
		health.LedgerHeadHash != protocol.ZeroHash {
		t.Fatalf("unexpected empty-registry health response: %+v", health)
	}

	identityResult := request(t, http.MethodGet, process.baseURL+protocol.IdentityPath, nil)
	assertStatus(t, identityResult, http.StatusOK)
	assertSecurityHeaders(t, identityResult)
	var identity protocol.RegistryIdentity
	decodeJSON(t, identityResult.body, &identity)
	registryPublicKey := verifyRegistryIdentity(t, identity, files.scope)
	if identity.RegistryKeyID != health.RegistryKeyID {
		t.Fatalf(
			"health key %q differs from identity key %q",
			health.RegistryKeyID,
			identity.RegistryKeyID,
		)
	}

	retry := request(t, http.MethodGet, process.baseURL+protocol.IdentityPath, nil)
	assertStatus(t, retry, http.StatusOK)
	if !bytes.Equal(identityResult.body, retry.body) {
		t.Fatal("read-only identity preflight changed between requests")
	}
	if afterIdentity := readHealth(t, process); afterIdentity != health {
		t.Fatalf(
			"read-only identity preflight mutated health/ledger state: before=%+v after=%+v",
			health,
			afterIdentity,
		)
	}

	queryAlias := request(
		t,
		http.MethodGet,
		process.baseURL+protocol.IdentityPath+"?alias=true",
		nil,
	)
	assertAPIError(t, queryAlias, http.StatusBadRequest, "invalid_request_target")

	wrongMethod := request(t, http.MethodGet, process.baseURL+protocol.RegistrationPath, nil)
	assertAPIError(t, wrongMethod, http.StatusMethodNotAllowed, "method_not_allowed")
	if wrongMethod.header.Get("Allow") != http.MethodPost {
		t.Fatalf("method rejection omitted Allow: POST: %v", wrongMethod.header)
	}

	unknownJSON := request(
		t,
		http.MethodPost,
		process.baseURL+protocol.RegistrationPath,
		[]byte(`{"protocol_version":"1","unknown":true}`),
	)
	assertAPIError(t, unknownJSON, http.StatusBadRequest, "invalid_json")

	announcements := request(
		t,
		http.MethodGet,
		process.baseURL+protocol.AnnouncementPath,
		nil,
	)
	assertStatus(t, announcements, http.StatusOK)
	var page protocol.AnnouncementPage
	decodeJSON(t, announcements.body, &page)
	if len(page.Items) != 0 ||
		page.Snapshot.RegistryScope != files.scope ||
		page.Snapshot.RegistryKeyID != identity.RegistryKeyID {
		t.Fatalf("unexpected empty announcement page: %+v", page)
	}
	verifyAnnouncementSnapshot(t, registryPublicKey, page.Snapshot)

	runRegistryCLI(t, binary, files, process.address, nil, "healthcheck")

	process.close(t)
	restarted := startRegistry(t, binary, files)
	restartedIdentityResult := request(
		t,
		http.MethodGet,
		restarted.baseURL+protocol.IdentityPath,
		nil,
	)
	assertStatus(t, restartedIdentityResult, http.StatusOK)
	if !bytes.Equal(identityResult.body, restartedIdentityResult.body) {
		t.Fatal("registry identity changed after a clean process restart")
	}
	if restartedHealth := readHealth(t, restarted); restartedHealth != health {
		t.Fatalf(
			"empty registry state changed after restart: before=%+v after=%+v",
			health,
			restartedHealth,
		)
	}
}

func testSignedRegistrationAndReceiptPersistence(t *testing.T, binary string) {
	files := newRegistryFiles(t, e2eScope)
	process := startRegistry(t, binary, files)

	identityResult := request(t, http.MethodGet, process.baseURL+protocol.IdentityPath, nil)
	assertStatus(t, identityResult, http.StatusOK)
	var identity protocol.RegistryIdentity
	decodeJSON(t, identityResult.body, &identity)
	registryPublicKey := verifyRegistryIdentity(t, identity, files.scope)

	_, deploymentPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate deployment signing key: %v", err)
	}
	registration := signedRegistration(
		t,
		deploymentPrivateKey,
		files.scope,
		wireNow(),
		"e2e_registration_nonce_0001",
		"e2e_registration_idempotency_0001",
		"registry-e2e-1.0.0",
	)

	invalidRegistration := registration
	invalidRegistration.Signature = corruptSignature(t, invalidRegistration.Signature)
	invalidResult := requestJSON(
		t,
		http.MethodPost,
		process.baseURL+protocol.RegistrationPath,
		invalidRegistration,
	)
	assertAPIError(t, invalidResult, http.StatusUnauthorized, "invalid_signature")
	if health := readHealth(t, process); health.EntryCount != 0 ||
		health.LedgerIndex != 0 ||
		health.LedgerHeadHash != protocol.ZeroHash {
		t.Fatalf("invalid registration mutated ledger state: %+v", health)
	}

	registrationResult := requestJSON(
		t,
		http.MethodPost,
		process.baseURL+protocol.RegistrationPath,
		registration,
	)
	assertStatus(t, registrationResult, http.StatusCreated)
	var acceptedRegistration protocol.RegistrationResponse
	decodeJSON(t, registrationResult.body, &acceptedRegistration)
	if acceptedRegistration.Duplicate ||
		acceptedRegistration.ProtocolVersion != protocol.Version ||
		acceptedRegistration.RegistryScope != files.scope ||
		acceptedRegistration.RegistryKeyID != identity.RegistryKeyID ||
		acceptedRegistration.RegistryPublicKey != identity.RegistryPublicKey ||
		acceptedRegistration.DeploymentID == "" {
		t.Fatalf("unexpected registration response: %+v", acceptedRegistration)
	}
	verifyRegistrationReceipt(t, registryPublicKey, acceptedRegistration)

	registrationRetry := requestJSON(
		t,
		http.MethodPost,
		process.baseURL+protocol.RegistrationPath,
		registration,
	)
	assertStatus(t, registrationRetry, http.StatusOK)
	var duplicateRegistration protocol.RegistrationResponse
	decodeJSON(t, registrationRetry.body, &duplicateRegistration)
	expectedRegistrationRetry := acceptedRegistration
	expectedRegistrationRetry.Duplicate = true
	if !reflect.DeepEqual(duplicateRegistration, expectedRegistrationRetry) {
		t.Fatalf(
			"idempotent registration did not return the immutable result: first=%+v retry=%+v",
			acceptedRegistration,
			duplicateRegistration,
		)
	}

	batch := signedInstallationBatch(
		t,
		deploymentPrivateKey,
		files.scope,
		acceptedRegistration.DeploymentID,
		wireNow(),
		"e2e_installation_nonce_0001",
		"e2e_installation_idempotency_0001",
		time.Now().UTC().Format("2006-01"),
	)
	batchResult := requestJSON(
		t,
		http.MethodPost,
		process.baseURL+protocol.BatchPath,
		batch,
	)
	assertStatus(t, batchResult, http.StatusCreated)
	var acceptedBatch protocol.BatchResponse
	decodeJSON(t, batchResult.body, &acceptedBatch)
	if acceptedBatch.Duplicate ||
		acceptedBatch.DeploymentID != acceptedRegistration.DeploymentID ||
		acceptedBatch.RegistryScope != files.scope ||
		acceptedBatch.BatchID == "" {
		t.Fatalf("unexpected installation-test response: %+v", acceptedBatch)
	}
	verifyInstallationReceipt(t, registryPublicKey, batch, acceptedBatch)

	batchRetry := signedInstallationBatch(
		t,
		deploymentPrivateKey,
		files.scope,
		acceptedRegistration.DeploymentID,
		wireNow(),
		"e2e_installation_nonce_0002",
		batch.IdempotencyKey,
		batch.Period,
	)
	batchRetryResult := requestJSON(
		t,
		http.MethodPost,
		process.baseURL+protocol.BatchPath,
		batchRetry,
	)
	assertStatus(t, batchRetryResult, http.StatusOK)
	var duplicateBatch protocol.BatchResponse
	decodeJSON(t, batchRetryResult.body, &duplicateBatch)
	expectedBatchRetry := acceptedBatch
	expectedBatchRetry.Duplicate = true
	if !reflect.DeepEqual(duplicateBatch, expectedBatchRetry) {
		t.Fatalf(
			"idempotent batch did not return the immutable receipt: first=%+v retry=%+v",
			acceptedBatch,
			duplicateBatch,
		)
	}

	receiptURL := process.baseURL + protocol.BatchPath + "/" +
		acceptedBatch.BatchID + "/receipt"
	receiptResult := request(t, http.MethodGet, receiptURL, nil)
	assertStatus(t, receiptResult, http.StatusOK)
	var lookedUpReceipt protocol.BatchResponse
	decodeJSON(t, receiptResult.body, &lookedUpReceipt)
	if !reflect.DeepEqual(lookedUpReceipt, expectedBatchRetry) {
		t.Fatalf("receipt lookup differs from accepted immutable receipt: %+v", lookedUpReceipt)
	}

	healthBeforeRestart := readHealth(t, process)
	if healthBeforeRestart.LedgerIndex != 1 ||
		healthBeforeRestart.EntryCount != 1 ||
		healthBeforeRestart.LedgerHeadHash != acceptedBatch.Receipt.EntryHash {
		t.Fatalf("health does not expose the accepted ledger head: %+v", healthBeforeRestart)
	}
	process.close(t)

	keyInfo, err := os.Stat(files.keyPath)
	if err != nil {
		t.Fatalf("stat generated signing key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("registry signing key mode = %04o, want 0600", keyInfo.Mode().Perm())
	}

	restarted := startRegistry(t, binary, files)
	restartedIdentityResult := request(
		t,
		http.MethodGet,
		restarted.baseURL+protocol.IdentityPath,
		nil,
	)
	assertStatus(t, restartedIdentityResult, http.StatusOK)
	if !bytes.Equal(identityResult.body, restartedIdentityResult.body) {
		t.Fatal("registry public identity changed after persisted receipt restart")
	}
	restartedReceipt := request(
		t,
		http.MethodGet,
		restarted.baseURL+protocol.BatchPath+"/"+acceptedBatch.BatchID+"/receipt",
		nil,
	)
	assertStatus(t, restartedReceipt, http.StatusOK)
	if !bytes.Equal(receiptResult.body, restartedReceipt.body) {
		t.Fatal("immutable installation receipt changed after restart")
	}
	if health := readHealth(t, restarted); health != healthBeforeRestart {
		t.Fatalf(
			"ledger head changed across restart: before=%+v after=%+v",
			healthBeforeRestart,
			health,
		)
	}
}

func testScopeAndSigningKeyBinding(t *testing.T, binary string) {
	files := newRegistryFiles(t, e2eScope)
	process := startRegistry(t, binary, files)
	originalIdentity := request(
		t,
		http.MethodGet,
		process.baseURL+protocol.IdentityPath,
		nil,
	)
	assertStatus(t, originalIdentity, http.StatusOK)
	process.close(t)

	wrongScope := files
	wrongScope.scope = e2eOtherScope
	output := runRegistryExpectFailure(t, binary, wrongScope)
	if !strings.Contains(output, "configured registry signing key does not match persisted registry identity") {
		t.Fatalf("scope mismatch failed for an unexpected reason:\n%s", output)
	}

	backupKeyPath := files.keyPath + ".backup"
	if err := os.Rename(files.keyPath, backupKeyPath); err != nil {
		t.Fatalf("temporarily move registry signing key: %v", err)
	}
	missingKeyOutput := runRegistryExpectFailure(t, binary, files)
	if !strings.Contains(missingKeyOutput, "registry signing key is absent") ||
		!strings.Contains(missingKeyOutput, "first-run generation is disabled") {
		t.Fatalf("missing key failed for an unexpected reason:\n%s", missingKeyOutput)
	}
	if _, err := os.Stat(files.keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-pristine database silently regenerated a missing key: %v", err)
	}
	if err := os.Rename(backupKeyPath, files.keyPath); err != nil {
		t.Fatalf("restore registry signing key: %v", err)
	}

	recovered := startRegistry(t, binary, files)
	recoveredIdentity := request(
		t,
		http.MethodGet,
		recovered.baseURL+protocol.IdentityPath,
		nil,
	)
	assertStatus(t, recoveredIdentity, http.StatusOK)
	if !bytes.Equal(originalIdentity.body, recoveredIdentity.body) {
		t.Fatal("restoring the correct key did not recover the original registry identity")
	}
}

func testAnnouncementCLIAndHTTPPersistence(t *testing.T, binary string) {
	files := newRegistryFiles(t, e2eScope)
	process := startRegistry(t, binary, files)
	identityResult := request(t, http.MethodGet, process.baseURL+protocol.IdentityPath, nil)
	assertStatus(t, identityResult, http.StatusOK)
	var identity protocol.RegistryIdentity
	decodeJSON(t, identityResult.body, &identity)
	registryPublicKey := verifyRegistryIdentity(t, identity, files.scope)

	now := time.Now().UTC().Truncate(time.Second)
	draft := protocol.AnnouncementDraft{
		ProtocolVersion: protocol.Version,
		PublicationID:   "e2e_publication_registry_0001",
		Kind:            protocol.AnnouncementKindGeneral,
		Severity:        protocol.AnnouncementSeverityNotice,
		PublishedAt:     now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:       now.Add(24 * time.Hour).Format(time.RFC3339),
		TitleKey:        "registry.e2e.announcement.title",
		BodyKey:         "registry.e2e.announcement.body",
		Links: []protocol.AnnouncementLink{{
			Relation: "details",
			URL:      "https://example.test/registry-e2e-announcement",
		}},
	}
	draftPath := filepath.Join(files.directory, "announcement.json")
	draftJSON, err := json.Marshal(draft)
	if err != nil {
		t.Fatalf("encode announcement draft: %v", err)
	}
	if err := os.WriteFile(draftPath, draftJSON, 0o600); err != nil {
		t.Fatalf("write announcement draft: %v", err)
	}

	publishOutput := runRegistryCLI(
		t,
		binary,
		files,
		process.address,
		nil,
		"publish-announcement",
		"--file",
		draftPath,
	)
	var published protocol.AnnouncementPublishResult
	decodeJSON(t, publishOutput, &published)
	if published.Duplicate ||
		published.Announcement.PublicationID != draft.PublicationID ||
		published.Announcement.RegistryKeyID != identity.RegistryKeyID {
		t.Fatalf("unexpected CLI publication result: %+v", published)
	}
	verifyAnnouncementEntry(t, registryPublicKey, published.Announcement)

	feedResult := request(t, http.MethodGet, process.baseURL+protocol.AnnouncementPath, nil)
	assertStatus(t, feedResult, http.StatusOK)
	var feed protocol.AnnouncementPage
	decodeJSON(t, feedResult.body, &feed)
	if len(feed.Items) != 1 ||
		feed.Items[0].AnnouncementID != published.Announcement.AnnouncementID {
		t.Fatalf("running HTTP process did not observe CLI publication: %+v", feed)
	}
	verifyAnnouncementSnapshot(t, registryPublicKey, feed.Snapshot)
	verifyAnnouncementEntry(t, registryPublicKey, feed.Items[0])

	duplicateOutput := runRegistryCLI(
		t,
		binary,
		files,
		process.address,
		draftJSON,
		"publish-announcement",
		"--file",
		"-",
	)
	var duplicate protocol.AnnouncementPublishResult
	decodeJSON(t, duplicateOutput, &duplicate)
	if !duplicate.Duplicate ||
		duplicate.Announcement.AnnouncementID != published.Announcement.AnnouncementID {
		t.Fatalf("CLI retry did not return the original publication: %+v", duplicate)
	}

	process.close(t)
	restarted := startRegistry(t, binary, files)
	restartedFeedResult := request(
		t,
		http.MethodGet,
		restarted.baseURL+protocol.AnnouncementPath,
		nil,
	)
	assertStatus(t, restartedFeedResult, http.StatusOK)
	var restartedFeed protocol.AnnouncementPage
	decodeJSON(t, restartedFeedResult.body, &restartedFeed)
	if len(restartedFeed.Items) != 1 ||
		restartedFeed.Items[0].AnnouncementID != published.Announcement.AnnouncementID ||
		restartedFeed.Items[0].PublicationID != draft.PublicationID {
		t.Fatalf("announcement did not persist across process restart: %+v", restartedFeed)
	}
	verifyAnnouncementSnapshot(t, registryPublicKey, restartedFeed.Snapshot)
	verifyAnnouncementEntry(t, registryPublicKey, restartedFeed.Items[0])
}

func registryRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve E2E source location")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), ".."))
}

func buildRegistryBinary(t *testing.T, repositoryRoot string) string {
	t.Helper()
	buildDirectory := t.TempDir()
	binary := filepath.Join(buildDirectory, "myscoutee-registry-e2e")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		"go",
		"build",
		"-trimpath",
		"-o",
		binary,
		"./cmd/registry",
	)
	command.Dir = repositoryRoot
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build registry E2E binary: %v\n%s", err, output)
	}
	return binary
}

func newRegistryFiles(t *testing.T, scope string) registryFiles {
	t.Helper()
	directory := t.TempDir()
	return registryFiles{
		scope:        scope,
		databasePath: filepath.Join(directory, "registry.db"),
		keyPath:      filepath.Join(directory, "registry-signing-key.pem"),
		directory:    directory,
	}
}

func startRegistry(t *testing.T, binary string, files registryFiles) *registryProcess {
	t.Helper()
	const requestedAddress = "127.0.0.1:0"
	logFile, err := os.CreateTemp(files.directory, "registry-process-*.log")
	if err != nil {
		t.Fatalf("create registry process log: %v", err)
	}
	command := exec.Command(binary)
	command.Env = registryEnvironment(files, requestedAddress)
	command.Stdout = logFile
	command.Stderr = logFile
	process := &registryProcess{
		files:   files,
		command: command,
		logPath: logFile.Name(),
		exited:  make(chan struct{}),
	}
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		t.Fatalf("start registry process: %v", err)
	}
	go func() {
		waitErr := command.Wait()
		_ = logFile.Close()
		process.mutex.Lock()
		process.waitErr = waitErr
		process.mutex.Unlock()
		close(process.exited)
	}()

	deadline := time.Now().Add(processTimeout)
	for {
		select {
		case <-process.exited:
			t.Fatalf(
				"registry exited before becoming ready: %v\n%s",
				process.exitError(),
				process.logs(),
			)
		default:
		}
		if address, found := acceptingAddress(process.logs()); found {
			process.address = address
			process.baseURL = "http://" + address
			client := &http.Client{Timeout: 250 * time.Millisecond}
			response, requestErr := client.Get(process.baseURL + "/healthz")
			if requestErr == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					t.Cleanup(func() {
						process.close(t)
					})
					return process
				}
			}
		}
		if time.Now().After(deadline) {
			process.close(t)
			t.Fatalf("registry did not become ready within %s\n%s", processTimeout, process.logs())
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (process *registryProcess) close(t *testing.T) {
	t.Helper()
	process.stop.Do(func() {
		select {
		case <-process.exited:
		default:
			if err := process.command.Process.Signal(os.Interrupt); err != nil {
				t.Errorf("signal registry process: %v", err)
				_ = process.command.Process.Kill()
			}
		}
		select {
		case <-process.exited:
			if err := process.exitError(); err != nil {
				t.Errorf("registry did not shut down cleanly: %v\n%s", err, process.logs())
			}
		case <-time.After(10 * time.Second):
			_ = process.command.Process.Kill()
			<-process.exited
			t.Errorf("registry did not stop within 10s\n%s", process.logs())
		}
	})
}

func (process *registryProcess) exitError() error {
	process.mutex.Lock()
	defer process.mutex.Unlock()
	return process.waitErr
}

func (process *registryProcess) logs() string {
	contents, err := os.ReadFile(process.logPath)
	if err != nil {
		return fmt.Sprintf("<read process log: %v>", err)
	}
	return string(contents)
}

func acceptingAddress(logs string) (string, bool) {
	for _, line := range strings.Split(logs, "\n") {
		var event struct {
			Message string `json:"msg"`
			Address string `json:"address"`
		}
		if json.Unmarshal([]byte(line), &event) == nil &&
			event.Message == "registry is accepting requests" &&
			event.Address != "" {
			return event.Address, true
		}
	}
	return "", false
}

func registryEnvironment(files registryFiles, address string) []string {
	replacements := map[string]string{
		"REGISTRY_LISTEN_ADDR":                       address,
		"REGISTRY_SCOPE":                             files.scope,
		"REGISTRY_DATABASE_PATH":                     files.databasePath,
		"REGISTRY_SIGNING_KEY_PATH":                  files.keyPath,
		"REGISTRY_GENERATE_SIGNING_KEY":              "true",
		"REGISTRY_DEMO_SEED":                         "false",
		"REGISTRY_TIMESTAMP_SKEW":                    "5m",
		"REGISTRY_MAX_REQUEST_BODY_BYTES":            "65536",
		"REGISTRY_VALUATION_MULTIPLIER_BASIS_POINTS": "30000",
		"REGISTRY_CHECKPOINT_INTERVAL":               "1h",
		"REGISTRY_SHUTDOWN_TIMEOUT":                  "3s",
		"REGISTRY_HEALTHCHECK_URL":                   "http://" + address + "/healthz",
	}
	environment := make([]string, 0, len(os.Environ())+len(replacements))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if _, replaced := replacements[name]; !replaced {
			environment = append(environment, entry)
		}
	}
	for name, value := range replacements {
		environment = append(environment, name+"="+value)
	}
	return environment
}

func runRegistryCLI(
	t *testing.T,
	binary string,
	files registryFiles,
	address string,
	stdin []byte,
	arguments ...string,
) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), processTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Env = registryEnvironment(files, address)
	if stdin != nil {
		command.Stdin = bytes.NewReader(stdin)
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("registry CLI %q failed: %v\n%s", arguments, err, output)
	}
	return output
}

func runRegistryExpectFailure(t *testing.T, binary string, files registryFiles) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary)
	command.Env = registryEnvironment(files, "127.0.0.1:0")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("registry unexpectedly remained running with invalid identity binding:\n%s", output)
	}
	if err == nil {
		t.Fatalf("registry unexpectedly started with invalid identity binding:\n%s", output)
	}
	return string(output)
}

func requestJSON(t *testing.T, method, endpoint string, value any) httpResult {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode request JSON: %v", err)
	}
	return request(t, method, endpoint, body)
}

func request(t *testing.T, method, endpoint string, body []byte) httpResult {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	httpRequest, err := http.NewRequest(method, endpoint, reader)
	if err != nil {
		t.Fatalf("build HTTP request: %v", err)
	}
	if body != nil {
		httpRequest.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		t.Fatalf("%s %s: %v", method, endpoint, err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024))
	if err != nil {
		t.Fatalf("read %s %s response: %v", method, endpoint, err)
	}
	return httpResult{
		status: response.StatusCode,
		header: response.Header.Clone(),
		body:   responseBody,
	}
}

func readHealth(t *testing.T, process *registryProcess) healthResponse {
	t.Helper()
	result := request(t, http.MethodGet, process.baseURL+"/healthz", nil)
	assertStatus(t, result, http.StatusOK)
	assertSecurityHeaders(t, result)
	var health healthResponse
	decodeJSON(t, result.body, &health)
	return health
}

func assertStatus(t *testing.T, result httpResult, expected int) {
	t.Helper()
	if result.status != expected {
		t.Fatalf("HTTP status = %d, want %d; body=%s", result.status, expected, result.body)
	}
}

func assertSecurityHeaders(t *testing.T, result httpResult) {
	t.Helper()
	if result.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("response omitted X-Content-Type-Options: nosniff: %v", result.header)
	}
	if mediaType := result.header.Get("Content-Type"); !strings.HasPrefix(mediaType, "application/json") {
		t.Fatalf("response Content-Type = %q, want application/json", mediaType)
	}
}

func assertAPIError(t *testing.T, result httpResult, expectedStatus int, expectedCode string) {
	t.Helper()
	assertStatus(t, result, expectedStatus)
	assertSecurityHeaders(t, result)
	var envelope errorResponse
	decodeJSON(t, result.body, &envelope)
	if envelope.Error.Code != expectedCode || envelope.Error.Message == "" {
		t.Fatalf(
			"API error = %+v, want non-empty %q error",
			envelope.Error,
			expectedCode,
		)
	}
}

func decodeJSON(t *testing.T, contents []byte, destination any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode JSON response: %v; body=%s", err, contents)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("JSON response has trailing data: %v; body=%s", err, contents)
	}
}

func wireNow() string {
	return time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
}

func signedRegistration(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	scope string,
	timestamp string,
	nonce string,
	idempotencyKey string,
	softwareVersion string,
) protocol.RegistrationRequest {
	t.Helper()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	encodedPublicKey, publicKeyDER, err := protocol.EncodePublicKey(publicKey)
	if err != nil {
		t.Fatalf("encode deployment public key: %v", err)
	}
	request := protocol.RegistrationRequest{
		ProtocolVersion: protocol.Version,
		RegistryScope:   scope,
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
	request.Signature = protocol.EncodeSignature(ed25519.Sign(
		privateKey,
		protocol.CanonicalRequest(
			http.MethodPost,
			protocol.RegistrationPath,
			request.ProtocolVersion,
			request.RegistryScope,
			protocol.PublicKeyFingerprint(publicKeyDER),
			request.Timestamp,
			request.Nonce,
			request.IdempotencyKey,
			request.PayloadHash,
		),
	))
	return request
}

func signedInstallationBatch(
	t *testing.T,
	privateKey ed25519.PrivateKey,
	scope string,
	deploymentID string,
	timestamp string,
	nonce string,
	idempotencyKey string,
	period string,
) protocol.BatchRequest {
	t.Helper()
	request := protocol.BatchRequest{
		ProtocolVersion:   protocol.Version,
		RegistryScope:     scope,
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

func corruptSignature(t *testing.T, encoded string) string {
	t.Helper()
	signature, err := protocol.ParseSignature(encoded)
	if err != nil {
		t.Fatalf("parse generated signature: %v", err)
	}
	signature[0] ^= 0xff
	return protocol.EncodeSignature(signature)
}

func verifyRegistryIdentity(
	t *testing.T,
	identity protocol.RegistryIdentity,
	expectedScope string,
) ed25519.PublicKey {
	t.Helper()
	if identity.ProtocolVersion != protocol.Version ||
		identity.RegistryScope != expectedScope ||
		identity.RegistryKeyID == "" ||
		identity.RegistryPublicKey == "" ||
		identity.Signature == "" {
		t.Fatalf("registry identity is incomplete: %+v", identity)
	}
	publicKey, publicKeyDER, err := protocol.ParsePublicKey(identity.RegistryPublicKey)
	if err != nil {
		t.Fatalf("parse registry public key: %v", err)
	}
	if identity.RegistryKeyID != protocol.RegistryKeyID(publicKeyDER) {
		t.Fatal("registry key ID does not match the advertised public key")
	}
	signature, err := protocol.ParseSignature(identity.Signature)
	if err != nil {
		t.Fatalf("parse registry identity signature: %v", err)
	}
	if !protocol.Verify(
		publicKey,
		protocol.RegistryIdentityMessage(
			identity.ProtocolVersion,
			identity.RegistryScope,
			identity.RegistryKeyID,
			identity.RegistryPublicKey,
		),
		signature,
	) {
		t.Fatal("registry identity self-signature is invalid")
	}
	return publicKey
}

func verifyRegistrationReceipt(
	t *testing.T,
	registryPublicKey ed25519.PublicKey,
	response protocol.RegistrationResponse,
) {
	t.Helper()
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
		t.Fatal("registration receipt signature is invalid")
	}
}

func verifyInstallationReceipt(
	t *testing.T,
	registryPublicKey ed25519.PublicKey,
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
		receipt.Kind != protocol.InstallationTestKind ||
		receipt.QualifiedMAUCount != 0 ||
		receipt.EntryHash != protocol.Digest(protocol.LedgerEntryMessage(entry)) {
		t.Fatalf("installation receipt does not describe a valid first ledger entry: %+v", receipt)
	}
	signature, err := protocol.ParseSignature(receipt.Signature)
	if err != nil {
		t.Fatalf("parse installation receipt signature: %v", err)
	}
	if !protocol.Verify(
		registryPublicKey,
		protocol.MAUReceiptMessage(
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
		),
		signature,
	) {
		t.Fatal("installation receipt registry signature is invalid")
	}
}

func verifyAnnouncementEntry(
	t *testing.T,
	registryPublicKey ed25519.PublicKey,
	entry protocol.AnnouncementEntry,
) {
	t.Helper()
	expectedContentHash := protocol.Digest(protocol.AnnouncementContentMessage(
		entry.TitleKey,
		entry.BodyKey,
		entry.Localizations,
	))
	expectedLinksHash := protocol.Digest(protocol.AnnouncementLinksMessage(entry.Links))
	expectedManifestHash := protocol.AnnouncementZeroHash
	if entry.UpdateManifest != nil {
		expectedManifestHash = protocol.Digest(protocol.UpdateManifestMessage(*entry.UpdateManifest))
	}
	if entry.ContentHash != expectedContentHash ||
		entry.LinksHash != expectedLinksHash ||
		entry.UpdateManifestHash != expectedManifestHash ||
		entry.AnnouncementHash != protocol.Digest(protocol.AnnouncementEntryMessage(entry)) {
		t.Fatalf("announcement hashes are invalid: %+v", entry)
	}
	signature, err := protocol.ParseSignature(entry.Signature)
	if err != nil {
		t.Fatalf("parse announcement signature: %v", err)
	}
	if !protocol.Verify(
		registryPublicKey,
		protocol.AnnouncementReceiptMessage(entry),
		signature,
	) {
		t.Fatal("announcement registry signature is invalid")
	}
}

func verifyAnnouncementSnapshot(
	t *testing.T,
	registryPublicKey ed25519.PublicKey,
	snapshot protocol.AnnouncementSnapshot,
) {
	t.Helper()
	if snapshot.SnapshotHash != protocol.Digest(
		protocol.AnnouncementSnapshotHashMessage(snapshot),
	) {
		t.Fatalf("announcement snapshot hash is invalid: %+v", snapshot)
	}
	signature, err := protocol.ParseSignature(snapshot.Signature)
	if err != nil {
		t.Fatalf("parse announcement snapshot signature: %v", err)
	}
	if !protocol.Verify(
		registryPublicKey,
		protocol.AnnouncementSnapshotReceiptMessage(snapshot),
		signature,
	) {
		t.Fatal("announcement snapshot registry signature is invalid")
	}
}
