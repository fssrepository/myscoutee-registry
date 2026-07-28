package main

import (
	"bytes"
	"context"
	"encoding/json"
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
