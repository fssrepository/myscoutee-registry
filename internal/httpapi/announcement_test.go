package httpapi_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/fssrepository/myscoutee-registry/internal/app"
	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	_ "modernc.org/sqlite"
)

func TestSignedAnnouncementFeedPaginationExpiryAndTamperDetection(t *testing.T) {
	fixture := newOperatorAPIFixture(t)

	general := announcementDraft(
		"publication_general_active",
		protocol.AnnouncementKindGeneral,
		protocol.AnnouncementSeverityNotice,
		"2026-07-28T08:00:00Z",
		"2026-07-29T08:00:00Z",
	)
	generalResult := publishAnnouncement(t, fixture, general)
	if generalResult.Duplicate {
		t.Fatalf("new general announcement reported as duplicate")
	}
	assertAnnouncementSignature(t, fixture, generalResult.Announcement)

	duplicate := publishAnnouncement(t, fixture, general)
	if !duplicate.Duplicate ||
		!reflect.DeepEqual(duplicate.Announcement, generalResult.Announcement) {
		t.Fatalf("idempotent publication did not return the original entry")
	}
	conflict := general
	conflict.Localizations[0].Body = "Changed contents"
	if _, err := fixture.runtime.Service.PublishAnnouncement(
		context.Background(),
		conflict,
	); err == nil {
		t.Fatalf("publication ID conflict unexpectedly succeeded")
	}

	expired := announcementDraft(
		"publication_maintenance_expired",
		protocol.AnnouncementKindMaintenance,
		protocol.AnnouncementSeverityWarning,
		"2026-07-27T08:00:00Z",
		"2026-07-28T10:00:00Z",
	)
	publishAnnouncement(t, fixture, expired)

	stable := announcementDraft(
		"publication_update_stable",
		protocol.AnnouncementKindUpdate,
		protocol.AnnouncementSeverityCritical,
		"2026-07-28T09:00:00Z",
		"",
	)
	stableManifest := announcementUpdateManifest("1.2.3", "stable")
	stableManifest.PublishedAt = stable.PublishedAt
	packagePublicKey, packagePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate package-signing key: %v", err)
	}
	packagePublicKeyDER, err := x509.MarshalPKIXPublicKey(packagePublicKey)
	if err != nil {
		t.Fatalf("marshal package-signing public key: %v", err)
	}
	stableManifest.PackageSigningKeyID = protocol.PackageSigningKeyID(
		packagePublicKeyDER,
	)
	stableManifest.PackageSignature = protocol.EncodeSignature(ed25519.Sign(
		packagePrivateKey,
		protocol.UpdatePackageSignatureMessage(stableManifest),
	))
	stable.UpdateManifest = &stableManifest
	stableResult := publishAnnouncement(t, fixture, stable)
	assertAnnouncementSignature(t, fixture, stableResult.Announcement)

	beta := announcementDraft(
		"publication_update_beta",
		protocol.AnnouncementKindUpdate,
		protocol.AnnouncementSeverityInfo,
		"2026-07-28T10:00:00Z",
		"",
	)
	betaManifest := announcementUpdateManifest("1.3.0-beta.1", "beta")
	betaManifest.PublishedAt = beta.PublishedAt
	betaManifest.SupersedesVersion = ""
	beta.UpdateManifest = &betaManifest
	publishAnnouncement(t, fixture, beta)

	future := announcementDraft(
		"publication_security_future",
		protocol.AnnouncementKindSecurity,
		protocol.AnnouncementSeverityCritical,
		"2026-07-29T00:00:00Z",
		"",
	)
	publishAnnouncement(t, fixture, future)

	first := fetchAnnouncements(t, fixture, "limit=2")
	if sequences(first.Items) == nil ||
		!reflect.DeepEqual(sequences(first.Items), []int64{4, 3}) ||
		first.NextCursor == "" {
		t.Fatalf("unexpected first announcement page: %+v", first)
	}
	assertAnnouncementSnapshot(t, fixture, first.Snapshot)
	for _, entry := range first.Items {
		assertAnnouncementSignature(t, fixture, entry)
	}

	late := announcementDraft(
		"publication_general_after_snapshot",
		protocol.AnnouncementKindGeneral,
		protocol.AnnouncementSeverityInfo,
		"2026-07-28T11:00:00Z",
		"",
	)
	publishAnnouncement(t, fixture, late)

	second := fetchAnnouncements(
		t,
		fixture,
		"limit=2&cursor="+url.QueryEscape(first.NextCursor),
	)
	if !reflect.DeepEqual(sequences(second.Items), []int64{1}) ||
		second.NextCursor != "" ||
		!reflect.DeepEqual(second.Snapshot, first.Snapshot) {
		t.Fatalf("cursor traversal was not snapshot-bound: %+v", second)
	}

	status, body := rawRequest(
		t,
		http.MethodGet,
		fixture.server.URL+protocol.AnnouncementPath+
			"?limit=2&cursor="+url.QueryEscape(tamperCursor(first.NextCursor)),
		nil,
		false,
	)
	assertAPIError(t, status, body, http.StatusBadRequest, "invalid_cursor")
	status, body = rawRequest(
		t,
		http.MethodGet,
		fixture.server.URL+protocol.AnnouncementPath+
			"?kind=UPDATE&limit=2&cursor="+url.QueryEscape(first.NextCursor),
		nil,
		false,
	)
	assertAPIError(t, status, body, http.StatusBadRequest, "invalid_cursor")

	stablePage := fetchAnnouncements(
		t,
		fixture,
		"kind=UPDATE&channel=stable",
	)
	if !reflect.DeepEqual(sequences(stablePage.Items), []int64{3}) ||
		stablePage.Items[0].UpdateManifest == nil ||
		stablePage.Items[0].UpdateManifest.ReleaseVersion != "1.2.3" {
		t.Fatalf("stable update filter returned unexpected entries: %+v", stablePage)
	}
	storedManifest := *stablePage.Items[0].UpdateManifest
	packageSignature, err := protocol.ParseSignature(
		storedManifest.PackageSignature,
	)
	if err != nil || !ed25519.Verify(
		packagePublicKey,
		protocol.UpdatePackageSignatureMessage(storedManifest),
		packageSignature,
	) {
		t.Fatalf("stored detached package signature did not verify")
	}
	activeMaintenance := fetchAnnouncements(
		t,
		fixture,
		"kind=MAINTENANCE",
	)
	if len(activeMaintenance.Items) != 0 {
		t.Fatalf("expired announcement appeared in active feed")
	}
	expiredMaintenance := fetchAnnouncements(
		t,
		fixture,
		"kind=MAINTENANCE&include_expired=true",
	)
	if !reflect.DeepEqual(sequences(expiredMaintenance.Items), []int64{2}) {
		t.Fatalf("include_expired did not return expired announcement")
	}
	futureSecurity := fetchAnnouncements(
		t,
		fixture,
		"kind=SECURITY&include_expired=true",
	)
	if len(futureSecurity.Items) != 0 {
		t.Fatalf("future publication appeared before published_at")
	}

	status, body = rawRequest(
		t,
		http.MethodGet,
		fixture.server.URL+protocol.AnnouncementPath+"?unknown=true",
		nil,
		false,
	)
	assertAPIError(t, status, body, http.StatusBadRequest, "invalid_request")
	status, body = rawRequest(
		t,
		http.MethodGet,
		fixture.server.URL+protocol.AnnouncementPath+"?include_expired=",
		nil,
		false,
	)
	assertAPIError(t, status, body, http.StatusBadRequest, "invalid_request")
	status, body = rawRequest(
		t,
		http.MethodPost,
		fixture.server.URL+protocol.AnnouncementPath,
		[]byte(`{}`),
		true,
	)
	assertAPIError(t, status, body, http.StatusMethodNotAllowed, "method_not_allowed")

	corruptAnnouncementTable(t, fixture)
	status, body = rawRequest(
		t,
		http.MethodGet,
		fixture.server.URL+protocol.AnnouncementPath,
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

func TestLiveCLIStyleCommitUsesBoundedOperationalBoundary(t *testing.T) {
	fixture := newOperatorAPIFixture(t)
	fullAudits := fixture.runtime.Service.FullVerificationRuns()

	cliRuntime, err := app.Bootstrap(
		context.Background(),
		fixture.cfg,
		app.Options{Now: fixture.clock.Now},
	)
	if err != nil {
		t.Fatalf("open independent CLI-style registry runtime: %v", err)
	}
	draft := announcementDraft(
		"publication_external_cli_boundary",
		protocol.AnnouncementKindGeneral,
		protocol.AnnouncementSeverityNotice,
		"2026-07-28T11:00:00Z",
		"",
	)
	if _, err := cliRuntime.Service.PublishAnnouncement(
		context.Background(),
		draft,
	); err != nil {
		cliRuntime.Close()
		t.Fatalf("publish through independent CLI-style connection: %v", err)
	}
	if err := cliRuntime.Close(); err != nil {
		t.Fatalf("close independent CLI-style registry runtime: %v", err)
	}

	page := fetchAnnouncements(t, fixture, "limit=20")
	if len(page.Items) != 1 ||
		page.Items[0].PublicationID != draft.PublicationID {
		t.Fatalf("primary runtime did not accept bounded external commit: %+v", page.Items)
	}
	if got := fixture.runtime.Service.FullVerificationRuns(); got != fullAudits {
		t.Fatalf(
			"external CLI-style commit caused %d request-path full audits",
			got-fullAudits,
		)
	}
}

func announcementDraft(
	publicationID string,
	kind string,
	severity string,
	publishedAt string,
	expiresAt string,
) protocol.AnnouncementDraft {
	return protocol.AnnouncementDraft{
		ProtocolVersion: protocol.Version,
		PublicationID:   publicationID,
		Kind:            kind,
		Severity:        severity,
		PublishedAt:     publishedAt,
		ExpiresAt:       expiresAt,
		Localizations: []protocol.AnnouncementLocalization{
			{
				Locale: "en",
				Title:  "Operator notice",
				Body:   "Registry-signed information for deployment operators.",
			},
			{
				Locale: "hu",
				Title:  "Üzemeltetői értesítés",
				Body:   "A registry által aláírt üzemeltetői tájékoztató.",
			},
		},
		Links: []protocol.AnnouncementLink{{
			Relation: "details",
			URL:      "https://community.example.test/operator-notice",
		}},
	}
}

func announcementUpdateManifest(
	version string,
	channel string,
) protocol.UpdateManifest {
	return protocol.UpdateManifest{
		ManifestVersion:          protocol.UpdateManifestVersion,
		ReleaseVersion:           version,
		Channel:                  channel,
		PublishedAt:              "2026-07-28T09:00:00Z",
		MinimumCompatibleVersion: "1.0.0",
		MaximumCompatibleVersion: "1.2.2",
		ArtifactURL: "https://github.com/example/myscoutee/releases/download/v" +
			version + "/myscoutee_" + version + "_amd64.deb",
		ArtifactSizeBytes:       1_048_576,
		ArtifactSHA256:          "sha256:" + strings.Repeat("a", 64),
		PackageSigningKeyID:     "pkey_" + strings.Repeat("b", 32),
		PackageSignature:        protocol.EncodeSignature(make([]byte, 64)),
		ReleaseNotesURL:         "https://github.com/example/myscoutee/releases/tag/v" + version,
		BackupRequired:          true,
		ExpectedDowntimeSeconds: 120,
		Status:                  protocol.UpdateStatusAvailable,
		SupersedesVersion:       "1.2.2",
	}
}

func publishAnnouncement(
	t *testing.T,
	fixture *operatorAPIFixture,
	draft protocol.AnnouncementDraft,
) protocol.AnnouncementPublishResult {
	t.Helper()
	result, err := fixture.runtime.Service.PublishAnnouncement(
		context.Background(),
		draft,
	)
	if err != nil {
		t.Fatalf("publish announcement %s: %v", draft.PublicationID, err)
	}
	return result
}

func fetchAnnouncements(
	t *testing.T,
	fixture *operatorAPIFixture,
	rawQuery string,
) protocol.AnnouncementPage {
	t.Helper()
	endpoint := fixture.server.URL + protocol.AnnouncementPath
	if rawQuery != "" {
		endpoint += "?" + rawQuery
	}
	status, body := rawRequest(t, http.MethodGet, endpoint, nil, false)
	if status != http.StatusOK {
		t.Fatalf("announcement feed status = %d, body = %s", status, body)
	}
	var page protocol.AnnouncementPage
	decodeResponse(t, body, &page)
	return page
}

func assertAnnouncementSignature(
	t *testing.T,
	fixture *operatorAPIFixture,
	entry protocol.AnnouncementEntry,
) {
	t.Helper()
	expectedContentHash := protocol.Digest(
		protocol.AnnouncementContentMessage(
			entry.TitleKey,
			entry.BodyKey,
			entry.Localizations,
		),
	)
	expectedLinksHash := protocol.Digest(
		protocol.AnnouncementLinksMessage(entry.Links),
	)
	expectedManifestHash := protocol.AnnouncementZeroHash
	if entry.UpdateManifest != nil {
		expectedManifestHash = protocol.Digest(
			protocol.UpdateManifestMessage(*entry.UpdateManifest),
		)
	}
	if entry.ContentHash != expectedContentHash ||
		entry.LinksHash != expectedLinksHash ||
		entry.UpdateManifestHash != expectedManifestHash ||
		entry.AnnouncementHash != protocol.Digest(
			protocol.AnnouncementEntryMessage(entry),
		) {
		t.Fatalf("announcement hashes do not verify: %+v", entry)
	}
	signature, err := protocol.ParseSignature(entry.Signature)
	if err != nil {
		t.Fatalf("parse announcement signature: %v", err)
	}
	if !protocol.Verify(
		fixture.runtime.SigningKey.PublicKey(),
		protocol.AnnouncementReceiptMessage(entry),
		signature,
	) {
		t.Fatalf("announcement registry signature verification failed")
	}
}

func assertAnnouncementSnapshot(
	t *testing.T,
	fixture *operatorAPIFixture,
	snapshot protocol.AnnouncementSnapshot,
) {
	t.Helper()
	if snapshot.RegistryScope != testRegistryScope ||
		snapshot.RegistryKeyID != fixture.runtime.SigningKey.KeyID() ||
		snapshot.SnapshotHash != protocol.Digest(
			protocol.AnnouncementSnapshotHashMessage(snapshot),
		) {
		t.Fatalf("announcement snapshot metadata does not verify: %+v", snapshot)
	}
	signature, err := protocol.ParseSignature(snapshot.Signature)
	if err != nil {
		t.Fatalf("parse announcement snapshot signature: %v", err)
	}
	if !protocol.Verify(
		fixture.runtime.SigningKey.PublicKey(),
		protocol.AnnouncementSnapshotReceiptMessage(snapshot),
		signature,
	) {
		t.Fatalf("announcement snapshot signature verification failed")
	}
}

func sequences(entries []protocol.AnnouncementEntry) []int64 {
	if len(entries) == 0 {
		return []int64{}
	}
	result := make([]int64, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry.Sequence)
	}
	return result
}

func corruptAnnouncementTable(
	t *testing.T,
	fixture *operatorAPIFixture,
) {
	t.Helper()
	db, err := sql.Open(
		"sqlite",
		"file:"+fixture.cfg.DatabasePath+"?_pragma=busy_timeout(5000)",
	)
	if err != nil {
		t.Fatalf("open corruption-test database: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`
		UPDATE announcements
		SET severity = 'CRITICAL'
		WHERE sequence = 1`); err == nil {
		t.Fatalf("append-only announcement trigger accepted an update")
	}
	if _, err := db.Exec(`
		DELETE FROM announcements
		WHERE sequence = 1`); err == nil {
		t.Fatalf("append-only announcement trigger accepted a delete")
	}
	if _, err := db.Exec("DROP TRIGGER announcements_no_update"); err != nil {
		t.Fatalf("drop announcement trigger for corruption test: %v", err)
	}
	if _, err := db.Exec(`
		UPDATE announcements
		SET severity = 'CRITICAL'
		WHERE sequence = 1`); err != nil {
		t.Fatalf("tamper announcement for integrity test: %v", err)
	}
}
