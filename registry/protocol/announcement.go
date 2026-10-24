package protocol

import (
	"strconv"
)

const (
	AnnouncementPath = "/v1/announcements"

	AnnouncementKindGeneral     = "GENERAL"
	AnnouncementKindUpdate      = "UPDATE"
	AnnouncementKindMaintenance = "MAINTENANCE"
	AnnouncementKindSecurity    = "SECURITY"

	AnnouncementSeverityInfo     = "INFO"
	AnnouncementSeverityNotice   = "NOTICE"
	AnnouncementSeverityWarning  = "WARNING"
	AnnouncementSeverityCritical = "CRITICAL"

	UpdateStatusAvailable  = "AVAILABLE"
	UpdateStatusRevoked    = "REVOKED"
	UpdateStatusSuperseded = "SUPERSEDED"

	UpdateManifestVersion = "1"
	AnnouncementZeroHash  = ZeroHash
)

func PackageSigningKeyID(spkiDER []byte) string {
	fingerprint := PublicKeyFingerprint(spkiDER)
	return "pkey_" + fingerprint[len("sha256:"):len("sha256:")+32]
}

type AnnouncementLocalization struct {
	Locale string `json:"locale"`
	Title  string `json:"title"`
	Body   string `json:"body"`
}

type AnnouncementLink struct {
	Relation string `json:"relation"`
	URL      string `json:"url"`
}

// UpdateManifest carries release metadata only. It never authorizes a
// download or installation. PackageSignature is a detached Ed25519 signature
// over UpdatePackageSignatureMessage and is verified by deployments against a
// separately pinned package-signing public key.
type UpdateManifest struct {
	ManifestVersion          string `json:"manifest_version"`
	ReleaseVersion           string `json:"release_version"`
	Channel                  string `json:"channel"`
	PublishedAt              string `json:"published_at"`
	MinimumCompatibleVersion string `json:"minimum_compatible_version"`
	MaximumCompatibleVersion string `json:"maximum_compatible_version"`
	ArtifactURL              string `json:"artifact_url"`
	ArtifactSizeBytes        int64  `json:"artifact_size_bytes"`
	ArtifactSHA256           string `json:"artifact_sha256"`
	PackageSigningKeyID      string `json:"package_signing_key_id"`
	PackageSignature         string `json:"package_signature"`
	ReleaseNotesURL          string `json:"release_notes_url"`
	BackupRequired           bool   `json:"backup_required"`
	ExpectedDowntimeSeconds  int64  `json:"expected_downtime_seconds"`
	Status                   string `json:"status"`
	SupersedesVersion        string `json:"supersedes_version,omitempty"`
	SupersededByVersion      string `json:"superseded_by_version,omitempty"`
	RevocationReason         string `json:"revocation_reason,omitempty"`
}

// AnnouncementDraft is the strict local publication-file contract. A
// PublicationID is a caller-chosen idempotency identifier, not the public
// registry-generated announcement ID.
type AnnouncementDraft struct {
	ProtocolVersion string                     `json:"protocol_version"`
	PublicationID   string                     `json:"publication_id"`
	Kind            string                     `json:"kind"`
	Severity        string                     `json:"severity"`
	PublishedAt     string                     `json:"published_at"`
	ExpiresAt       string                     `json:"expires_at,omitempty"`
	TitleKey        string                     `json:"title_key,omitempty"`
	BodyKey         string                     `json:"body_key,omitempty"`
	Localizations   []AnnouncementLocalization `json:"localizations,omitempty"`
	Links           []AnnouncementLink         `json:"links,omitempty"`
	UpdateManifest  *UpdateManifest            `json:"update_manifest,omitempty"`
}

type AnnouncementEntry struct {
	ProtocolVersion          string                     `json:"protocol_version"`
	RegistryScope            string                     `json:"registry_scope"`
	Sequence                 int64                      `json:"sequence"`
	AnnouncementID           string                     `json:"announcement_id"`
	PublicationID            string                     `json:"publication_id"`
	Kind                     string                     `json:"kind"`
	Severity                 string                     `json:"severity"`
	PublishedAt              string                     `json:"published_at"`
	ExpiresAt                string                     `json:"expires_at,omitempty"`
	TitleKey                 string                     `json:"title_key,omitempty"`
	BodyKey                  string                     `json:"body_key,omitempty"`
	Localizations            []AnnouncementLocalization `json:"localizations,omitempty"`
	Links                    []AnnouncementLink         `json:"links,omitempty"`
	UpdateManifest           *UpdateManifest            `json:"update_manifest,omitempty"`
	ContentHash              string                     `json:"content_hash"`
	LinksHash                string                     `json:"links_hash"`
	UpdateManifestHash       string                     `json:"update_manifest_hash"`
	PreviousAnnouncementHash string                     `json:"previous_announcement_hash"`
	AnnouncementHash         string                     `json:"announcement_hash"`
	AcceptedAt               string                     `json:"accepted_at"`
	RegistryKeyID            string                     `json:"registry_key_id"`
	Signature                string                     `json:"signature"`
}

type AnnouncementSnapshot struct {
	SnapshotID           string `json:"snapshot_id"`
	AsOf                 string `json:"as_of"`
	ThroughSequence      int64  `json:"through_sequence"`
	AnnouncementHeadHash string `json:"announcement_head_hash"`
	Kind                 string `json:"kind,omitempty"`
	Severity             string `json:"severity,omitempty"`
	Channel              string `json:"channel,omitempty"`
	IncludeExpired       bool   `json:"include_expired"`
	CreatedAt            string `json:"created_at"`
	SnapshotHash         string `json:"snapshot_hash"`
	RegistryScope        string `json:"registry_scope"`
	RegistryKeyID        string `json:"registry_key_id"`
	Signature            string `json:"signature"`
}

type AnnouncementPage struct {
	Snapshot   AnnouncementSnapshot `json:"snapshot"`
	Items      []AnnouncementEntry  `json:"items"`
	NextCursor string               `json:"next_cursor,omitempty"`
}

type AnnouncementPublishResult struct {
	Duplicate    bool              `json:"duplicate"`
	Announcement AnnouncementEntry `json:"announcement"`
}

func AnnouncementContentMessage(
	titleKey string,
	bodyKey string,
	localizations []AnnouncementLocalization,
) []byte {
	values := []string{
		"myscoutee-registry-announcement-content-v1",
		titleKey,
		bodyKey,
		strconv.Itoa(len(localizations)),
	}
	for _, localization := range localizations {
		values = append(
			values,
			localization.Locale,
			Digest([]byte(localization.Title)),
			Digest([]byte(localization.Body)),
		)
	}
	return canonical(values...)
}

func AnnouncementLinksMessage(links []AnnouncementLink) []byte {
	values := []string{
		"myscoutee-registry-announcement-links-v1",
		strconv.Itoa(len(links)),
	}
	for _, link := range links {
		values = append(values, link.Relation, link.URL)
	}
	return canonical(values...)
}

func UpdateManifestMessage(manifest UpdateManifest) []byte {
	return canonical(
		"myscoutee-registry-update-manifest-v1",
		manifest.ManifestVersion,
		manifest.ReleaseVersion,
		manifest.Channel,
		manifest.PublishedAt,
		manifest.MinimumCompatibleVersion,
		manifest.MaximumCompatibleVersion,
		manifest.ArtifactURL,
		strconv.FormatInt(manifest.ArtifactSizeBytes, 10),
		manifest.ArtifactSHA256,
		manifest.PackageSigningKeyID,
		manifest.PackageSignature,
		manifest.ReleaseNotesURL,
		strconv.FormatBool(manifest.BackupRequired),
		strconv.FormatInt(manifest.ExpectedDowntimeSeconds, 10),
		manifest.Status,
		manifest.SupersedesVersion,
		manifest.SupersededByVersion,
		manifest.RevocationReason,
	)
}

func UpdatePackageSignatureMessage(manifest UpdateManifest) []byte {
	return canonical(
		"myscoutee-release-package-v1",
		manifest.ReleaseVersion,
		manifest.Channel,
		strconv.FormatInt(manifest.ArtifactSizeBytes, 10),
		manifest.ArtifactSHA256,
	)
}

func AnnouncementEntryMessage(entry AnnouncementEntry) []byte {
	return canonical(
		"myscoutee-registry-announcement-entry-v1",
		entry.ProtocolVersion,
		entry.RegistryScope,
		strconv.FormatInt(entry.Sequence, 10),
		entry.AnnouncementID,
		entry.PublicationID,
		entry.Kind,
		entry.Severity,
		entry.PublishedAt,
		entry.ExpiresAt,
		entry.ContentHash,
		entry.LinksHash,
		entry.UpdateManifestHash,
		entry.PreviousAnnouncementHash,
		entry.AcceptedAt,
		entry.RegistryKeyID,
	)
}

func AnnouncementDraftMessage(
	publicationID string,
	kind string,
	severity string,
	publishedAt string,
	expiresAt string,
	contentHash string,
	linksHash string,
	updateManifestHash string,
) []byte {
	return canonical(
		"myscoutee-registry-announcement-draft-v1",
		publicationID,
		kind,
		severity,
		publishedAt,
		expiresAt,
		contentHash,
		linksHash,
		updateManifestHash,
	)
}

func AnnouncementReceiptMessage(entry AnnouncementEntry) []byte {
	return canonical(
		"myscoutee-registry-announcement-receipt-v1",
		entry.AnnouncementHash,
		entry.RegistryScope,
		entry.RegistryKeyID,
	)
}

func AnnouncementSnapshotHashMessage(snapshot AnnouncementSnapshot) []byte {
	return canonical(
		"myscoutee-registry-announcement-snapshot-hash-v1",
		snapshot.SnapshotID,
		snapshot.AsOf,
		strconv.FormatInt(snapshot.ThroughSequence, 10),
		snapshot.AnnouncementHeadHash,
		snapshot.Kind,
		snapshot.Severity,
		snapshot.Channel,
		strconv.FormatBool(snapshot.IncludeExpired),
		snapshot.CreatedAt,
		snapshot.RegistryScope,
		snapshot.RegistryKeyID,
	)
}

func AnnouncementSnapshotReceiptMessage(snapshot AnnouncementSnapshot) []byte {
	return canonical(
		"myscoutee-registry-announcement-snapshot-receipt-v1",
		snapshot.SnapshotHash,
		snapshot.RegistryScope,
		snapshot.RegistryKeyID,
	)
}
