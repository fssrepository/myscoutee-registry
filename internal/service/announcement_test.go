package service

import (
	"strings"
	"testing"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

func TestValidateAndNormalizeAnnouncement(t *testing.T) {
	t.Run("localized general announcement is normalized", func(t *testing.T) {
		draft := validGeneralAnnouncementDraft()
		draft.Localizations = []protocol.AnnouncementLocalization{
			{Locale: "hu", Title: "Karbantartás", Body: "Részletek"},
			{Locale: "en", Title: "Maintenance", Body: "Details"},
		}
		draft.Links = []protocol.AnnouncementLink{
			{Relation: "status", URL: "https://status.example.test/current"},
			{Relation: "details", URL: "https://example.test/details"},
		}
		normalized, err := validateAndNormalizeAnnouncement(draft)
		if err != nil {
			t.Fatalf("validate announcement: %v", err)
		}
		if normalized.Localizations[0].Locale != "en" ||
			normalized.Links[0].Relation != "details" {
			t.Fatalf("announcement collections were not normalized: %+v", normalized)
		}
	})

	t.Run("localization keys are accepted instead of inline text", func(t *testing.T) {
		draft := validGeneralAnnouncementDraft()
		draft.Localizations = nil
		draft.TitleKey = "operator.announcement.title"
		draft.BodyKey = "operator.announcement.body"
		normalized, err := validateAndNormalizeAnnouncement(draft)
		if err != nil {
			t.Fatalf("validate keyed announcement: %v", err)
		}
		if normalized.Localizations == nil {
			t.Fatalf("normalized keyed announcement must use an empty localization list")
		}
	})

	tests := []struct {
		name   string
		mutate func(*protocol.AnnouncementDraft)
	}{
		{
			name: "unknown kind",
			mutate: func(draft *protocol.AnnouncementDraft) {
				draft.Kind = "OTHER"
			},
		},
		{
			name: "unknown severity",
			mutate: func(draft *protocol.AnnouncementDraft) {
				draft.Severity = "LOUD"
			},
		},
		{
			name: "expired before publication",
			mutate: func(draft *protocol.AnnouncementDraft) {
				draft.ExpiresAt = "2026-07-27T00:00:00Z"
			},
		},
		{
			name: "keys and inline content conflict",
			mutate: func(draft *protocol.AnnouncementDraft) {
				draft.TitleKey = "operator.title"
				draft.BodyKey = "operator.body"
			},
		},
		{
			name: "duplicate locale",
			mutate: func(draft *protocol.AnnouncementDraft) {
				draft.Localizations = append(
					draft.Localizations,
					draft.Localizations[0],
				)
			},
		},
		{
			name: "unsafe HTTP link",
			mutate: func(draft *protocol.AnnouncementDraft) {
				draft.Links = []protocol.AnnouncementLink{{
					Relation: "details",
					URL:      "http://example.test/details",
				}}
			},
		},
		{
			name: "update manifest on general announcement",
			mutate: func(draft *protocol.AnnouncementDraft) {
				manifest := validUpdateManifest()
				draft.UpdateManifest = &manifest
			},
		},
		{
			name: "missing update manifest",
			mutate: func(draft *protocol.AnnouncementDraft) {
				draft.Kind = protocol.AnnouncementKindUpdate
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			draft := validGeneralAnnouncementDraft()
			test.mutate(&draft)
			if _, err := validateAndNormalizeAnnouncement(draft); err == nil {
				t.Fatalf("invalid announcement unexpectedly passed validation")
			}
		})
	}
}

func TestValidateUpdateManifest(t *testing.T) {
	valid := validGeneralAnnouncementDraft()
	valid.Kind = protocol.AnnouncementKindUpdate
	manifest := validUpdateManifest()
	valid.UpdateManifest = &manifest
	if _, err := validateAndNormalizeAnnouncement(valid); err != nil {
		t.Fatalf("validate complete update manifest: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*protocol.UpdateManifest)
	}{
		{
			name: "unknown manifest version",
			mutate: func(manifest *protocol.UpdateManifest) {
				manifest.ManifestVersion = "2"
			},
		},
		{
			name: "non semantic release",
			mutate: func(manifest *protocol.UpdateManifest) {
				manifest.ReleaseVersion = "v1"
			},
		},
		{
			name: "inverted compatibility range",
			mutate: func(manifest *protocol.UpdateManifest) {
				manifest.MinimumCompatibleVersion = "2.0.0"
				manifest.MaximumCompatibleVersion = "1.0.0"
			},
		},
		{
			name: "non deb artifact",
			mutate: func(manifest *protocol.UpdateManifest) {
				manifest.ArtifactURL = "https://github.com/example/releases/download/v1/package.tar"
			},
		},
		{
			name: "http artifact",
			mutate: func(manifest *protocol.UpdateManifest) {
				manifest.ArtifactURL = "http://github.com/example/releases/download/v1/package.deb"
			},
		},
		{
			name: "invalid artifact digest",
			mutate: func(manifest *protocol.UpdateManifest) {
				manifest.ArtifactSHA256 = "sha256:ABC"
			},
		},
		{
			name: "invalid package key ID",
			mutate: func(manifest *protocol.UpdateManifest) {
				manifest.PackageSigningKeyID = "pkgkey_00000000000000000000000000000000"
			},
		},
		{
			name: "invalid package signature",
			mutate: func(manifest *protocol.UpdateManifest) {
				manifest.PackageSignature = "not-base64"
			},
		},
		{
			name: "mismatched publication time",
			mutate: func(manifest *protocol.UpdateManifest) {
				manifest.PublishedAt = "2026-07-29T00:00:00Z"
			},
		},
		{
			name: "revoked without reason",
			mutate: func(manifest *protocol.UpdateManifest) {
				manifest.Status = protocol.UpdateStatusRevoked
			},
		},
		{
			name: "superseded without successor",
			mutate: func(manifest *protocol.UpdateManifest) {
				manifest.Status = protocol.UpdateStatusSuperseded
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			draft := validGeneralAnnouncementDraft()
			draft.Kind = protocol.AnnouncementKindUpdate
			manifest := validUpdateManifest()
			test.mutate(&manifest)
			draft.UpdateManifest = &manifest
			if _, err := validateAndNormalizeAnnouncement(draft); err == nil {
				t.Fatalf("invalid update manifest unexpectedly passed validation")
			}
		})
	}

	t.Run("revocation is explicit and signed as a new manifest", func(t *testing.T) {
		draft := validGeneralAnnouncementDraft()
		draft.Kind = protocol.AnnouncementKindUpdate
		manifest := validUpdateManifest()
		manifest.Status = protocol.UpdateStatusRevoked
		manifest.SupersedesVersion = ""
		manifest.RevocationReason = "Package withdrawn after a failed health check."
		draft.UpdateManifest = &manifest
		if _, err := validateAndNormalizeAnnouncement(draft); err != nil {
			t.Fatalf("validate revoked manifest: %v", err)
		}
	})

	t.Run("supersession names the replacement", func(t *testing.T) {
		draft := validGeneralAnnouncementDraft()
		draft.Kind = protocol.AnnouncementKindUpdate
		manifest := validUpdateManifest()
		manifest.Status = protocol.UpdateStatusSuperseded
		manifest.SupersedesVersion = ""
		manifest.SupersededByVersion = "1.2.4"
		draft.UpdateManifest = &manifest
		if _, err := validateAndNormalizeAnnouncement(draft); err != nil {
			t.Fatalf("validate superseded manifest: %v", err)
		}
	})
}

func TestSemanticVersionOrdering(t *testing.T) {
	versions := []string{
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha-beta",
		"1.0.0-beta",
		"1.0.0",
	}
	for index := 0; index < len(versions)-1; index++ {
		left, err := parseSemanticVersion("left", versions[index])
		if err != nil {
			t.Fatalf("parse %s: %v", versions[index], err)
		}
		right, err := parseSemanticVersion("right", versions[index+1])
		if err != nil {
			t.Fatalf("parse %s: %v", versions[index+1], err)
		}
		if compareSemanticVersions(left, right) >= 0 {
			t.Fatalf("%s should precede %s", versions[index], versions[index+1])
		}
	}
}

func validGeneralAnnouncementDraft() protocol.AnnouncementDraft {
	return protocol.AnnouncementDraft{
		ProtocolVersion: protocol.Version,
		PublicationID:   "publication_general_0001",
		Kind:            protocol.AnnouncementKindGeneral,
		Severity:        protocol.AnnouncementSeverityNotice,
		PublishedAt:     "2026-07-28T00:00:00Z",
		ExpiresAt:       "2026-08-28T00:00:00Z",
		Localizations: []protocol.AnnouncementLocalization{{
			Locale: "en",
			Title:  "Operator announcement",
			Body:   "A registry-signed notice for operators.",
		}},
	}
}

func validUpdateManifest() protocol.UpdateManifest {
	return protocol.UpdateManifest{
		ManifestVersion:          protocol.UpdateManifestVersion,
		ReleaseVersion:           "1.2.3",
		Channel:                  "stable",
		PublishedAt:              "2026-07-28T00:00:00Z",
		MinimumCompatibleVersion: "1.0.0",
		MaximumCompatibleVersion: "1.2.2",
		ArtifactURL: "https://github.com/example/myscoutee/releases/download/v1.2.3/" +
			"myscoutee_1.2.3_amd64.deb",
		ArtifactSizeBytes:       123456,
		ArtifactSHA256:          "sha256:" + strings.Repeat("a", 64),
		PackageSigningKeyID:     "pkey_" + strings.Repeat("b", 32),
		PackageSignature:        protocol.EncodeSignature(make([]byte, 64)),
		ReleaseNotesURL:         "https://github.com/example/myscoutee/releases/tag/v1.2.3",
		BackupRequired:          true,
		ExpectedDowntimeSeconds: 180,
		Status:                  protocol.UpdateStatusAvailable,
		SupersedesVersion:       "1.2.2",
	}
}
