package store

import (
	"context"
	"crypto/ed25519"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

type AnnouncementInput struct {
	PublicationID           string
	Kind                    string
	Severity                string
	PublishedAt             string
	ExpiresAt               string
	TitleKey                string
	BodyKey                 string
	Localizations           []protocol.AnnouncementLocalization
	Links                   []protocol.AnnouncementLink
	UpdateManifest          *protocol.UpdateManifest
	ContentHash             string
	LinksHash               string
	UpdateManifestHash      string
	DraftHash               string
	CandidateAnnouncementID string
	AcceptedAt              string
	RegistryScope           string
	RegistryKeyID           string
}

type AnnouncementHead struct {
	Sequence         int64
	AnnouncementHash string
	AcceptedAt       string
}

type AnnouncementQuery struct {
	ThroughSequence int64
	AsOf            string
	Kind            string
	Severity        string
	Channel         string
	IncludeExpired  bool
	AfterSequence   int64
	HasAfter        bool
	Limit           int
}

type AnnouncementSigner func(protocol.AnnouncementEntry) ([]byte, error)

type AnnouncementStore interface {
	AppendAnnouncement(
		context.Context,
		AnnouncementInput,
		AnnouncementSigner,
	) (protocol.AnnouncementEntry, bool, error)
	AnnouncementHead(context.Context) (AnnouncementHead, error)
	AnnouncementBoundary(context.Context, int64) (AnnouncementHead, error)
	Announcements(
		context.Context,
		AnnouncementQuery,
	) ([]protocol.AnnouncementEntry, error)
	VerifyAnnouncements(context.Context, ed25519.PublicKey, string, string) error
}
