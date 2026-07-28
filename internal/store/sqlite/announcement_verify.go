package sqlite

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

func (sqliteStore *Store) VerifyAnnouncements(
	ctx context.Context,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) error {
	if len(registryPublicKey) != ed25519.PublicKeySize {
		return inconsistentMessage("announcement verifier has an invalid registry public key")
	}
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		announcementSelect+" ORDER BY sequence",
	)
	if err != nil {
		return inconsistent("read announcement chain", err)
	}
	defer rows.Close()

	expectedSequence := int64(1)
	previousHash := protocol.AnnouncementZeroHash
	var previousAcceptedAt time.Time
	for rows.Next() {
		persisted, err := scanPersistedAnnouncement(rows)
		if err != nil {
			return inconsistent("scan announcement chain", err)
		}
		entry := persisted.entry
		if entry.Sequence != expectedSequence {
			return inconsistentMessage(
				"announcement sequence discontinuity: got %d, expected %d",
				entry.Sequence,
				expectedSequence,
			)
		}
		if !validHexID(entry.AnnouncementID, "ann_", 32) {
			return inconsistentMessage(
				"announcement has malformed ID %q",
				entry.AnnouncementID,
			)
		}
		if entry.ProtocolVersion != protocol.Version ||
			entry.RegistryScope != registryScope ||
			entry.RegistryKeyID != registryKeyID {
			return inconsistentMessage(
				"announcement %s has invalid registry metadata",
				entry.AnnouncementID,
			)
		}
		if entry.PreviousAnnouncementHash != previousHash {
			return inconsistentMessage(
				"announcement %s has an invalid previous hash",
				entry.AnnouncementID,
			)
		}
		acceptedAt, err := time.Parse(time.RFC3339Nano, entry.AcceptedAt)
		if err != nil || !validPersistedTimestamp(entry.AcceptedAt) {
			return inconsistentMessage(
				"announcement %s has an invalid accepted_at",
				entry.AnnouncementID,
			)
		}
		if expectedSequence > 1 && acceptedAt.Before(previousAcceptedAt) {
			return inconsistentMessage(
				"announcement %s has a non-monotonic accepted_at",
				entry.AnnouncementID,
			)
		}
		if !validPersistedTimestamp(entry.PublishedAt) {
			return inconsistentMessage(
				"announcement %s has an invalid published_at",
				entry.AnnouncementID,
			)
		}
		if entry.ExpiresAt != "" && !validPersistedTimestamp(entry.ExpiresAt) {
			return inconsistentMessage(
				"announcement %s has an invalid expires_at",
				entry.AnnouncementID,
			)
		}

		contentHash := protocol.Digest(protocol.AnnouncementContentMessage(
			entry.TitleKey,
			entry.BodyKey,
			entry.Localizations,
		))
		linksHash := protocol.Digest(
			protocol.AnnouncementLinksMessage(entry.Links),
		)
		updateManifestHash := protocol.AnnouncementZeroHash
		updateChannel := ""
		if entry.UpdateManifest != nil {
			updateManifestHash = protocol.Digest(
				protocol.UpdateManifestMessage(*entry.UpdateManifest),
			)
			updateChannel = entry.UpdateManifest.Channel
		}
		if entry.ContentHash != contentHash ||
			entry.LinksHash != linksHash ||
			entry.UpdateManifestHash != updateManifestHash ||
			persisted.updateChannel != updateChannel {
			return inconsistentMessage(
				"announcement %s nested content hash verification failed",
				entry.AnnouncementID,
			)
		}
		expectedDraftHash := protocol.Digest(protocol.AnnouncementDraftMessage(
			entry.PublicationID,
			entry.Kind,
			entry.Severity,
			entry.PublishedAt,
			entry.ExpiresAt,
			entry.ContentHash,
			entry.LinksHash,
			entry.UpdateManifestHash,
		))
		if persisted.draftHash != expectedDraftHash {
			return inconsistentMessage(
				"announcement %s publication hash verification failed",
				entry.AnnouncementID,
			)
		}
		expectedHash := protocol.Digest(protocol.AnnouncementEntryMessage(entry))
		if entry.AnnouncementHash != expectedHash {
			return inconsistentMessage(
				"announcement %s chain hash verification failed",
				entry.AnnouncementID,
			)
		}
		if !ed25519.Verify(
			registryPublicKey,
			protocol.AnnouncementReceiptMessage(entry),
			persisted.signature,
		) {
			return inconsistentMessage(
				"announcement %s registry signature verification failed",
				entry.AnnouncementID,
			)
		}
		if !knownAnnouncementKind(entry.Kind) ||
			!knownAnnouncementSeverity(entry.Severity) ||
			(entry.Kind == protocol.AnnouncementKindUpdate) !=
				(entry.UpdateManifest != nil) {
			return inconsistentMessage(
				"announcement %s has invalid kind-specific content",
				entry.AnnouncementID,
			)
		}
		previousHash = entry.AnnouncementHash
		previousAcceptedAt = acceptedAt
		expectedSequence++
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate announcement chain", err)
	}
	return nil
}

func knownAnnouncementKind(value string) bool {
	switch value {
	case protocol.AnnouncementKindGeneral,
		protocol.AnnouncementKindUpdate,
		protocol.AnnouncementKindMaintenance,
		protocol.AnnouncementKindSecurity:
		return true
	default:
		return false
	}
}

func knownAnnouncementSeverity(value string) bool {
	switch value {
	case protocol.AnnouncementSeverityInfo,
		protocol.AnnouncementSeverityNotice,
		protocol.AnnouncementSeverityWarning,
		protocol.AnnouncementSeverityCritical:
		return true
	default:
		return false
	}
}
