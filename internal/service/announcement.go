package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const (
	defaultAnnouncementLimit     = 20
	maxAnnouncementLimit         = 100
	maxAnnouncementArtifactBytes = int64(16 * 1024 * 1024 * 1024)
	maxAnnouncementLocalizations = 16
	maxAnnouncementLinks         = 8
)

var (
	announcementIDPattern     = regexp.MustCompile(`^ann_[0-9a-f]{32}$`)
	announcementLocalePattern = regexp.MustCompile(
		`^[a-z]{2,3}(?:-[a-z0-9]{2,8})*$`,
	)
	announcementKeyPattern = regexp.MustCompile(
		`^[a-z][a-z0-9_.-]{2,127}$`,
	)
	announcementLinkRelationPattern = regexp.MustCompile(
		`^[a-z][a-z0-9-]{0,31}$`,
	)
	updateChannelPattern       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	packageSigningKeyIDPattern = regexp.MustCompile(
		`^pkey_[0-9a-f]{32}$`,
	)
)

type AnnouncementFeedOptions struct {
	Kind           string
	Severity       string
	Channel        string
	IncludeExpired bool
	Limit          int
	Cursor         string
}

type announcementCursor struct {
	Version              int    `json:"version"`
	SnapshotID           string `json:"snapshot_id"`
	AsOf                 string `json:"as_of"`
	ThroughSequence      int64  `json:"through_sequence"`
	AnnouncementHeadHash string `json:"announcement_head_hash"`
	Kind                 string `json:"kind,omitempty"`
	Severity             string `json:"severity,omitempty"`
	Channel              string `json:"channel,omitempty"`
	IncludeExpired       bool   `json:"include_expired"`
	CreatedAt            string `json:"created_at"`
	AfterSequence        int64  `json:"after_sequence"`
}

func (registry *Service) PublishAnnouncement(
	ctx context.Context,
	draft protocol.AnnouncementDraft,
) (protocol.AnnouncementPublishResult, error) {
	normalized, err := validateAndNormalizeAnnouncement(draft)
	if err != nil {
		return protocol.AnnouncementPublishResult{}, err
	}
	if err := registry.VerifyState(ctx); err != nil {
		registry.logger.Error(
			"refusing local announcement publication while registry integrity verification fails",
			"error",
			err,
		)
		return protocol.AnnouncementPublishResult{}, requestError(
			"registry_integrity_unavailable",
			"registry integrity verification failed; announcement publication is unavailable",
		)
	}

	announcementID, err := registry.newID("ann_")
	if err != nil {
		return protocol.AnnouncementPublishResult{}, fmt.Errorf(
			"generate announcement ID: %w",
			err,
		)
	}
	if !announcementIDPattern.MatchString(announcementID) {
		return protocol.AnnouncementPublishResult{}, fmt.Errorf(
			"generated announcement ID is malformed",
		)
	}
	contentHash := protocol.Digest(protocol.AnnouncementContentMessage(
		normalized.TitleKey,
		normalized.BodyKey,
		normalized.Localizations,
	))
	linksHash := protocol.Digest(
		protocol.AnnouncementLinksMessage(normalized.Links),
	)
	updateManifestHash := protocol.AnnouncementZeroHash
	if normalized.UpdateManifest != nil {
		updateManifestHash = protocol.Digest(
			protocol.UpdateManifestMessage(*normalized.UpdateManifest),
		)
	}
	draftHash := protocol.Digest(protocol.AnnouncementDraftMessage(
		normalized.PublicationID,
		normalized.Kind,
		normalized.Severity,
		normalized.PublishedAt,
		normalized.ExpiresAt,
		contentHash,
		linksHash,
		updateManifestHash,
	))
	entry, duplicate, err := registry.store.AppendAnnouncement(
		ctx,
		store.AnnouncementInput{
			PublicationID:           normalized.PublicationID,
			Kind:                    normalized.Kind,
			Severity:                normalized.Severity,
			PublishedAt:             normalized.PublishedAt,
			ExpiresAt:               normalized.ExpiresAt,
			TitleKey:                normalized.TitleKey,
			BodyKey:                 normalized.BodyKey,
			Localizations:           normalized.Localizations,
			Links:                   normalized.Links,
			UpdateManifest:          normalized.UpdateManifest,
			ContentHash:             contentHash,
			LinksHash:               linksHash,
			UpdateManifestHash:      updateManifestHash,
			DraftHash:               draftHash,
			CandidateAnnouncementID: announcementID,
			AcceptedAt:              registry.canonicalNow().Format(time.RFC3339),
			RegistryScope:           registry.registryScope,
			RegistryKeyID:           registry.signingKey.KeyID(),
		},
		func(entry protocol.AnnouncementEntry) ([]byte, error) {
			return registry.signingKey.Sign(
				protocol.AnnouncementReceiptMessage(entry),
			), nil
		},
	)
	if err != nil {
		if errors.Is(err, store.ErrAnnouncementConflict) {
			return protocol.AnnouncementPublishResult{}, requestError(
				"announcement_conflict",
				"publication_id was already used with different announcement contents",
			)
		}
		if errors.Is(err, store.ErrAnnouncementClockBeforeHead) {
			return protocol.AnnouncementPublishResult{}, requestError(
				"registry_clock_before_announcement_head",
				"registry clock is before the current immutable announcement head",
			)
		}
		return protocol.AnnouncementPublishResult{}, mapStoreError(err)
	}
	return protocol.AnnouncementPublishResult{
		Duplicate:    duplicate,
		Announcement: entry,
	}, nil
}

func (registry *Service) AnnouncementFeed(
	ctx context.Context,
	options AnnouncementFeedOptions,
) (protocol.AnnouncementPage, error) {
	limit, err := validateAnnouncementLimit(options.Limit)
	if err != nil {
		return protocol.AnnouncementPage{}, err
	}
	if err := validateAnnouncementFilters(
		options.Kind,
		options.Severity,
		options.Channel,
	); err != nil {
		return protocol.AnnouncementPage{}, err
	}
	if err := registry.VerifyState(ctx); err != nil {
		registry.logger.Error(
			"refusing announcement feed while registry integrity verification fails",
			"error",
			err,
		)
		return protocol.AnnouncementPage{}, requestError(
			"registry_integrity_unavailable",
			"registry integrity verification failed; announcement feed is unavailable",
		)
	}

	state, hasCursor, err := registry.announcementState(ctx, options)
	if err != nil {
		return protocol.AnnouncementPage{}, err
	}
	entries, err := registry.store.Announcements(
		ctx,
		store.AnnouncementQuery{
			ThroughSequence: state.ThroughSequence,
			AsOf:            state.AsOf,
			Kind:            state.Kind,
			Severity:        state.Severity,
			Channel:         state.Channel,
			IncludeExpired:  state.IncludeExpired,
			AfterSequence:   state.AfterSequence,
			HasAfter:        hasCursor,
			Limit:           limit + 1,
		},
	)
	if err != nil {
		return protocol.AnnouncementPage{}, err
	}
	hasMore := len(entries) > limit
	if hasMore {
		entries = entries[:limit]
	}
	nextCursor := ""
	if hasMore && len(entries) > 0 {
		state.AfterSequence = entries[len(entries)-1].Sequence
		nextCursor, err = registry.encodeAnnouncementCursor(state)
		if err != nil {
			return protocol.AnnouncementPage{}, err
		}
	}
	return protocol.AnnouncementPage{
		Snapshot:   registry.announcementSnapshot(state),
		Items:      entries,
		NextCursor: nextCursor,
	}, nil
}

func (registry *Service) announcementState(
	ctx context.Context,
	options AnnouncementFeedOptions,
) (announcementCursor, bool, error) {
	if options.Cursor != "" {
		state, err := registry.decodeAnnouncementCursor(options.Cursor)
		if err != nil {
			return announcementCursor{}, false, err
		}
		if state.Kind != options.Kind ||
			state.Severity != options.Severity ||
			state.Channel != options.Channel ||
			state.IncludeExpired != options.IncludeExpired {
			return announcementCursor{}, false, requestError(
				"invalid_cursor",
				"cursor does not belong to this announcement request",
			)
		}
		boundary, err := registry.store.AnnouncementBoundary(
			ctx,
			state.ThroughSequence,
		)
		if err != nil ||
			boundary.AnnouncementHash != state.AnnouncementHeadHash {
			return announcementCursor{}, false, requestError(
				"invalid_cursor",
				"cursor snapshot is not available in this registry",
			)
		}
		return state, true, nil
	}
	head, err := registry.store.AnnouncementHead(ctx)
	if err != nil {
		return announcementCursor{}, false, err
	}
	asOf := registry.canonicalNow().Format(time.RFC3339)
	state := announcementCursor{
		Version:              1,
		AsOf:                 asOf,
		ThroughSequence:      head.Sequence,
		AnnouncementHeadHash: head.AnnouncementHash,
		Kind:                 options.Kind,
		Severity:             options.Severity,
		Channel:              options.Channel,
		IncludeExpired:       options.IncludeExpired,
		CreatedAt:            asOf,
	}
	state.SnapshotID = announcementSnapshotID(state)
	return state, false, nil
}

func (registry *Service) announcementSnapshot(
	state announcementCursor,
) protocol.AnnouncementSnapshot {
	snapshot := protocol.AnnouncementSnapshot{
		SnapshotID:           state.SnapshotID,
		AsOf:                 state.AsOf,
		ThroughSequence:      state.ThroughSequence,
		AnnouncementHeadHash: state.AnnouncementHeadHash,
		Kind:                 state.Kind,
		Severity:             state.Severity,
		Channel:              state.Channel,
		IncludeExpired:       state.IncludeExpired,
		CreatedAt:            state.CreatedAt,
		RegistryScope:        registry.registryScope,
		RegistryKeyID:        registry.signingKey.KeyID(),
	}
	snapshot.SnapshotHash = protocol.Digest(
		protocol.AnnouncementSnapshotHashMessage(snapshot),
	)
	snapshot.Signature = protocol.EncodeSignature(registry.signingKey.Sign(
		protocol.AnnouncementSnapshotReceiptMessage(snapshot),
	))
	return snapshot
}

func (registry *Service) encodeAnnouncementCursor(
	cursor announcementCursor,
) (string, error) {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", fmt.Errorf("encode announcement cursor: %w", err)
	}
	signature := registry.signingKey.Sign(announcementCursorMessage(payload))
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(signature), nil
}

func (registry *Service) decodeAnnouncementCursor(
	value string,
) (announcementCursor, error) {
	if len(value) > 4096 {
		return announcementCursor{}, requestError(
			"invalid_cursor",
			"cursor is malformed",
		)
	}
	payloadText, signatureText, found := strings.Cut(value, ".")
	if !found || strings.Contains(signatureText, ".") {
		return announcementCursor{}, requestError(
			"invalid_cursor",
			"cursor is malformed",
		)
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadText)
	if err != nil {
		return announcementCursor{}, requestError(
			"invalid_cursor",
			"cursor is malformed",
		)
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil || !protocol.Verify(
		registry.signingKey.PublicKey(),
		announcementCursorMessage(payload),
		signature,
	) {
		return announcementCursor{}, requestError(
			"invalid_cursor",
			"cursor signature is invalid",
		)
	}
	var cursor announcementCursor
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cursor); err != nil ||
		cursor.Version != 1 ||
		cursor.SnapshotID != announcementSnapshotID(cursor) ||
		!validAnnouncementTimestamp(cursor.AsOf) ||
		!validAnnouncementTimestamp(cursor.CreatedAt) ||
		cursor.ThroughSequence < 0 ||
		cursor.AfterSequence <= 0 ||
		cursor.AfterSequence > cursor.ThroughSequence ||
		!protocol.IsDigest(cursor.AnnouncementHeadHash) ||
		validateAnnouncementFilters(
			cursor.Kind,
			cursor.Severity,
			cursor.Channel,
		) != nil {
		return announcementCursor{}, requestError(
			"invalid_cursor",
			"cursor payload is invalid",
		)
	}
	return cursor, nil
}

func announcementSnapshotID(state announcementCursor) string {
	seed := strings.Join([]string{
		state.AsOf,
		strconv.FormatInt(state.ThroughSequence, 10),
		state.AnnouncementHeadHash,
		state.Kind,
		state.Severity,
		state.Channel,
		strconv.FormatBool(state.IncludeExpired),
		state.CreatedAt,
	}, "\x00")
	digest := strings.TrimPrefix(protocol.Digest([]byte(seed)), "sha256:")
	return "annsnap_" + digest[:32]
}

func announcementCursorMessage(payload []byte) []byte {
	message := make([]byte, 0, len(payload)+50)
	message = append(
		message,
		[]byte("myscoutee-registry-announcement-cursor-v1\n")...,
	)
	message = append(message, payload...)
	return message
}

func validateAndNormalizeAnnouncement(
	draft protocol.AnnouncementDraft,
) (protocol.AnnouncementDraft, error) {
	if draft.ProtocolVersion != protocol.Version {
		return protocol.AnnouncementDraft{}, requestError(
			"unsupported_protocol",
			"protocol_version must be \"1\"",
		)
	}
	if err := validateToken("publication_id", draft.PublicationID); err != nil {
		return protocol.AnnouncementDraft{}, err
	}
	if !knownAnnouncementKind(draft.Kind) {
		return protocol.AnnouncementDraft{}, requestError(
			"invalid_request",
			"kind must be GENERAL, UPDATE, MAINTENANCE, or SECURITY",
		)
	}
	if !knownAnnouncementSeverity(draft.Severity) {
		return protocol.AnnouncementDraft{}, requestError(
			"invalid_request",
			"severity must be INFO, NOTICE, WARNING, or CRITICAL",
		)
	}
	publishedAt, err := parseAnnouncementTimestamp(
		"published_at",
		draft.PublishedAt,
	)
	if err != nil {
		return protocol.AnnouncementDraft{}, err
	}
	if draft.ExpiresAt != "" {
		expiresAt, err := parseAnnouncementTimestamp(
			"expires_at",
			draft.ExpiresAt,
		)
		if err != nil {
			return protocol.AnnouncementDraft{}, err
		}
		if !expiresAt.After(publishedAt) {
			return protocol.AnnouncementDraft{}, requestError(
				"invalid_request",
				"expires_at must be after published_at",
			)
		}
	}

	keysMode := draft.TitleKey != "" || draft.BodyKey != ""
	localizedMode := len(draft.Localizations) > 0
	if keysMode == localizedMode {
		return protocol.AnnouncementDraft{}, requestError(
			"invalid_request",
			"provide either title_key/body_key or localized title/body values",
		)
	}
	if keysMode {
		if !announcementKeyPattern.MatchString(draft.TitleKey) ||
			!announcementKeyPattern.MatchString(draft.BodyKey) {
			return protocol.AnnouncementDraft{}, requestError(
				"invalid_request",
				"title_key and body_key must be canonical localization keys",
			)
		}
		draft.Localizations = []protocol.AnnouncementLocalization{}
	} else {
		if len(draft.Localizations) > maxAnnouncementLocalizations {
			return protocol.AnnouncementDraft{}, requestError(
				"invalid_request",
				"localizations may contain at most 16 entries",
			)
		}
		sort.Slice(draft.Localizations, func(left, right int) bool {
			return draft.Localizations[left].Locale <
				draft.Localizations[right].Locale
		})
		for index, localization := range draft.Localizations {
			if !announcementLocalePattern.MatchString(localization.Locale) {
				return protocol.AnnouncementDraft{}, requestError(
					"invalid_request",
					"localization locale is malformed or not lowercase",
				)
			}
			if index > 0 &&
				localization.Locale == draft.Localizations[index-1].Locale {
				return protocol.AnnouncementDraft{}, requestError(
					"invalid_request",
					"localization locales must be unique",
				)
			}
			if err := validateAnnouncementHumanText(
				"localized title",
				localization.Title,
				1,
				200,
				false,
			); err != nil {
				return protocol.AnnouncementDraft{}, err
			}
			if err := validateAnnouncementHumanText(
				"localized body",
				localization.Body,
				1,
				10_000,
				true,
			); err != nil {
				return protocol.AnnouncementDraft{}, err
			}
		}
	}

	if len(draft.Links) > maxAnnouncementLinks {
		return protocol.AnnouncementDraft{}, requestError(
			"invalid_request",
			"links may contain at most 8 entries",
		)
	}
	sort.Slice(draft.Links, func(left, right int) bool {
		if draft.Links[left].Relation == draft.Links[right].Relation {
			return draft.Links[left].URL < draft.Links[right].URL
		}
		return draft.Links[left].Relation < draft.Links[right].Relation
	})
	for index, link := range draft.Links {
		if !announcementLinkRelationPattern.MatchString(link.Relation) {
			return protocol.AnnouncementDraft{}, requestError(
				"invalid_request",
				"announcement link relation is malformed",
			)
		}
		if err := validateSafeHTTPSURL(
			"announcement link URL",
			link.URL,
			false,
		); err != nil {
			return protocol.AnnouncementDraft{}, err
		}
		if index > 0 &&
			link.Relation == draft.Links[index-1].Relation &&
			link.URL == draft.Links[index-1].URL {
			return protocol.AnnouncementDraft{}, requestError(
				"invalid_request",
				"announcement links must be unique",
			)
		}
	}
	if len(draft.Links) == 0 {
		draft.Links = []protocol.AnnouncementLink{}
	}

	if draft.Kind == protocol.AnnouncementKindUpdate {
		if draft.UpdateManifest == nil {
			return protocol.AnnouncementDraft{}, requestError(
				"invalid_request",
				"UPDATE announcements require update_manifest",
			)
		}
		if err := validateUpdateManifest(
			*draft.UpdateManifest,
			draft.PublishedAt,
		); err != nil {
			return protocol.AnnouncementDraft{}, err
		}
	} else if draft.UpdateManifest != nil {
		return protocol.AnnouncementDraft{}, requestError(
			"invalid_request",
			"update_manifest is valid only for UPDATE announcements",
		)
	}
	return draft, nil
}

func validateAnnouncementFilters(kind, severity, channel string) error {
	if kind != "" && !knownAnnouncementKind(kind) {
		return requestError("invalid_request", "kind filter is unsupported")
	}
	if severity != "" && !knownAnnouncementSeverity(severity) {
		return requestError("invalid_request", "severity filter is unsupported")
	}
	if channel != "" && !updateChannelPattern.MatchString(channel) {
		return requestError("invalid_request", "channel filter is malformed")
	}
	if channel != "" && kind != "" && kind != protocol.AnnouncementKindUpdate {
		return requestError(
			"invalid_request",
			"channel filter can be combined only with kind=UPDATE",
		)
	}
	return nil
}

func validateAnnouncementLimit(limit int) (int, error) {
	if limit == 0 {
		return defaultAnnouncementLimit, nil
	}
	if limit < 1 || limit > maxAnnouncementLimit {
		return 0, requestError(
			"invalid_request",
			"limit must be between 1 and 100",
		)
	}
	return limit, nil
}

func validateUpdateManifest(
	manifest protocol.UpdateManifest,
	announcementPublishedAt string,
) error {
	if manifest.ManifestVersion != protocol.UpdateManifestVersion {
		return requestError(
			"invalid_request",
			"update manifest_version must be \"1\"",
		)
	}
	_, err := parseSemanticVersion(
		"release_version",
		manifest.ReleaseVersion,
	)
	if err != nil {
		return err
	}
	minimum, err := parseSemanticVersion(
		"minimum_compatible_version",
		manifest.MinimumCompatibleVersion,
	)
	if err != nil {
		return err
	}
	maximum, err := parseSemanticVersion(
		"maximum_compatible_version",
		manifest.MaximumCompatibleVersion,
	)
	if err != nil {
		return err
	}
	if compareSemanticVersions(minimum, maximum) > 0 {
		return requestError(
			"invalid_request",
			"minimum_compatible_version must not exceed maximum_compatible_version",
		)
	}
	if !updateChannelPattern.MatchString(manifest.Channel) {
		return requestError(
			"invalid_request",
			"update channel must be a lowercase canonical token",
		)
	}
	if manifest.PublishedAt != announcementPublishedAt ||
		!validAnnouncementTimestamp(manifest.PublishedAt) {
		return requestError(
			"invalid_request",
			"update manifest published_at must equal announcement published_at",
		)
	}
	if err := validateSafeHTTPSURL(
		"artifact_url",
		manifest.ArtifactURL,
		true,
	); err != nil {
		return err
	}
	if manifest.ArtifactSizeBytes < 1 ||
		manifest.ArtifactSizeBytes > maxAnnouncementArtifactBytes {
		return requestError(
			"invalid_request",
			"artifact_size_bytes must be between 1 byte and 16 GiB",
		)
	}
	if !protocol.IsDigest(manifest.ArtifactSHA256) {
		return requestError(
			"invalid_request",
			"artifact_sha256 must be a lowercase sha256 digest",
		)
	}
	if !packageSigningKeyIDPattern.MatchString(
		manifest.PackageSigningKeyID,
	) {
		return requestError(
			"invalid_request",
			"package_signing_key_id must be pkey_ followed by 32 lowercase hexadecimal characters",
		)
	}
	if _, err := protocol.ParseSignature(manifest.PackageSignature); err != nil {
		return requestError(
			"invalid_request",
			"package_signature must be canonical padded base64 Ed25519",
		)
	}
	if err := validateSafeHTTPSURL(
		"release_notes_url",
		manifest.ReleaseNotesURL,
		false,
	); err != nil {
		return err
	}
	if manifest.ExpectedDowntimeSeconds < 0 ||
		manifest.ExpectedDowntimeSeconds > 86_400 {
		return requestError(
			"invalid_request",
			"expected_downtime_seconds must be between 0 and 86400",
		)
	}

	switch manifest.Status {
	case protocol.UpdateStatusAvailable:
		if manifest.SupersededByVersion != "" ||
			manifest.RevocationReason != "" {
			return requestError(
				"invalid_request",
				"AVAILABLE update manifests cannot be revoked or superseded",
			)
		}
		if manifest.SupersedesVersion != "" {
			if _, err := parseSemanticVersion(
				"supersedes_version",
				manifest.SupersedesVersion,
			); err != nil {
				return err
			}
			if manifest.SupersedesVersion == manifest.ReleaseVersion {
				return requestError(
					"invalid_request",
					"an update cannot supersede its own release version",
				)
			}
		}
	case protocol.UpdateStatusRevoked:
		if manifest.SupersedesVersion != "" ||
			manifest.SupersededByVersion != "" {
			return requestError(
				"invalid_request",
				"REVOKED update manifests cannot contain supersession fields",
			)
		}
		if err := validateCanonicalText(
			"revocation_reason",
			manifest.RevocationReason,
			1,
			1000,
		); err != nil {
			return err
		}
	case protocol.UpdateStatusSuperseded:
		if manifest.SupersedesVersion != "" ||
			manifest.RevocationReason != "" {
			return requestError(
				"invalid_request",
				"SUPERSEDED update manifests contain only superseded_by_version",
			)
		}
		if _, err := parseSemanticVersion(
			"superseded_by_version",
			manifest.SupersededByVersion,
		); err != nil {
			return err
		}
		if manifest.SupersededByVersion == manifest.ReleaseVersion {
			return requestError(
				"invalid_request",
				"an update cannot be superseded by its own release version",
			)
		}
	default:
		return requestError(
			"invalid_request",
			"update status must be AVAILABLE, REVOKED, or SUPERSEDED",
		)
	}
	return nil
}

func validateSafeHTTPSURL(name, value string, requireDeb bool) error {
	if len(value) < 1 || len(value) > 2048 ||
		protocol.HasCanonicalLineBreak(value) {
		return requestError("invalid_request", name+" is malformed")
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil ||
		parsed.Scheme != "https" ||
		parsed.Host == "" ||
		parsed.Hostname() == "" ||
		parsed.User != nil ||
		parsed.Fragment != "" ||
		parsed.Opaque != "" {
		return requestError(
			"invalid_request",
			name+" must be an absolute HTTPS URL without credentials or a fragment",
		)
	}
	if requireDeb && !strings.HasSuffix(strings.ToLower(parsed.Path), ".deb") {
		return requestError(
			"invalid_request",
			name+" must identify a Debian .deb package",
		)
	}
	return nil
}

func validateAnnouncementHumanText(
	name string,
	value string,
	minimum int,
	maximum int,
	allowLineBreaks bool,
) error {
	if !utf8.ValidString(value) ||
		len(value) < minimum ||
		len(value) > maximum ||
		strings.ContainsRune(value, '\x00') {
		return requestError("invalid_request", name+" is malformed")
	}
	for _, character := range value {
		if character == '\r' ||
			(!allowLineBreaks && character == '\n') ||
			(character < 0x20 && character != '\n' && character != '\t') {
			return requestError("invalid_request", name+" contains unsafe control characters")
		}
	}
	return nil
}

func parseAnnouncementTimestamp(name, value string) (time.Time, error) {
	if !validAnnouncementTimestamp(value) {
		return time.Time{}, requestError(
			"invalid_request",
			name+" must be an RFC 3339 UTC timestamp ending in Z",
		)
	}
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed, nil
}

func validAnnouncementTimestamp(value string) bool {
	if !strings.HasSuffix(value, "Z") ||
		protocol.HasCanonicalLineBreak(value) {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Location() == time.UTC
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

type semanticVersion struct {
	major      uint64
	minor      uint64
	patch      uint64
	prerelease []string
}

func parseSemanticVersion(name, value string) (semanticVersion, error) {
	if len(value) < 5 || len(value) > 128 ||
		protocol.HasCanonicalLineBreak(value) {
		return semanticVersion{}, invalidSemanticVersion(name)
	}
	mainPart, buildPart, hasBuild := strings.Cut(value, "+")
	if (hasBuild && strings.Contains(buildPart, "+")) ||
		(hasBuild && !validSemanticIdentifiers(
			buildPart,
			false,
		)) {
		return semanticVersion{}, invalidSemanticVersion(name)
	}
	corePart, prereleasePart, hasPrerelease := strings.Cut(mainPart, "-")
	if hasPrerelease && !validSemanticIdentifiers(
		prereleasePart,
		true,
	) {
		return semanticVersion{}, invalidSemanticVersion(name)
	}
	core := strings.Split(corePart, ".")
	if len(core) != 3 {
		return semanticVersion{}, invalidSemanticVersion(name)
	}
	parts := make([]uint64, 3)
	for index, part := range core {
		if part == "" ||
			(len(part) > 1 && part[0] == '0') ||
			!allASCIIDigits(part) {
			return semanticVersion{}, invalidSemanticVersion(name)
		}
		parsed, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return semanticVersion{}, invalidSemanticVersion(name)
		}
		parts[index] = parsed
	}
	parsed := semanticVersion{
		major: parts[0],
		minor: parts[1],
		patch: parts[2],
	}
	if hasPrerelease {
		parsed.prerelease = strings.Split(prereleasePart, ".")
	}
	return parsed, nil
}

func validSemanticIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	if value == "" {
		return false
	}
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for _, character := range []byte(identifier) {
			if (character < '0' || character > '9') &&
				(character < 'A' || character > 'Z') &&
				(character < 'a' || character > 'z') &&
				character != '-' {
				return false
			}
			if character < '0' || character > '9' {
				numeric = false
			}
		}
		if rejectNumericLeadingZero &&
			numeric &&
			len(identifier) > 1 &&
			identifier[0] == '0' {
			return false
		}
	}
	return true
}

func allASCIIDigits(value string) bool {
	for _, character := range []byte(value) {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func compareSemanticVersions(left, right semanticVersion) int {
	leftCore := []uint64{left.major, left.minor, left.patch}
	rightCore := []uint64{right.major, right.minor, right.patch}
	for index := range leftCore {
		if leftCore[index] < rightCore[index] {
			return -1
		}
		if leftCore[index] > rightCore[index] {
			return 1
		}
	}
	if len(left.prerelease) == 0 && len(right.prerelease) == 0 {
		return 0
	}
	if len(left.prerelease) == 0 {
		return 1
	}
	if len(right.prerelease) == 0 {
		return -1
	}
	for index := 0; index < len(left.prerelease) &&
		index < len(right.prerelease); index++ {
		leftPart := left.prerelease[index]
		rightPart := right.prerelease[index]
		if leftPart == rightPart {
			continue
		}
		leftNumeric := allASCIIDigits(leftPart)
		rightNumeric := allASCIIDigits(rightPart)
		switch {
		case leftNumeric && rightNumeric:
			if len(leftPart) < len(rightPart) {
				return -1
			}
			if len(leftPart) > len(rightPart) {
				return 1
			}
			if leftPart < rightPart {
				return -1
			}
			return 1
		case leftNumeric:
			return -1
		case rightNumeric:
			return 1
		case leftPart < rightPart:
			return -1
		default:
			return 1
		}
	}
	if len(left.prerelease) < len(right.prerelease) {
		return -1
	}
	if len(left.prerelease) > len(right.prerelease) {
		return 1
	}
	return 0
}

func invalidSemanticVersion(name string) error {
	return requestError(
		"invalid_request",
		name+" must be a canonical semantic version",
	)
}
