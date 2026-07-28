package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const announcementSelect = `
	SELECT
		sequence,
		announcement_id,
		publication_id,
		protocol_version,
		registry_scope,
		kind,
		severity,
		published_at,
		expires_at,
		title_key,
		body_key,
		localizations_json,
		links_json,
		update_manifest_json,
		update_channel,
		content_hash,
		links_hash,
		update_manifest_hash,
		draft_hash,
		previous_announcement_hash,
		announcement_hash,
		accepted_at,
		registry_key_id,
		signature
	FROM announcements`

type persistedAnnouncement struct {
	entry              protocol.AnnouncementEntry
	localizationsJSON  string
	linksJSON          string
	updateManifestJSON string
	updateChannel      string
	draftHash          string
	signature          []byte
}

func (sqliteStore *Store) AppendAnnouncement(
	ctx context.Context,
	input store.AnnouncementInput,
	signAnnouncement store.AnnouncementSigner,
) (protocol.AnnouncementEntry, bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.AnnouncementEntry{}, false, fmt.Errorf(
			"begin announcement publication: %w",
			err,
		)
	}
	defer tx.Rollback()

	existing, err := announcementByPublicationIDTx(ctx, tx, input.PublicationID)
	if err == nil {
		if existing.draftHash != input.DraftHash {
			return protocol.AnnouncementEntry{}, false, store.ErrAnnouncementConflict
		}
		if err := tx.Commit(); err != nil {
			return protocol.AnnouncementEntry{}, false, fmt.Errorf(
				"commit duplicate announcement publication: %w",
				err,
			)
		}
		return existing.entry, true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return protocol.AnnouncementEntry{}, false, err
	}

	if err := ensureAcceptedAtAfterRegistryCreation(ctx, tx, input.AcceptedAt); err != nil {
		return protocol.AnnouncementEntry{}, false, err
	}
	head, err := announcementHeadTx(ctx, tx)
	if err != nil {
		return protocol.AnnouncementEntry{}, false, err
	}
	if err := ensureAcceptedAtNotBeforeHead(input.AcceptedAt, head.AcceptedAt); err != nil {
		if errors.Is(err, store.ErrAcceptedAtBeforeHead) {
			return protocol.AnnouncementEntry{}, false, store.ErrAnnouncementClockBeforeHead
		}
		return protocol.AnnouncementEntry{}, false, err
	}

	entry := protocol.AnnouncementEntry{
		ProtocolVersion:          protocol.Version,
		RegistryScope:            input.RegistryScope,
		Sequence:                 head.Sequence + 1,
		AnnouncementID:           input.CandidateAnnouncementID,
		PublicationID:            input.PublicationID,
		Kind:                     input.Kind,
		Severity:                 input.Severity,
		PublishedAt:              input.PublishedAt,
		ExpiresAt:                input.ExpiresAt,
		TitleKey:                 input.TitleKey,
		BodyKey:                  input.BodyKey,
		Localizations:            cloneLocalizations(input.Localizations),
		Links:                    cloneAnnouncementLinks(input.Links),
		UpdateManifest:           cloneUpdateManifest(input.UpdateManifest),
		ContentHash:              input.ContentHash,
		LinksHash:                input.LinksHash,
		UpdateManifestHash:       input.UpdateManifestHash,
		PreviousAnnouncementHash: head.AnnouncementHash,
		AcceptedAt:               input.AcceptedAt,
		RegistryKeyID:            input.RegistryKeyID,
	}
	entry.AnnouncementHash = protocol.Digest(
		protocol.AnnouncementEntryMessage(entry),
	)
	signature, err := signAnnouncement(entry)
	if err != nil {
		return protocol.AnnouncementEntry{}, false, fmt.Errorf(
			"sign announcement: %w",
			err,
		)
	}

	localizationsJSON, err := json.Marshal(entry.Localizations)
	if err != nil {
		return protocol.AnnouncementEntry{}, false, fmt.Errorf(
			"encode announcement localizations: %w",
			err,
		)
	}
	linksJSON, err := json.Marshal(entry.Links)
	if err != nil {
		return protocol.AnnouncementEntry{}, false, fmt.Errorf(
			"encode announcement links: %w",
			err,
		)
	}
	updateManifestJSON := ""
	updateChannel := ""
	if entry.UpdateManifest != nil {
		encoded, err := json.Marshal(entry.UpdateManifest)
		if err != nil {
			return protocol.AnnouncementEntry{}, false, fmt.Errorf(
				"encode update manifest: %w",
				err,
			)
		}
		updateManifestJSON = string(encoded)
		updateChannel = entry.UpdateManifest.Channel
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO announcements (
			sequence,
			announcement_id,
			publication_id,
			protocol_version,
			registry_scope,
			kind,
			severity,
			published_at,
			expires_at,
			title_key,
			body_key,
			localizations_json,
			links_json,
			update_manifest_json,
			update_channel,
			content_hash,
			links_hash,
			update_manifest_hash,
			draft_hash,
			previous_announcement_hash,
			announcement_hash,
			accepted_at,
			registry_key_id,
			signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Sequence,
		entry.AnnouncementID,
		entry.PublicationID,
		entry.ProtocolVersion,
		entry.RegistryScope,
		entry.Kind,
		entry.Severity,
		entry.PublishedAt,
		entry.ExpiresAt,
		entry.TitleKey,
		entry.BodyKey,
		string(localizationsJSON),
		string(linksJSON),
		updateManifestJSON,
		updateChannel,
		entry.ContentHash,
		entry.LinksHash,
		entry.UpdateManifestHash,
		input.DraftHash,
		entry.PreviousAnnouncementHash,
		entry.AnnouncementHash,
		entry.AcceptedAt,
		entry.RegistryKeyID,
		signature,
	); err != nil {
		return protocol.AnnouncementEntry{}, false, fmt.Errorf(
			"persist announcement: %w",
			err,
		)
	}
	if err := tx.Commit(); err != nil {
		return protocol.AnnouncementEntry{}, false, fmt.Errorf(
			"commit announcement publication: %w",
			err,
		)
	}
	entry.Signature = protocol.EncodeSignature(signature)
	return entry, false, nil
}

func (sqliteStore *Store) AnnouncementHead(
	ctx context.Context,
) (store.AnnouncementHead, error) {
	row := sqliteStore.db.QueryRowContext(ctx, `
		SELECT sequence, announcement_hash, accepted_at
		FROM announcements
		ORDER BY sequence DESC
		LIMIT 1`)
	var head store.AnnouncementHead
	if err := row.Scan(
		&head.Sequence,
		&head.AnnouncementHash,
		&head.AcceptedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.AnnouncementHead{
				AnnouncementHash: protocol.AnnouncementZeroHash,
			}, nil
		}
		return store.AnnouncementHead{}, fmt.Errorf(
			"read announcement head: %w",
			err,
		)
	}
	return head, nil
}

func (sqliteStore *Store) AnnouncementBoundary(
	ctx context.Context,
	sequence int64,
) (store.AnnouncementHead, error) {
	if sequence == 0 {
		return store.AnnouncementHead{
			AnnouncementHash: protocol.AnnouncementZeroHash,
		}, nil
	}
	row := sqliteStore.db.QueryRowContext(ctx, `
		SELECT sequence, announcement_hash, accepted_at
		FROM announcements
		WHERE sequence = ?`,
		sequence,
	)
	var head store.AnnouncementHead
	if err := row.Scan(
		&head.Sequence,
		&head.AnnouncementHash,
		&head.AcceptedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.AnnouncementHead{}, store.ErrNotFound
		}
		return store.AnnouncementHead{}, fmt.Errorf(
			"read announcement boundary: %w",
			err,
		)
	}
	return head, nil
}

func (sqliteStore *Store) Announcements(
	ctx context.Context,
	query store.AnnouncementQuery,
) ([]protocol.AnnouncementEntry, error) {
	statement := announcementSelect + `
		WHERE sequence <= ?
		  AND julianday(published_at) <= julianday(?)`
	arguments := []any{query.ThroughSequence, query.AsOf}
	if !query.IncludeExpired {
		statement += " AND (expires_at = '' OR julianday(expires_at) > julianday(?))"
		arguments = append(arguments, query.AsOf)
	}
	if query.Kind != "" {
		statement += " AND kind = ?"
		arguments = append(arguments, query.Kind)
	}
	if query.Severity != "" {
		statement += " AND severity = ?"
		arguments = append(arguments, query.Severity)
	}
	if query.Channel != "" {
		statement += " AND update_channel = ?"
		arguments = append(arguments, query.Channel)
	}
	if query.HasAfter {
		statement += " AND sequence < ?"
		arguments = append(arguments, query.AfterSequence)
	}
	statement += " ORDER BY sequence DESC LIMIT ?"
	arguments = append(arguments, query.Limit)

	rows, err := sqliteStore.db.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, fmt.Errorf("read announcement feed: %w", err)
	}
	defer rows.Close()

	entries := make([]protocol.AnnouncementEntry, 0)
	for rows.Next() {
		persisted, err := scanPersistedAnnouncement(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, persisted.entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate announcement feed: %w", err)
	}
	return entries, nil
}

func announcementByPublicationIDTx(
	ctx context.Context,
	tx *sql.Tx,
	publicationID string,
) (persistedAnnouncement, error) {
	row := tx.QueryRowContext(
		ctx,
		announcementSelect+" WHERE publication_id = ?",
		publicationID,
	)
	persisted, err := scanPersistedAnnouncement(row)
	if errors.Is(err, sql.ErrNoRows) {
		return persistedAnnouncement{}, store.ErrNotFound
	}
	return persisted, err
}

func announcementHeadTx(
	ctx context.Context,
	tx *sql.Tx,
) (store.AnnouncementHead, error) {
	var head store.AnnouncementHead
	err := tx.QueryRowContext(ctx, `
		SELECT sequence, announcement_hash, accepted_at
		FROM announcements
		ORDER BY sequence DESC
		LIMIT 1`).Scan(
		&head.Sequence,
		&head.AnnouncementHash,
		&head.AcceptedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return store.AnnouncementHead{
			AnnouncementHash: protocol.AnnouncementZeroHash,
		}, nil
	}
	if err != nil {
		return store.AnnouncementHead{}, fmt.Errorf(
			"read announcement head: %w",
			err,
		)
	}
	return head, nil
}

type announcementScanner interface {
	Scan(...any) error
}

func scanPersistedAnnouncement(
	scanner announcementScanner,
) (persistedAnnouncement, error) {
	var persisted persistedAnnouncement
	if err := scanner.Scan(
		&persisted.entry.Sequence,
		&persisted.entry.AnnouncementID,
		&persisted.entry.PublicationID,
		&persisted.entry.ProtocolVersion,
		&persisted.entry.RegistryScope,
		&persisted.entry.Kind,
		&persisted.entry.Severity,
		&persisted.entry.PublishedAt,
		&persisted.entry.ExpiresAt,
		&persisted.entry.TitleKey,
		&persisted.entry.BodyKey,
		&persisted.localizationsJSON,
		&persisted.linksJSON,
		&persisted.updateManifestJSON,
		&persisted.updateChannel,
		&persisted.entry.ContentHash,
		&persisted.entry.LinksHash,
		&persisted.entry.UpdateManifestHash,
		&persisted.draftHash,
		&persisted.entry.PreviousAnnouncementHash,
		&persisted.entry.AnnouncementHash,
		&persisted.entry.AcceptedAt,
		&persisted.entry.RegistryKeyID,
		&persisted.signature,
	); err != nil {
		return persistedAnnouncement{}, err
	}
	if err := decodeCanonicalJSON(
		persisted.localizationsJSON,
		&persisted.entry.Localizations,
	); err != nil {
		return persistedAnnouncement{}, inconsistent(
			"decode announcement localizations",
			err,
		)
	}
	if err := decodeCanonicalJSON(
		persisted.linksJSON,
		&persisted.entry.Links,
	); err != nil {
		return persistedAnnouncement{}, inconsistent(
			"decode announcement links",
			err,
		)
	}
	if persisted.updateManifestJSON != "" {
		var manifest protocol.UpdateManifest
		if err := decodeCanonicalJSON(
			persisted.updateManifestJSON,
			&manifest,
		); err != nil {
			return persistedAnnouncement{}, inconsistent(
				"decode update manifest",
				err,
			)
		}
		persisted.entry.UpdateManifest = &manifest
	}
	persisted.entry.Signature = protocol.EncodeSignature(persisted.signature)
	return persisted, nil
}

func decodeCanonicalJSON(value string, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return errors.New("multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	encoded, err := json.Marshal(destination)
	if err != nil {
		return err
	}
	if string(encoded) != value {
		return errors.New("JSON is not in canonical stored form")
	}
	return nil
}

func cloneLocalizations(
	values []protocol.AnnouncementLocalization,
) []protocol.AnnouncementLocalization {
	if len(values) == 0 {
		return []protocol.AnnouncementLocalization{}
	}
	return append([]protocol.AnnouncementLocalization(nil), values...)
}

func cloneAnnouncementLinks(
	values []protocol.AnnouncementLink,
) []protocol.AnnouncementLink {
	if len(values) == 0 {
		return []protocol.AnnouncementLink{}
	}
	return append([]protocol.AnnouncementLink(nil), values...)
}

func cloneUpdateManifest(
	value *protocol.UpdateManifest,
) *protocol.UpdateManifest {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
