package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/store"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve SQLite database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absolutePath), 0o700); err != nil {
		return nil, fmt.Errorf("create SQLite database directory: %w", err)
	}

	dsnURL := url.URL{Scheme: "file", Path: absolutePath}
	query := dsnURL.Query()
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "synchronous(FULL)")
	dsnURL.RawQuery = query.Encode()

	db, err := sql.Open("sqlite", dsnURL.String())
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping SQLite database: %w", err)
	}
	if err := migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	if err := reconcileMerkleTree(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	if err := verifyPragmas(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// OpenExisting refuses to create or initialize a registry database. It checks
// for an existing initialized identity using a read-only connection before the
// ordinary migration/open path is allowed to make any changes.
func OpenExisting(path string) (*Store, error) {
	if _, err := InspectExistingRegistryIdentity(path); err != nil {
		return nil, err
	}
	return Open(path)
}

// InspectExistingRegistryIdentity reads the existing identity without running
// migrations or changing SQLite pragmas. Operational callers use it to verify
// the configured key/scope before allowing OpenExisting to mutate schema.
func InspectExistingRegistryIdentity(path string) (store.RegistryIdentity, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return store.RegistryIdentity{}, fmt.Errorf("resolve SQLite database path: %w", err)
	}
	info, err := os.Lstat(absolutePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return store.RegistryIdentity{}, fmt.Errorf(
				"registry database does not exist: %s",
				absolutePath,
			)
		}
		return store.RegistryIdentity{}, fmt.Errorf("inspect registry database: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return store.RegistryIdentity{}, fmt.Errorf(
			"registry database must be an existing regular non-symlink file: %s",
			absolutePath,
		)
	}

	dsnURL := url.URL{Scheme: "file", Path: absolutePath}
	query := dsnURL.Query()
	query.Add("mode", "ro")
	dsnURL.RawQuery = query.Encode()
	preflight, err := sql.Open("sqlite", dsnURL.String())
	if err != nil {
		return store.RegistryIdentity{}, fmt.Errorf(
			"inspect existing SQLite database: %w",
			err,
		)
	}
	defer preflight.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var identityTableCount int
	if err := preflight.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM sqlite_master
		WHERE type = 'table' AND name = 'registry_identity'`).Scan(
		&identityTableCount,
	); err != nil {
		return store.RegistryIdentity{}, fmt.Errorf(
			"inspect initialized registry identity: %w",
			err,
		)
	}
	if identityTableCount != 1 {
		return store.RegistryIdentity{}, fmt.Errorf(
			"registry database is not initialized with exactly one identity: %s",
			absolutePath,
		)
	}
	var persisted store.RegistryIdentity
	if err := preflight.QueryRowContext(ctx, `
		SELECT
			protocol_version,
			registry_scope,
			registry_key_id,
			public_key_der,
			created_at
		FROM registry_identity
		WHERE singleton = 1`).Scan(
		&persisted.ProtocolVersion,
		&persisted.RegistryScope,
		&persisted.RegistryKeyID,
		&persisted.PublicKeyDER,
		&persisted.CreatedAt,
	); err != nil {
		return store.RegistryIdentity{}, fmt.Errorf(
			"inspect initialized registry identity: %w",
			err,
		)
	}
	var identityCount int
	if err := preflight.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM registry_identity`,
	).Scan(&identityCount); err != nil || identityCount != 1 {
		return store.RegistryIdentity{}, fmt.Errorf(
			"registry database is not initialized with exactly one identity: %s",
			absolutePath,
		)
	}
	if err := preflight.Close(); err != nil {
		return store.RegistryIdentity{}, fmt.Errorf(
			"close registry database preflight: %w",
			err,
		)
	}
	return persisted, nil
}

func (sqliteStore *Store) Close() error {
	return sqliteStore.db.Close()
}

func (sqliteStore *Store) Ping(ctx context.Context) error {
	return sqliteStore.db.PingContext(ctx)
}

func (sqliteStore *Store) PersistentStateIsPristine(ctx context.Context) (bool, error) {
	var recordCount int64
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM registry_identity) +
			(SELECT COUNT(*) FROM deployments) +
			(SELECT COUNT(*) FROM used_nonces) +
			(SELECT COUNT(*) FROM idempotency_records) +
			(SELECT COUNT(*) FROM ledger_entries) +
			(SELECT COUNT(*) FROM ledger_merkle_nodes) +
			(SELECT COUNT(*) FROM ledger_weight_rows) +
				(SELECT COUNT(*) FROM mau_batches) +
				(SELECT COUNT(*) FROM revenue_batches) +
				(SELECT COUNT(*) FROM revenue_query_rows) +
				(SELECT COUNT(*) FROM settlements) +
				(SELECT COUNT(*) FROM settlement_revenue_sources) +
				(SELECT COUNT(*) FROM settlement_ttm_months) +
				(SELECT COUNT(*) FROM settlement_weight_sources) +
				(SELECT COUNT(*) FROM settlement_beneficiary_deployments) +
				(SELECT COUNT(*) FROM settlement_allocations) +
				(SELECT COUNT(*) FROM checkpoints) +
			(SELECT COUNT(*) FROM operator_audit_events) +
			(SELECT COUNT(*) FROM operator_action_nonces) +
			(SELECT COUNT(*) FROM operator_network_state_rows) +
			(SELECT COUNT(*) FROM announcements) +
			(SELECT COUNT(*) FROM registry_case_events) +
			(SELECT COUNT(*) FROM registry_cases) +
			(SELECT COUNT(*) FROM demo_seed_metadata)`).Scan(&recordCount); err != nil {
		return false, fmt.Errorf("inspect registry persistent state: %w", err)
	}
	return recordCount == 0, nil
}

func (sqliteStore *Store) RegistryIdentity(ctx context.Context) (*store.RegistryIdentity, error) {
	row := sqliteStore.db.QueryRowContext(ctx, `
		SELECT protocol_version, registry_scope, registry_key_id, public_key_der, created_at
		FROM registry_identity
		WHERE singleton = 1`)
	var identity store.RegistryIdentity
	if err := row.Scan(
		&identity.ProtocolVersion,
		&identity.RegistryScope,
		&identity.RegistryKeyID,
		&identity.PublicKeyDER,
		&identity.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("read registry identity: %w", err)
	}
	return &identity, nil
}

func (sqliteStore *Store) EnsureRegistryIdentity(ctx context.Context, expected store.RegistryIdentity) error {
	current, err := sqliteStore.RegistryIdentity(ctx)
	if err != nil {
		return err
	}
	if current != nil {
		if current.ProtocolVersion != expected.ProtocolVersion ||
			current.RegistryScope != expected.RegistryScope ||
			current.RegistryKeyID != expected.RegistryKeyID ||
			!bytes.Equal(current.PublicKeyDER, expected.PublicKeyDER) {
			return store.ErrRegistryKeyMismatch
		}
		return nil
	}
	_, err = sqliteStore.db.ExecContext(ctx, `
		INSERT INTO registry_identity (
			singleton, protocol_version, registry_scope, registry_key_id, public_key_der, created_at
		) VALUES (1, ?, ?, ?, ?, ?)`,
		expected.ProtocolVersion,
		expected.RegistryScope,
		expected.RegistryKeyID,
		expected.PublicKeyDER,
		expected.CreatedAt,
	)
	if err != nil {
		// A concurrent first start may have inserted it. Re-read before failing.
		current, readErr := sqliteStore.RegistryIdentity(ctx)
		if readErr == nil && current != nil &&
			current.ProtocolVersion == expected.ProtocolVersion &&
			current.RegistryScope == expected.RegistryScope &&
			current.RegistryKeyID == expected.RegistryKeyID &&
			bytes.Equal(current.PublicKeyDER, expected.PublicKeyDER) {
			return nil
		}
		return fmt.Errorf("persist registry identity: %w", err)
	}
	return nil
}

func verifyPragmas(ctx context.Context, db *sql.DB) error {
	var journalMode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		return fmt.Errorf("read SQLite journal mode: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		return fmt.Errorf("SQLite journal mode is %q, expected WAL", journalMode)
	}
	var foreignKeys int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return fmt.Errorf("read SQLite foreign-key mode: %w", err)
	}
	if foreignKeys != 1 {
		return errors.New("SQLite foreign keys are not enabled")
	}
	return nil
}

type idempotencyRecord struct {
	PayloadHash string
	ResultType  string
	ResultID    string
}

type acceptedNonce struct {
	Signer           string
	Nonce            string
	RequestHash      string
	IdempotencyKey   string
	PayloadHash      string
	RequestTimestamp string
	RequestSignature []byte
	ResultType       string
	ResultID         string
	AcceptedAt       string
}

func nonceState(ctx context.Context, tx *sql.Tx, signer, nonce, requestHash string) (bool, error) {
	var storedRequestHash string
	err := tx.QueryRowContext(ctx, `
		SELECT request_hash
		FROM used_nonces
		WHERE signer = ? AND nonce = ?`,
		signer,
		nonce,
	).Scan(&storedRequestHash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read nonce state: %w", err)
	}
	if storedRequestHash != requestHash {
		return true, store.ErrReplayConflict
	}
	return true, nil
}

func insertNonce(ctx context.Context, tx *sql.Tx, nonce acceptedNonce) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO used_nonces (
			signer,
			nonce,
			request_hash,
			idempotency_key,
			payload_hash,
			request_timestamp,
			request_signature,
			result_type,
			result_id,
			accepted_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nonce.Signer,
		nonce.Nonce,
		nonce.RequestHash,
		nonce.IdempotencyKey,
		nonce.PayloadHash,
		nonce.RequestTimestamp,
		nonce.RequestSignature,
		nonce.ResultType,
		nonce.ResultID,
		nonce.AcceptedAt,
	)
	if err != nil {
		return fmt.Errorf("persist used nonce: %w", err)
	}
	return nil
}

func readIdempotency(
	ctx context.Context,
	tx *sql.Tx,
	signer string,
	idempotencyKey string,
) (*idempotencyRecord, error) {
	var record idempotencyRecord
	err := tx.QueryRowContext(ctx, `
		SELECT payload_hash, result_type, result_id
		FROM idempotency_records
		WHERE signer = ? AND idempotency_key = ?`,
		signer,
		idempotencyKey,
	).Scan(&record.PayloadHash, &record.ResultType, &record.ResultID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read idempotency record: %w", err)
	}
	return &record, nil
}

func insertIdempotency(
	ctx context.Context,
	tx *sql.Tx,
	signer string,
	idempotencyKey string,
	payloadHash string,
	resultType string,
	resultID string,
	acceptedAt string,
) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO idempotency_records (
			signer, idempotency_key, payload_hash, result_type, result_id, accepted_at
		) VALUES (?, ?, ?, ?, ?, ?)`,
		signer,
		idempotencyKey,
		payloadHash,
		resultType,
		resultID,
		acceptedAt,
	)
	if err != nil {
		return fmt.Errorf("persist idempotency record: %w", err)
	}
	return nil
}
