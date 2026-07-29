package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const (
	DemoSeedStateStarted  = "STARTED"
	DemoSeedStateComplete = "COMPLETE"
)

type DemoSeedExpectedState struct {
	Deployments          int64
	UsedNonces           int64
	IdempotencyRecords   int64
	LedgerEntries        int64
	MerkleNodes          int64
	LedgerWeightRows     int64
	MAUBatches           int64
	RevenueBatches       int64
	RevenueQueryRows     int64
	Checkpoints          int64
	OperatorAuditEvents  int64
	OperatorActionNonces int64
	OperatorNetworkRows  int64
	ClaimSubmissions     int64
	ClaimReviews         int64
	ClaimStatuses        int64
	Announcements        int64
	RegistryCaseEvents   int64
	RegistryCases        int64
}

type demoSeedMarker struct {
	Version       string
	RegistryScope string
	Digest        string
	State         string
}

func (sqliteStore *Store) HasQualifiedMAU(
	ctx context.Context,
	deploymentID string,
	period string,
) (bool, error) {
	var count int
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM mau_batches
		WHERE deployment_id = ?
		  AND period = ?
		  AND kind = 'monthly-qmau'`,
		deploymentID,
		period,
	).Scan(&count); err != nil {
		return false, fmt.Errorf("inspect demo QMAU period: %w", err)
	}
	return count > 0, nil
}

// BeginDemoSeed creates the only direct seed record. All domain records are
// subsequently created through the same signed service methods used by real
// deployments. A populated unmarked database is rejected.
func (sqliteStore *Store) BeginDemoSeed(
	ctx context.Context,
	version string,
	registryScope string,
	digest string,
	startedAt string,
) (bool, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin demo seed marker: %w", err)
	}
	defer tx.Rollback()

	marker, err := readDemoSeedMarker(ctx, tx)
	if err == nil {
		if marker.Version != version ||
			marker.RegistryScope != registryScope ||
			marker.Digest != digest {
			return false, fmt.Errorf(
				"demo seed marker does not match the requested seed definition",
			)
		}
		if marker.State != DemoSeedStateStarted &&
			marker.State != DemoSeedStateComplete {
			return false, fmt.Errorf("demo seed marker has an invalid state")
		}
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("finish demo seed marker read: %w", err)
		}
		return marker.State == DemoSeedStateComplete, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}

	recordCount, err := demoDomainRecordCount(ctx, tx)
	if err != nil {
		return false, err
	}
	if recordCount != 0 {
		return false, fmt.Errorf(
			"refusing to seed demo data into a populated unmarked registry database",
		)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO demo_seed_metadata (
			singleton,
			seed_version,
			registry_scope,
			seed_digest,
			state,
			started_at
		) VALUES (1, ?, ?, ?, 'STARTED', ?)`,
		version,
		registryScope,
		digest,
		startedAt,
	); err != nil {
		return false, fmt.Errorf("write demo seed marker: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit demo seed marker: %w", err)
	}
	return false, nil
}

func (sqliteStore *Store) CompleteDemoSeed(
	ctx context.Context,
	version string,
	registryScope string,
	digest string,
	completedAt string,
	expected DemoSeedExpectedState,
) error {
	tx, err := sqliteStore.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin demo seed completion: %w", err)
	}
	defer tx.Rollback()

	marker, err := readDemoSeedMarker(ctx, tx)
	if err != nil {
		return err
	}
	if marker.Version != version ||
		marker.RegistryScope != registryScope ||
		marker.Digest != digest {
		return fmt.Errorf(
			"demo seed marker does not match the completed seed definition",
		)
	}
	// A completed demo registry is intentionally interactive. Subsequent demo
	// registrations, claims, batches, announcements, and daily checkpoints are
	// legitimate state and must survive a restart; exact counts apply only to
	// the transition that establishes the baseline.
	if marker.State == DemoSeedStateComplete {
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("finish completed demo seed validation: %w", err)
		}
		return nil
	}
	actual, err := readDemoSeedExpectedState(ctx, tx)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf(
			"demo seed domain state is not exact: got %+v, expected %+v",
			actual,
			expected,
		)
	}
	if marker.State != DemoSeedStateStarted {
		return fmt.Errorf("demo seed marker has an invalid state")
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE demo_seed_metadata
		SET state = 'COMPLETE', completed_at = ?
		WHERE singleton = 1 AND state = 'STARTED'`,
		completedAt,
	); err != nil {
		return fmt.Errorf("complete demo seed marker: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit demo seed completion: %w", err)
	}
	return nil
}

func readDemoSeedMarker(
	ctx context.Context,
	queryer interface {
		QueryRowContext(context.Context, string, ...any) *sql.Row
	},
) (demoSeedMarker, error) {
	var marker demoSeedMarker
	err := queryer.QueryRowContext(ctx, `
		SELECT seed_version, registry_scope, seed_digest, state
		FROM demo_seed_metadata
		WHERE singleton = 1`).Scan(
		&marker.Version,
		&marker.RegistryScope,
		&marker.Digest,
		&marker.State,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return demoSeedMarker{}, sql.ErrNoRows
		}
		return demoSeedMarker{}, fmt.Errorf("read demo seed marker: %w", err)
	}
	return marker, nil
}

func demoDomainRecordCount(ctx context.Context, tx *sql.Tx) (int64, error) {
	var count int64
	if err := tx.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM deployments) +
			(SELECT COUNT(*) FROM used_nonces) +
			(SELECT COUNT(*) FROM idempotency_records) +
			(SELECT COUNT(*) FROM ledger_entries) +
			(SELECT COUNT(*) FROM ledger_merkle_nodes) +
			(SELECT COUNT(*) FROM ledger_weight_rows) +
			(SELECT COUNT(*) FROM mau_batches) +
			(SELECT COUNT(*) FROM revenue_batches) +
			(SELECT COUNT(*) FROM revenue_query_rows) +
			(SELECT COUNT(*) FROM checkpoints) +
			(SELECT COUNT(*) FROM operator_audit_events) +
			(SELECT COUNT(*) FROM operator_action_nonces) +
			(SELECT COUNT(*) FROM operator_network_state_rows) +
			(SELECT COUNT(*) FROM operator_claim_verification_submissions) +
			(SELECT COUNT(*) FROM operator_claim_reviews) +
			(SELECT COUNT(*) FROM operator_claim_status) +
			(SELECT COUNT(*) FROM announcements) +
			(SELECT COUNT(*) FROM registry_case_events) +
			(SELECT COUNT(*) FROM registry_cases)`).Scan(&count); err != nil {
		return 0, fmt.Errorf("inspect demo seed target database: %w", err)
	}
	return count, nil
}

func readDemoSeedExpectedState(
	ctx context.Context,
	tx *sql.Tx,
) (DemoSeedExpectedState, error) {
	var state DemoSeedExpectedState
	if err := tx.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM deployments),
			(SELECT COUNT(*) FROM used_nonces),
			(SELECT COUNT(*) FROM idempotency_records),
			(SELECT COUNT(*) FROM ledger_entries),
			(SELECT COUNT(*) FROM ledger_merkle_nodes),
			(SELECT COUNT(*) FROM ledger_weight_rows),
			(SELECT COUNT(*) FROM mau_batches),
			(SELECT COUNT(*) FROM revenue_batches),
			(SELECT COUNT(*) FROM revenue_query_rows),
			(SELECT COUNT(*) FROM checkpoints),
			(SELECT COUNT(*) FROM operator_audit_events),
			(SELECT COUNT(*) FROM operator_action_nonces),
			(SELECT COUNT(*) FROM operator_network_state_rows),
			(SELECT COUNT(*) FROM operator_claim_verification_submissions),
			(SELECT COUNT(*) FROM operator_claim_reviews),
			(SELECT COUNT(*) FROM operator_claim_status),
			(SELECT COUNT(*) FROM announcements),
			(SELECT COUNT(*) FROM registry_case_events),
			(SELECT COUNT(*) FROM registry_cases)`).Scan(
		&state.Deployments,
		&state.UsedNonces,
		&state.IdempotencyRecords,
		&state.LedgerEntries,
		&state.MerkleNodes,
		&state.LedgerWeightRows,
		&state.MAUBatches,
		&state.RevenueBatches,
		&state.RevenueQueryRows,
		&state.Checkpoints,
		&state.OperatorAuditEvents,
		&state.OperatorActionNonces,
		&state.OperatorNetworkRows,
		&state.ClaimSubmissions,
		&state.ClaimReviews,
		&state.ClaimStatuses,
		&state.Announcements,
		&state.RegistryCaseEvents,
		&state.RegistryCases,
	); err != nil {
		return DemoSeedExpectedState{}, fmt.Errorf(
			"inspect completed demo seed state: %w",
			err,
		)
	}
	return state, nil
}
