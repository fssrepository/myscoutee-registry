package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func TestGlobalIdentityCompletedCommitmentsIncludesInflightFinalChunk(
	t *testing.T,
) {
	database, err := sql.Open(
		"sqlite",
		filepath.Join(t.TempDir(), "presence.db"),
	)
	if err != nil {
		t.Fatalf("open presence test database: %v", err)
	}
	defer database.Close()

	if _, err := database.Exec(`
		CREATE TABLE global_identity_presence_chunks (
			submission_id TEXT NOT NULL,
			chunk_index   INTEGER NOT NULL,
			item_count    INTEGER NOT NULL
		);
		CREATE TABLE global_identity_presence_chunk_items (
			submission_id                TEXT NOT NULL,
			chunk_index                  INTEGER NOT NULL,
			item_index                   INTEGER NOT NULL,
			key_version                  INTEGER NOT NULL,
			network_identity_commitment  TEXT NOT NULL
		);
		INSERT INTO global_identity_presence_chunks
			(submission_id, chunk_index, item_count)
		VALUES ('gipsub_test', 0, 2);
		INSERT INTO global_identity_presence_chunk_items
			(submission_id, chunk_index, item_index, key_version,
			 network_identity_commitment)
		VALUES
			('gipsub_test', 0, 0, 7, 'sha256:a'),
			('gipsub_test', 0, 1, 7, 'sha256:b');
	`); err != nil {
		t.Fatalf("seed staged presence chunks: %v", err)
	}

	transaction, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin presence test transaction: %v", err)
	}
	defer transaction.Rollback()

	got, err := globalIdentityCompletedCommitments(
		context.Background(),
		transaction,
		store.GlobalIdentityPresenceInput{
			SubmissionID: "gipsub_test",
			KeyVersion:   7,
			ChunkIndex:   1,
			ChunkCount:   2,
			Commitments:  []string{"sha256:c"},
		},
	)
	if err != nil {
		t.Fatalf("assemble completed commitments: %v", err)
	}
	want := []string{"sha256:a", "sha256:b", "sha256:c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("completed commitments = %#v, want %#v", got, want)
	}
}
