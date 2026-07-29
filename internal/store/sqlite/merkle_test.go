package sqlite

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"math/bits"
	"testing"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

func TestMerkleIndexAppendsCompactNodesAndServesHistoricalProofs(t *testing.T) {
	registryStore := newLedgerIntegrityStore(t)
	ctx := context.Background()
	baseTime := time.Date(2026, 7, 28, 0, 0, 2, 0, time.UTC)

	for index := 1; index <= 17; index++ {
		input := ledgerIntegrityBatchInput(fmt.Sprintf("merkle_%02d", index))
		input.RequestTimestamp = baseTime.Add(time.Duration(index*2) * time.Second).
			Format(time.RFC3339)
		input.AcceptedAt = baseTime.Add(time.Duration(index*2+1) * time.Second).
			Format(time.RFC3339)
		if _, duplicate, err := registryStore.AcceptInstallationBatch(
			ctx,
			input,
			func(protocol.LedgerEntry, string) ([]byte, error) {
				return make([]byte, ed25519.SignatureSize), nil
			},
		); err != nil {
			t.Fatalf("append ledger entry %d: %v", index, err)
		} else if duplicate {
			t.Fatalf("ledger entry %d unexpectedly reported as duplicate", index)
		}

		var nodeCount int
		if err := registryStore.db.QueryRowContext(
			ctx,
			"SELECT COUNT(*) FROM ledger_merkle_nodes",
		).Scan(&nodeCount); err != nil {
			t.Fatalf("count Merkle nodes after entry %d: %v", index, err)
		}
		expected := index - bits.OnesCount(uint(index))
		if nodeCount != expected {
			t.Fatalf(
				"Merkle node count after entry %d = %d, want %d",
				index,
				nodeCount,
				expected,
			)
		}
	}
	if err := registryStore.VerifyMerkleTree(ctx); err != nil {
		t.Fatalf("verify compact Merkle index: %v", err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate proof-verification key: %v", err)
	}
	encodedPublicKey, publicKeyDER, err := protocol.EncodePublicKey(publicKey)
	if err != nil {
		t.Fatalf("encode proof-verification key: %v", err)
	}
	signHead := func(treeSize int64, rootHash string) protocol.MerkleTreeHead {
		head := protocol.MerkleTreeHead{
			ProtocolVersion:   protocol.Version,
			RegistryScope:     ledgerIntegrityScope,
			TreeSize:          treeSize,
			RootHash:          rootHash,
			GeneratedAt:       "2026-07-29T00:00:00Z",
			RegistryKeyID:     protocol.RegistryKeyID(publicKeyDER),
			RegistryPublicKey: encodedPublicKey,
		}
		head.Signature = protocol.EncodeSignature(
			ed25519.Sign(privateKey, protocol.MerkleTreeHeadMessage(head)),
		)
		return head
	}

	for treeSize := int64(1); treeSize <= 17; treeSize++ {
		for ledgerIndex := int64(1); ledgerIndex <= treeSize; ledgerIndex++ {
			record, err := registryStore.MerkleInclusionProof(
				ctx,
				ledgerIndex,
				treeSize,
			)
			if err != nil {
				t.Fatalf(
					"generate inclusion proof tree=%d leaf=%d: %v",
					treeSize,
					ledgerIndex,
					err,
				)
			}
			if err := protocol.VerifyMerkleInclusionProof(
				protocol.MerkleInclusionProof{
					LedgerIndex:     record.LedgerIndex,
					LedgerEntryHash: record.LedgerEntryHash,
					LeafHash:        record.LeafHash,
					AuditPath:       record.AuditPath,
					TreeHead:        signHead(record.TreeSize, record.RootHash),
				},
			); err != nil {
				t.Fatalf(
					"verify inclusion proof tree=%d leaf=%d: %v",
					treeSize,
					ledgerIndex,
					err,
				)
			}
		}

		for oldSize := int64(0); oldSize <= treeSize; oldSize++ {
			record, err := registryStore.MerkleConsistencyProof(
				ctx,
				oldSize,
				treeSize,
			)
			if err != nil {
				t.Fatalf(
					"generate consistency proof old=%d new=%d: %v",
					oldSize,
					treeSize,
					err,
				)
			}
			if err := protocol.VerifyMerkleConsistencyProof(
				protocol.MerkleConsistencyProof{
					OldTreeSize: record.OldTreeSize,
					OldRootHash: record.OldRootHash,
					AuditPath:   record.AuditPath,
					TreeHead:    signHead(record.NewTreeSize, record.NewRootHash),
				},
			); err != nil {
				t.Fatalf(
					"verify consistency proof old=%d new=%d: %v",
					oldSize,
					treeSize,
					err,
				)
			}
		}
	}
}

func TestVerifyMerkleTreeDetectsPersistedNodeTampering(t *testing.T) {
	registryStore := newLedgerIntegrityStore(t)
	ctx := context.Background()
	for index := 1; index <= 4; index++ {
		input := ledgerIntegrityBatchInput(fmt.Sprintf("tamper_%02d", index))
		if _, _, err := registryStore.AcceptInstallationBatch(
			ctx,
			input,
			func(protocol.LedgerEntry, string) ([]byte, error) {
				return make([]byte, ed25519.SignatureSize), nil
			},
		); err != nil {
			t.Fatalf("append ledger entry %d: %v", index, err)
		}
	}
	if err := registryStore.VerifyMerkleTree(ctx); err != nil {
		t.Fatalf("verify Merkle index before corruption: %v", err)
	}
	if _, err := registryStore.db.Exec(
		"DROP TRIGGER ledger_merkle_nodes_no_update",
	); err != nil {
		t.Fatalf("drop Merkle update guard for corruption test: %v", err)
	}
	if _, err := registryStore.db.Exec(`
		UPDATE ledger_merkle_nodes
		SET node_hash = zeroblob(32)
		WHERE tree_level = 1 AND node_index = 0`,
	); err != nil {
		t.Fatalf("corrupt persisted Merkle node: %v", err)
	}
	if err := registryStore.VerifyMerkleTree(ctx); err == nil {
		t.Fatal("tampered persisted Merkle node unexpectedly verified")
	}
}
