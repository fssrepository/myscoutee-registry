package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func reconcileMerkleTree(ctx context.Context, database *sql.DB) error {
	var ledgerCount, nodeCount int64
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM ledger_entries").Scan(&ledgerCount); err != nil {
		return fmt.Errorf("count ledger entries before Merkle reconciliation: %w", err)
	}
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM ledger_merkle_nodes").Scan(&nodeCount); err != nil {
		return fmt.Errorf("count persisted Merkle nodes: %w", err)
	}
	expectedNodeCount := ledgerCount - int64(bits.OnesCount64(uint64(ledgerCount)))
	if nodeCount == expectedNodeCount {
		return nil
	}
	if nodeCount > expectedNodeCount {
		return fmt.Errorf(
			"%w: Merkle index has %d nodes for a %d-entry ledger (expected at most %d)",
			store.ErrInconsistentState,
			nodeCount,
			ledgerCount,
			expectedNodeCount,
		)
	}

	rows, err := database.QueryContext(ctx, `
		SELECT ledger_index, entry_hash
		FROM ledger_entries
		ORDER BY ledger_index`)
	if err != nil {
		return fmt.Errorf("read ledger for Merkle migration: %w", err)
	}
	entryHashes := make([]string, 0, ledgerCount)
	expectedIndex := int64(1)
	for rows.Next() {
		var ledgerIndex int64
		var entryHash string
		if err := rows.Scan(&ledgerIndex, &entryHash); err != nil {
			rows.Close()
			return fmt.Errorf("scan ledger for Merkle migration: %w", err)
		}
		if ledgerIndex != expectedIndex || !protocol.IsDigest(entryHash) {
			rows.Close()
			return fmt.Errorf("%w: cannot index a discontinuous or malformed ledger", store.ErrInconsistentState)
		}
		entryHashes = append(entryHashes, entryHash)
		expectedIndex++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate ledger for Merkle migration: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close Merkle migration rows: %w", err)
	}

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin Merkle migration: %w", err)
	}
	defer tx.Rollback()
	frontier := make(map[int64][]byte)
	for offset, entryHash := range entryHashes {
		current, err := merkleLeafBytes(entryHash)
		if err != nil {
			return err
		}
		nodeIndex := int64(offset)
		level := int64(0)
		for nodeIndex&1 == 1 {
			left, ok := frontier[level]
			if !ok {
				return fmt.Errorf("%w: Merkle migration frontier is incomplete", store.ErrInconsistentState)
			}
			current = merkleNodeBytes(left, current)
			delete(frontier, level)
			nodeIndex >>= 1
			level++
			if err := ensureMerkleNodeTx(ctx, tx, level, nodeIndex, current); err != nil {
				return err
			}
		}
		frontier[level] = current
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit Merkle migration: %w", err)
	}
	return nil
}

func appendMerkleEntryTx(
	ctx context.Context,
	tx *sql.Tx,
	ledgerIndex int64,
	entryHash string,
) error {
	if ledgerIndex < 1 {
		return fmt.Errorf("%w: invalid ledger index for Merkle append", store.ErrInconsistentState)
	}
	current, err := merkleLeafBytes(entryHash)
	if err != nil {
		return err
	}
	nodeIndex := ledgerIndex - 1
	level := int64(0)
	for nodeIndex&1 == 1 {
		left, err := completeMerkleSubtreeTx(ctx, tx, level, nodeIndex-1)
		if err != nil {
			return err
		}
		current = merkleNodeBytes(left, current)
		nodeIndex >>= 1
		level++
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ledger_merkle_nodes (tree_level, node_index, node_hash)
			VALUES (?, ?, ?)`,
			level,
			nodeIndex,
			current,
		); err != nil {
			return fmt.Errorf("append Merkle node %d/%d: %w", level, nodeIndex, err)
		}
	}
	return nil
}

func ensureMerkleNodeTx(
	ctx context.Context,
	tx *sql.Tx,
	level int64,
	index int64,
	expected []byte,
) error {
	var persisted []byte
	err := tx.QueryRowContext(ctx, `
		SELECT node_hash
		FROM ledger_merkle_nodes
		WHERE tree_level = ? AND node_index = ?`,
		level,
		index,
	).Scan(&persisted)
	if err == nil {
		if !equalHash(persisted, expected) {
			return fmt.Errorf("%w: persisted Merkle node %d/%d is invalid", store.ErrInconsistentState, level, index)
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read Merkle node %d/%d: %w", level, index, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO ledger_merkle_nodes (tree_level, node_index, node_hash)
		VALUES (?, ?, ?)`,
		level,
		index,
		expected,
	); err != nil {
		return fmt.Errorf("backfill Merkle node %d/%d: %w", level, index, err)
	}
	return nil
}

func (sqliteStore *Store) VerifyMerkleTree(ctx context.Context) error {
	var treeSize, nodeCount int64
	if err := sqliteStore.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ledger_entries").Scan(&treeSize); err != nil {
		return fmt.Errorf("count Merkle ledger leaves: %w", err)
	}
	if err := sqliteStore.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ledger_merkle_nodes").Scan(&nodeCount); err != nil {
		return fmt.Errorf("count Merkle internal nodes: %w", err)
	}
	expectedTotal := treeSize - int64(bits.OnesCount64(uint64(treeSize)))
	if nodeCount != expectedTotal {
		return fmt.Errorf("Merkle internal-node count is %d, expected %d", nodeCount, expectedTotal)
	}
	for level, width := int64(1), treeSize/2; width > 0; level, width = level+1, width/2 {
		var count int64
		var maximum sql.NullInt64
		if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT COUNT(*), MAX(node_index)
			FROM ledger_merkle_nodes
			WHERE tree_level = ?`,
			level,
		).Scan(&count, &maximum); err != nil {
			return fmt.Errorf("inspect Merkle level %d: %w", level, err)
		}
		if count != width || !maximum.Valid || maximum.Int64 != width-1 {
			return fmt.Errorf("Merkle level %d is discontinuous", level)
		}
	}

	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT tree_level, node_index, node_hash
		FROM ledger_merkle_nodes
		ORDER BY tree_level, node_index`)
	if err != nil {
		return fmt.Errorf("read Merkle nodes: %w", err)
	}
	type persistedNode struct {
		level int64
		index int64
		hash  []byte
	}
	nodes := make([]persistedNode, 0, nodeCount)
	for rows.Next() {
		var node persistedNode
		if err := rows.Scan(&node.level, &node.index, &node.hash); err != nil {
			rows.Close()
			return fmt.Errorf("scan Merkle node: %w", err)
		}
		nodes = append(nodes, node)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate Merkle nodes: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close Merkle nodes: %w", err)
	}

	for _, node := range nodes {
		left, err := sqliteStore.completeMerkleSubtree(ctx, node.level-1, node.index*2)
		if err != nil {
			return err
		}
		right, err := sqliteStore.completeMerkleSubtree(ctx, node.level-1, node.index*2+1)
		if err != nil {
			return err
		}
		if !equalHash(node.hash, merkleNodeBytes(left, right)) {
			return fmt.Errorf("Merkle node %d/%d hash verification failed", node.level, node.index)
		}
	}
	return nil
}

func (sqliteStore *Store) MerkleInclusionProof(
	ctx context.Context,
	ledgerIndex int64,
	treeSize int64,
) (store.MerkleInclusionRecord, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return store.MerkleInclusionRecord{}, fmt.Errorf("begin Merkle proof: %w", err)
	}
	defer tx.Rollback()
	actualSize, err := merkleTreeSizeTx(ctx, tx)
	if err != nil {
		return store.MerkleInclusionRecord{}, err
	}
	if treeSize == 0 {
		treeSize = actualSize
	}
	if treeSize < 1 || treeSize > actualSize || ledgerIndex < 1 || ledgerIndex > treeSize {
		return store.MerkleInclusionRecord{}, store.ErrNotFound
	}
	var entryHash string
	if err := tx.QueryRowContext(ctx, `
		SELECT entry_hash FROM ledger_entries WHERE ledger_index = ?`,
		ledgerIndex,
	).Scan(&entryHash); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return store.MerkleInclusionRecord{}, store.ErrNotFound
		}
		return store.MerkleInclusionRecord{}, fmt.Errorf("read Merkle proof leaf: %w", err)
	}
	leaf, err := merkleLeafBytes(entryHash)
	if err != nil {
		return store.MerkleInclusionRecord{}, err
	}
	path := make([]string, 0, bits.Len64(uint64(treeSize)))
	if err := inclusionPathTx(ctx, tx, 0, treeSize, ledgerIndex-1, &path); err != nil {
		return store.MerkleInclusionRecord{}, err
	}
	root, err := merkleSubtreeRootTx(ctx, tx, 0, treeSize)
	if err != nil {
		return store.MerkleInclusionRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return store.MerkleInclusionRecord{}, fmt.Errorf("finish Merkle proof: %w", err)
	}
	return store.MerkleInclusionRecord{
		LedgerIndex:     ledgerIndex,
		TreeSize:        treeSize,
		LedgerEntryHash: entryHash,
		LeafHash:        encodeMerkleHash(leaf),
		RootHash:        encodeMerkleHash(root),
		AuditPath:       path,
	}, nil
}

func (sqliteStore *Store) MerkleConsistencyProof(
	ctx context.Context,
	oldTreeSize int64,
	newTreeSize int64,
) (store.MerkleConsistencyRecord, error) {
	tx, err := sqliteStore.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return store.MerkleConsistencyRecord{}, fmt.Errorf("begin Merkle consistency proof: %w", err)
	}
	defer tx.Rollback()
	actualSize, err := merkleTreeSizeTx(ctx, tx)
	if err != nil {
		return store.MerkleConsistencyRecord{}, err
	}
	if newTreeSize == 0 {
		newTreeSize = actualSize
	}
	if oldTreeSize < 0 || oldTreeSize > newTreeSize || newTreeSize > actualSize {
		return store.MerkleConsistencyRecord{}, store.ErrNotFound
	}
	oldRoot := []byte(nil)
	if oldTreeSize == 0 {
		empty := sha256.Sum256(nil)
		oldRoot = empty[:]
	} else {
		oldRoot, err = merkleSubtreeRootTx(ctx, tx, 0, oldTreeSize)
		if err != nil {
			return store.MerkleConsistencyRecord{}, err
		}
	}
	newRoot := oldRoot
	path := make([]string, 0, bits.Len64(uint64(newTreeSize)))
	if oldTreeSize != newTreeSize {
		newRoot, err = merkleSubtreeRootTx(ctx, tx, 0, newTreeSize)
		if err != nil {
			return store.MerkleConsistencyRecord{}, err
		}
		if oldTreeSize > 0 {
			if err := consistencyPathTx(ctx, tx, oldTreeSize, 0, newTreeSize, true, &path); err != nil {
				return store.MerkleConsistencyRecord{}, err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return store.MerkleConsistencyRecord{}, fmt.Errorf("finish Merkle consistency proof: %w", err)
	}
	return store.MerkleConsistencyRecord{
		OldTreeSize: oldTreeSize,
		NewTreeSize: newTreeSize,
		OldRootHash: encodeMerkleHash(oldRoot),
		NewRootHash: encodeMerkleHash(newRoot),
		AuditPath:   path,
	}, nil
}

func inclusionPathTx(
	ctx context.Context,
	tx *sql.Tx,
	start int64,
	size int64,
	target int64,
	path *[]string,
) error {
	if size == 1 {
		return nil
	}
	split := largestMerklePower(size)
	if target < start+split {
		if err := inclusionPathTx(ctx, tx, start, split, target, path); err != nil {
			return err
		}
		right, err := merkleSubtreeRootTx(ctx, tx, start+split, size-split)
		if err != nil {
			return err
		}
		*path = append(*path, encodeMerkleHash(right))
		return nil
	}
	if err := inclusionPathTx(ctx, tx, start+split, size-split, target, path); err != nil {
		return err
	}
	left, err := merkleSubtreeRootTx(ctx, tx, start, split)
	if err != nil {
		return err
	}
	*path = append(*path, encodeMerkleHash(left))
	return nil
}

func consistencyPathTx(
	ctx context.Context,
	tx *sql.Tx,
	oldSize int64,
	start int64,
	newSize int64,
	completeOld bool,
	path *[]string,
) error {
	if oldSize == newSize {
		if !completeOld {
			root, err := merkleSubtreeRootTx(ctx, tx, start, newSize)
			if err != nil {
				return err
			}
			*path = append(*path, encodeMerkleHash(root))
		}
		return nil
	}
	split := largestMerklePower(newSize)
	if oldSize <= split {
		if err := consistencyPathTx(ctx, tx, oldSize, start, split, completeOld, path); err != nil {
			return err
		}
		right, err := merkleSubtreeRootTx(ctx, tx, start+split, newSize-split)
		if err != nil {
			return err
		}
		*path = append(*path, encodeMerkleHash(right))
		return nil
	}
	if err := consistencyPathTx(ctx, tx, oldSize-split, start+split, newSize-split, false, path); err != nil {
		return err
	}
	left, err := merkleSubtreeRootTx(ctx, tx, start, split)
	if err != nil {
		return err
	}
	*path = append(*path, encodeMerkleHash(left))
	return nil
}

func merkleSubtreeRootTx(
	ctx context.Context,
	tx *sql.Tx,
	start int64,
	size int64,
) ([]byte, error) {
	if size < 1 {
		return nil, fmt.Errorf("%w: invalid Merkle subtree size", store.ErrInconsistentState)
	}
	if size&(size-1) == 0 && start%size == 0 {
		level := int64(bits.TrailingZeros64(uint64(size)))
		return completeMerkleSubtreeTx(ctx, tx, level, start/size)
	}
	split := largestMerklePower(size)
	left, err := merkleSubtreeRootTx(ctx, tx, start, split)
	if err != nil {
		return nil, err
	}
	right, err := merkleSubtreeRootTx(ctx, tx, start+split, size-split)
	if err != nil {
		return nil, err
	}
	return merkleNodeBytes(left, right), nil
}

func completeMerkleSubtreeTx(
	ctx context.Context,
	tx *sql.Tx,
	level int64,
	index int64,
) ([]byte, error) {
	if level == 0 {
		var entryHash string
		if err := tx.QueryRowContext(ctx, `
			SELECT entry_hash
			FROM ledger_entries
			WHERE ledger_index = ?`,
			index+1,
		).Scan(&entryHash); err != nil {
			return nil, fmt.Errorf("read Merkle leaf %d: %w", index, err)
		}
		return merkleLeafBytes(entryHash)
	}
	var result []byte
	if err := tx.QueryRowContext(ctx, `
		SELECT node_hash
		FROM ledger_merkle_nodes
		WHERE tree_level = ? AND node_index = ?`,
		level,
		index,
	).Scan(&result); err != nil {
		return nil, fmt.Errorf("read Merkle node %d/%d: %w", level, index, err)
	}
	return result, nil
}

func (sqliteStore *Store) completeMerkleSubtree(
	ctx context.Context,
	level int64,
	index int64,
) ([]byte, error) {
	if level == 0 {
		var entryHash string
		if err := sqliteStore.db.QueryRowContext(ctx, `
			SELECT entry_hash FROM ledger_entries WHERE ledger_index = ?`,
			index+1,
		).Scan(&entryHash); err != nil {
			return nil, fmt.Errorf("read Merkle leaf %d: %w", index, err)
		}
		return merkleLeafBytes(entryHash)
	}
	var result []byte
	if err := sqliteStore.db.QueryRowContext(ctx, `
		SELECT node_hash FROM ledger_merkle_nodes
		WHERE tree_level = ? AND node_index = ?`,
		level,
		index,
	).Scan(&result); err != nil {
		return nil, fmt.Errorf("read Merkle node %d/%d: %w", level, index, err)
	}
	return result, nil
}

func merkleTreeSizeTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var result int64
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM ledger_entries").Scan(&result); err != nil {
		return 0, fmt.Errorf("read Merkle tree size: %w", err)
	}
	return result, nil
}

func merkleLeafBytes(entryHash string) ([]byte, error) {
	if !protocol.IsDigest(entryHash) {
		return nil, fmt.Errorf("%w: ledger entry hash is not canonical", store.ErrInconsistentState)
	}
	raw, err := hex.DecodeString(entryHash[len("sha256:"):])
	if err != nil || len(raw) != sha256.Size {
		return nil, fmt.Errorf("%w: ledger entry hash is not canonical", store.ErrInconsistentState)
	}
	message := make([]byte, 1+sha256.Size)
	copy(message[1:], raw)
	sum := sha256.Sum256(message)
	return sum[:], nil
}

func merkleNodeBytes(left, right []byte) []byte {
	message := make([]byte, 1+sha256.Size*2)
	message[0] = 1
	copy(message[1:], left)
	copy(message[1+sha256.Size:], right)
	sum := sha256.Sum256(message)
	return sum[:]
}

func encodeMerkleHash(value []byte) string {
	return "sha256:" + hex.EncodeToString(value)
}

func largestMerklePower(value int64) int64 {
	power := int64(1)
	for power<<1 < value {
		power <<= 1
	}
	return power
}

func equalHash(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
