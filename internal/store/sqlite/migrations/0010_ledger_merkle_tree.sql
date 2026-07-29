-- Compact RFC 9162 Certificate-Transparency-style Merkle index over the
-- immutable ledger entry hashes. Leaves are derived from ledger_entries and
-- are not duplicated. Only completed internal subtree nodes are persisted,
-- giving n-popcount(n) rows for n ledger entries (strictly fewer than n).
CREATE TABLE ledger_merkle_nodes (
    tree_level  INTEGER NOT NULL CHECK (tree_level BETWEEN 1 AND 62),
    node_index  INTEGER NOT NULL CHECK (node_index >= 0),
    node_hash   BLOB NOT NULL CHECK (length(node_hash) = 32),
    PRIMARY KEY (tree_level, node_index)
) WITHOUT ROWID;

CREATE TRIGGER ledger_merkle_nodes_no_update
BEFORE UPDATE ON ledger_merkle_nodes BEGIN
    SELECT RAISE(ABORT, 'ledger Merkle nodes are append-only');
END;

CREATE TRIGGER ledger_merkle_nodes_no_delete
BEFORE DELETE ON ledger_merkle_nodes BEGIN
    SELECT RAISE(ABORT, 'ledger Merkle nodes are append-only');
END;
