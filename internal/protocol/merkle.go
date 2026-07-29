package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

// MerkleTreeHead is a registry-signed commitment to one immutable ledger
// prefix. Hashing follows the domain-separated Merkle Tree Hash construction
// in RFC 9162 section 2.1; the signed-head envelope is registry-specific.
type MerkleTreeHead struct {
	ProtocolVersion   string `json:"protocol_version"`
	RegistryScope     string `json:"registry_scope"`
	TreeSize          int64  `json:"tree_size"`
	RootHash          string `json:"root_hash"`
	GeneratedAt       string `json:"generated_at"`
	RegistryKeyID     string `json:"registry_key_id"`
	RegistryPublicKey string `json:"registry_public_key"`
	Signature         string `json:"signature"`
}

type MerkleInclusionProof struct {
	LedgerIndex     int64          `json:"ledger_index"`
	LedgerEntryHash string         `json:"ledger_entry_hash"`
	LeafHash        string         `json:"leaf_hash"`
	AuditPath       []string       `json:"audit_path"`
	TreeHead        MerkleTreeHead `json:"tree_head"`
}

type MerkleConsistencyProof struct {
	OldTreeSize int64          `json:"old_tree_size"`
	OldRootHash string         `json:"old_root_hash"`
	AuditPath   []string       `json:"audit_path"`
	TreeHead    MerkleTreeHead `json:"tree_head"`
}

func MerkleLeafHash(ledgerEntryHash string) (string, error) {
	entryHash, err := decodeDigest(ledgerEntryHash)
	if err != nil {
		return "", fmt.Errorf("decode ledger entry hash: %w", err)
	}
	message := make([]byte, 1+len(entryHash))
	message[0] = 0
	copy(message[1:], entryHash)
	sum := sha256.Sum256(message)
	return encodeDigest(sum[:]), nil
}

func MerkleNodeHash(leftHash, rightHash string) (string, error) {
	left, err := decodeDigest(leftHash)
	if err != nil {
		return "", fmt.Errorf("decode left Merkle hash: %w", err)
	}
	right, err := decodeDigest(rightHash)
	if err != nil {
		return "", fmt.Errorf("decode right Merkle hash: %w", err)
	}
	message := make([]byte, 1+sha256.Size*2)
	message[0] = 1
	copy(message[1:1+sha256.Size], left)
	copy(message[1+sha256.Size:], right)
	sum := sha256.Sum256(message)
	return encodeDigest(sum[:]), nil
}

func MerkleEmptyRoot() string {
	sum := sha256.Sum256(nil)
	return encodeDigest(sum[:])
}

func MerkleTreeHeadMessage(head MerkleTreeHead) []byte {
	return canonical(
		"myscoutee-registry-merkle-tree-head-v1",
		head.ProtocolVersion,
		head.RegistryScope,
		strconv.FormatInt(head.TreeSize, 10),
		head.RootHash,
		head.GeneratedAt,
		head.RegistryKeyID,
	)
}

func VerifyMerkleTreeHead(head MerkleTreeHead) error {
	if head.ProtocolVersion != Version ||
		!IsRegistryScope(head.RegistryScope) ||
		head.TreeSize < 0 ||
		!IsDigest(head.RootHash) {
		return errors.New("Merkle tree head contains invalid fields")
	}
	publicKey, publicKeyDER, err := ParsePublicKey(head.RegistryPublicKey)
	if err != nil {
		return err
	}
	if RegistryKeyID(publicKeyDER) != head.RegistryKeyID {
		return errors.New("Merkle tree head key ID does not match its public key")
	}
	signature, err := ParseSignature(head.Signature)
	if err != nil {
		return err
	}
	if !Verify(publicKey, MerkleTreeHeadMessage(head), signature) {
		return errors.New("Merkle tree head signature verification failed")
	}
	return nil
}

func VerifyMerkleInclusionProof(proof MerkleInclusionProof) error {
	if err := VerifyMerkleTreeHead(proof.TreeHead); err != nil {
		return err
	}
	if proof.LedgerIndex < 1 || proof.LedgerIndex > proof.TreeHead.TreeSize {
		return errors.New("ledger index is outside the signed Merkle tree")
	}
	leafHash, err := MerkleLeafHash(proof.LedgerEntryHash)
	if err != nil {
		return err
	}
	if leafHash != proof.LeafHash {
		return errors.New("Merkle leaf hash does not commit to the ledger entry hash")
	}
	position := 0
	root, err := rebuildInclusionRoot(
		0,
		proof.TreeHead.TreeSize,
		proof.LedgerIndex-1,
		leafHash,
		proof.AuditPath,
		&position,
	)
	if err != nil {
		return err
	}
	if position != len(proof.AuditPath) {
		return errors.New("Merkle inclusion proof contains extra audit nodes")
	}
	if root != proof.TreeHead.RootHash {
		return errors.New("Merkle inclusion proof root does not match the signed tree head")
	}
	return nil
}

func VerifyMerkleConsistencyProof(proof MerkleConsistencyProof) error {
	if err := VerifyMerkleTreeHead(proof.TreeHead); err != nil {
		return err
	}
	if proof.OldTreeSize < 0 ||
		proof.OldTreeSize > proof.TreeHead.TreeSize ||
		!IsDigest(proof.OldRootHash) {
		return errors.New("Merkle consistency proof contains invalid tree sizes or root")
	}
	if proof.OldTreeSize == 0 {
		if proof.OldRootHash != MerkleEmptyRoot() || len(proof.AuditPath) != 0 {
			return errors.New("empty-tree consistency proof must use the RFC 9162 empty root and no audit path")
		}
		return nil
	}
	if proof.OldTreeSize == proof.TreeHead.TreeSize {
		if proof.OldRootHash != proof.TreeHead.RootHash || len(proof.AuditPath) != 0 {
			return errors.New("equal-size consistency proof must have equal roots and no audit path")
		}
		return nil
	}
	position := 0
	oldRoot, newRoot, err := rebuildConsistencyRoots(
		proof.OldTreeSize,
		proof.TreeHead.TreeSize,
		true,
		proof.OldRootHash,
		proof.AuditPath,
		&position,
	)
	if err != nil {
		return err
	}
	if position != len(proof.AuditPath) {
		return errors.New("Merkle consistency proof contains extra audit nodes")
	}
	if oldRoot != proof.OldRootHash || newRoot != proof.TreeHead.RootHash {
		return errors.New("Merkle consistency proof does not match the supplied roots")
	}
	return nil
}

func rebuildInclusionRoot(
	start int64,
	size int64,
	target int64,
	leafHash string,
	path []string,
	position *int,
) (string, error) {
	if size == 1 {
		return leafHash, nil
	}
	split := largestPowerOfTwoLessThan(size)
	if target < start+split {
		left, err := rebuildInclusionRoot(start, split, target, leafHash, path, position)
		if err != nil {
			return "", err
		}
		right, err := nextAuditHash(path, position)
		if err != nil {
			return "", err
		}
		return MerkleNodeHash(left, right)
	}
	right, err := rebuildInclusionRoot(start+split, size-split, target, leafHash, path, position)
	if err != nil {
		return "", err
	}
	left, err := nextAuditHash(path, position)
	if err != nil {
		return "", err
	}
	return MerkleNodeHash(left, right)
}

func rebuildConsistencyRoots(
	oldSize int64,
	newSize int64,
	useKnownOldRoot bool,
	knownOldRoot string,
	path []string,
	position *int,
) (string, string, error) {
	if oldSize == newSize {
		if useKnownOldRoot {
			return knownOldRoot, knownOldRoot, nil
		}
		root, err := nextAuditHash(path, position)
		return root, root, err
	}
	split := largestPowerOfTwoLessThan(newSize)
	if oldSize <= split {
		oldLeft, newLeft, err := rebuildConsistencyRoots(
			oldSize,
			split,
			useKnownOldRoot,
			knownOldRoot,
			path,
			position,
		)
		if err != nil {
			return "", "", err
		}
		right, err := nextAuditHash(path, position)
		if err != nil {
			return "", "", err
		}
		newRoot, err := MerkleNodeHash(newLeft, right)
		return oldLeft, newRoot, err
	}
	oldRight, newRight, err := rebuildConsistencyRoots(
		oldSize-split,
		newSize-split,
		false,
		knownOldRoot,
		path,
		position,
	)
	if err != nil {
		return "", "", err
	}
	left, err := nextAuditHash(path, position)
	if err != nil {
		return "", "", err
	}
	oldRoot, err := MerkleNodeHash(left, oldRight)
	if err != nil {
		return "", "", err
	}
	newRoot, err := MerkleNodeHash(left, newRight)
	return oldRoot, newRoot, err
}

func nextAuditHash(path []string, position *int) (string, error) {
	if *position >= len(path) {
		return "", errors.New("Merkle proof audit path is truncated")
	}
	value := path[*position]
	*position++
	if !IsDigest(value) {
		return "", errors.New("Merkle proof contains a malformed audit hash")
	}
	return value, nil
}

func largestPowerOfTwoLessThan(value int64) int64 {
	power := int64(1)
	for power<<1 < value {
		power <<= 1
	}
	return power
}

func decodeDigest(value string) ([]byte, error) {
	if !IsDigest(value) {
		return nil, errors.New("digest must be canonical lowercase SHA-256")
	}
	return hex.DecodeString(value[len("sha256:"):])
}

func encodeDigest(value []byte) string {
	return "sha256:" + hex.EncodeToString(value)
}
