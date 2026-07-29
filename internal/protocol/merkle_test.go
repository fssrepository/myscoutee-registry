package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestRFC9162StyleMerkleInclusionAndConsistencyProofs(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublicKey, publicKeyDER, err := EncodePublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	entryHashes := make([]string, 17)
	for index := range entryHashes {
		entryHashes[index] = Digest([]byte(fmt.Sprintf("ledger-entry-%d", index+1)))
	}
	for treeSize := 1; treeSize <= len(entryHashes); treeSize++ {
		root := testMerkleRoot(t, entryHashes[:treeSize])
		head := MerkleTreeHead{
			ProtocolVersion:   Version,
			RegistryScope:     "example:merkle-test",
			TreeSize:          int64(treeSize),
			RootHash:          root,
			GeneratedAt:       "2026-07-29T03:00:00Z",
			RegistryKeyID:     RegistryKeyID(publicKeyDER),
			RegistryPublicKey: encodedPublicKey,
		}
		head.Signature = EncodeSignature(ed25519.Sign(privateKey, MerkleTreeHeadMessage(head)))
		for ledgerIndex := 1; ledgerIndex <= treeSize; ledgerIndex++ {
			path := make([]string, 0)
			testInclusionPath(t, entryHashes[:treeSize], ledgerIndex-1, &path)
			leaf, err := MerkleLeafHash(entryHashes[ledgerIndex-1])
			if err != nil {
				t.Fatal(err)
			}
			proof := MerkleInclusionProof{
				LedgerIndex:     int64(ledgerIndex),
				LedgerEntryHash: entryHashes[ledgerIndex-1],
				LeafHash:        leaf,
				AuditPath:       path,
				TreeHead:        head,
			}
			if err := VerifyMerkleInclusionProof(proof); err != nil {
				t.Fatalf("verify inclusion tree=%d leaf=%d: %v", treeSize, ledgerIndex, err)
			}
		}
		for oldSize := 0; oldSize <= treeSize; oldSize++ {
			oldRoot := MerkleEmptyRoot()
			path := make([]string, 0)
			if oldSize > 0 {
				oldRoot = testMerkleRoot(t, entryHashes[:oldSize])
				if oldSize != treeSize {
					testConsistencyPath(t, entryHashes[:treeSize], oldSize, true, &path)
				}
			}
			proof := MerkleConsistencyProof{
				OldTreeSize: int64(oldSize),
				OldRootHash: oldRoot,
				AuditPath:   path,
				TreeHead:    head,
			}
			if err := VerifyMerkleConsistencyProof(proof); err != nil {
				t.Fatalf("verify consistency old=%d new=%d: %v", oldSize, treeSize, err)
			}
		}
	}
}

func TestMerkleProofTamperingFails(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublicKey, publicKeyDER, err := EncodePublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	entries := []string{Digest([]byte("a")), Digest([]byte("b")), Digest([]byte("c"))}
	head := MerkleTreeHead{
		ProtocolVersion:   Version,
		RegistryScope:     "example:merkle-test",
		TreeSize:          3,
		RootHash:          testMerkleRoot(t, entries),
		GeneratedAt:       "2026-07-29T03:00:00Z",
		RegistryKeyID:     RegistryKeyID(publicKeyDER),
		RegistryPublicKey: encodedPublicKey,
	}
	head.Signature = EncodeSignature(ed25519.Sign(privateKey, MerkleTreeHeadMessage(head)))
	path := make([]string, 0)
	testInclusionPath(t, entries, 1, &path)
	leaf, _ := MerkleLeafHash(entries[1])
	proof := MerkleInclusionProof{
		LedgerIndex:     2,
		LedgerEntryHash: entries[1],
		LeafHash:        leaf,
		AuditPath:       path,
		TreeHead:        head,
	}
	proof.AuditPath[0] = Digest([]byte("tampered"))
	if err := VerifyMerkleInclusionProof(proof); err == nil {
		t.Fatal("tampered inclusion proof unexpectedly verified")
	}
}

func testMerkleRoot(t *testing.T, entries []string) string {
	t.Helper()
	if len(entries) == 0 {
		return MerkleEmptyRoot()
	}
	if len(entries) == 1 {
		result, err := MerkleLeafHash(entries[0])
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	split := 1
	for split<<1 < len(entries) {
		split <<= 1
	}
	result, err := MerkleNodeHash(
		testMerkleRoot(t, entries[:split]),
		testMerkleRoot(t, entries[split:]),
	)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testInclusionPath(t *testing.T, entries []string, target int, path *[]string) {
	t.Helper()
	if len(entries) == 1 {
		return
	}
	split := 1
	for split<<1 < len(entries) {
		split <<= 1
	}
	if target < split {
		testInclusionPath(t, entries[:split], target, path)
		*path = append(*path, testMerkleRoot(t, entries[split:]))
		return
	}
	testInclusionPath(t, entries[split:], target-split, path)
	*path = append(*path, testMerkleRoot(t, entries[:split]))
}

func testConsistencyPath(
	t *testing.T,
	entries []string,
	oldSize int,
	completeOld bool,
	path *[]string,
) {
	t.Helper()
	if oldSize == len(entries) {
		if !completeOld {
			*path = append(*path, testMerkleRoot(t, entries))
		}
		return
	}
	split := 1
	for split<<1 < len(entries) {
		split <<= 1
	}
	if oldSize <= split {
		testConsistencyPath(t, entries[:split], oldSize, completeOld, path)
		*path = append(*path, testMerkleRoot(t, entries[split:]))
		return
	}
	testConsistencyPath(t, entries[split:], oldSize-split, false, path)
	*path = append(*path, testMerkleRoot(t, entries[:split]))
}
