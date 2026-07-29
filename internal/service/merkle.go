package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func (registry *Service) MerkleInclusionProof(
	ctx context.Context,
	ledgerIndex int64,
	treeSize int64,
) (protocol.MerkleInclusionProof, error) {
	if ledgerIndex < 1 || treeSize < 0 {
		return protocol.MerkleInclusionProof{}, requestError(
			"invalid_request",
			"ledger index must be positive and tree size must be non-negative",
		)
	}
	record, err := registry.store.MerkleInclusionProof(ctx, ledgerIndex, treeSize)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.MerkleInclusionProof{}, requestError(
				"merkle_proof_not_found",
				"the requested ledger leaf or tree size does not exist",
			)
		}
		return protocol.MerkleInclusionProof{}, err
	}
	head := registry.signedMerkleTreeHead(record.TreeSize, record.RootHash)
	proof := protocol.MerkleInclusionProof{
		LedgerIndex:     record.LedgerIndex,
		LedgerEntryHash: record.LedgerEntryHash,
		LeafHash:        record.LeafHash,
		AuditPath:       record.AuditPath,
		TreeHead:        head,
	}
	if err := protocol.VerifyMerkleInclusionProof(proof); err != nil {
		return protocol.MerkleInclusionProof{}, fmt.Errorf(
			"generated Merkle inclusion proof failed verification: %w",
			err,
		)
	}
	return proof, nil
}

func (registry *Service) MerkleConsistencyProof(
	ctx context.Context,
	oldTreeSize int64,
	newTreeSize int64,
) (protocol.MerkleConsistencyProof, error) {
	if oldTreeSize < 0 || newTreeSize < 0 {
		return protocol.MerkleConsistencyProof{}, requestError(
			"invalid_request",
			"Merkle tree sizes must be non-negative",
		)
	}
	record, err := registry.store.MerkleConsistencyProof(ctx, oldTreeSize, newTreeSize)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.MerkleConsistencyProof{}, requestError(
				"merkle_proof_not_found",
				"the requested Merkle tree sizes do not exist",
			)
		}
		return protocol.MerkleConsistencyProof{}, err
	}
	proof := protocol.MerkleConsistencyProof{
		OldTreeSize: record.OldTreeSize,
		OldRootHash: record.OldRootHash,
		AuditPath:   record.AuditPath,
		TreeHead: registry.signedMerkleTreeHead(
			record.NewTreeSize,
			record.NewRootHash,
		),
	}
	if err := protocol.VerifyMerkleConsistencyProof(proof); err != nil {
		return protocol.MerkleConsistencyProof{}, fmt.Errorf(
			"generated Merkle consistency proof failed verification: %w",
			err,
		)
	}
	return proof, nil
}

func (registry *Service) signedMerkleTreeHead(
	treeSize int64,
	rootHash string,
) protocol.MerkleTreeHead {
	head := protocol.MerkleTreeHead{
		ProtocolVersion:   protocol.Version,
		RegistryScope:     registry.registryScope,
		TreeSize:          treeSize,
		RootHash:          rootHash,
		GeneratedAt:       registry.canonicalNow().Format(time.RFC3339),
		RegistryKeyID:     registry.signingKey.KeyID(),
		RegistryPublicKey: registry.signingKey.EncodedPublicKey(),
	}
	head.Signature = protocol.EncodeSignature(
		registry.signingKey.Sign(protocol.MerkleTreeHeadMessage(head)),
	)
	return head
}
