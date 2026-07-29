package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/service"
)

func runMerkleProof(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("merkle-proof", flag.ContinueOnError)
	flags.SetOutput(stdout)
	ledgerIndex := flags.Int64("ledger-index", 0, "one-based ledger entry index")
	treeSize := flags.Int64("tree-size", 0, "ledger prefix size; 0 selects the current head")
	flags.Usage = func() {
		fmt.Fprintln(stdout, "Usage: /registry merkle-proof --ledger-index N [--tree-size N]")
		fmt.Fprintln(stdout, "Returns an RFC 9162 CT-style inclusion proof and registry-signed tree head.")
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *ledgerIndex < 1 || *treeSize < 0 {
		flags.Usage()
		return errors.New("merkle-proof requires a positive --ledger-index and non-negative --tree-size")
	}
	return withRegistryService(func(ctx context.Context, registry *service.Service) error {
		proof, err := registry.MerkleInclusionProof(ctx, *ledgerIndex, *treeSize)
		if err != nil {
			return err
		}
		return writeCLIJSON(stdout, proof)
	})
}

func runMerkleConsistency(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("merkle-consistency", flag.ContinueOnError)
	flags.SetOutput(stdout)
	oldTreeSize := flags.Int64("old-tree-size", -1, "previous witnessed tree size, including 0")
	newTreeSize := flags.Int64("new-tree-size", 0, "new ledger prefix size; 0 selects the current head")
	flags.Usage = func() {
		fmt.Fprintln(stdout, "Usage: /registry merkle-consistency --old-tree-size N [--new-tree-size N]")
		fmt.Fprintln(stdout, "Returns an RFC 9162 CT-style append-only consistency proof.")
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *oldTreeSize < 0 || *newTreeSize < 0 {
		flags.Usage()
		return errors.New("merkle-consistency requires non-negative tree sizes")
	}
	return withRegistryService(func(ctx context.Context, registry *service.Service) error {
		proof, err := registry.MerkleConsistencyProof(ctx, *oldTreeSize, *newTreeSize)
		if err != nil {
			return err
		}
		return writeCLIJSON(stdout, proof)
	})
}

func runVerifyMerkleProof(args []string, stdin io.Reader, stdout io.Writer) error {
	var proof protocol.MerkleInclusionProof
	help, err := readMerkleJSONArgument("verify-merkle-proof", args, stdin, stdout, &proof)
	if err != nil || help {
		return err
	}
	if err := protocol.VerifyMerkleInclusionProof(proof); err != nil {
		return fmt.Errorf("verify Merkle inclusion proof: %w", err)
	}
	return writeCLIJSON(stdout, map[string]any{
		"valid":        true,
		"tree_size":    proof.TreeHead.TreeSize,
		"root_hash":    proof.TreeHead.RootHash,
		"ledger_index": proof.LedgerIndex,
	})
}

func runVerifyMerkleConsistency(args []string, stdin io.Reader, stdout io.Writer) error {
	var proof protocol.MerkleConsistencyProof
	help, err := readMerkleJSONArgument("verify-merkle-consistency", args, stdin, stdout, &proof)
	if err != nil || help {
		return err
	}
	if err := protocol.VerifyMerkleConsistencyProof(proof); err != nil {
		return fmt.Errorf("verify Merkle consistency proof: %w", err)
	}
	return writeCLIJSON(stdout, map[string]any{
		"valid":         true,
		"old_tree_size": proof.OldTreeSize,
		"new_tree_size": proof.TreeHead.TreeSize,
		"root_hash":     proof.TreeHead.RootHash,
	})
}

func readMerkleJSONArgument(
	command string,
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	destination any,
) (bool, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stdout)
	filePath := flags.String("file", "", "proof JSON path, or - for stdin")
	flags.Usage = func() {
		fmt.Fprintf(stdout, "Usage: /registry %s --file PATH|-\\n", command)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil {
		return false, err
	}
	if help {
		return true, nil
	}
	if *filePath == "" {
		flags.Usage()
		return false, errors.New(command + " requires --file")
	}
	reader := stdin
	var file *os.File
	if *filePath != "-" {
		file, err = os.Open(*filePath)
		if err != nil {
			return false, fmt.Errorf("open proof file: %w", err)
		}
		defer file.Close()
		reader = file
	}
	decoder := json.NewDecoder(io.LimitReader(reader, 1024*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false, fmt.Errorf("decode proof JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return false, errors.New("proof file must contain exactly one JSON object")
	}
	return false, nil
}
