package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/service"
)

func runCreateExitAllocation(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("create-exit-allocation", flag.ContinueOnError)
	flags.SetOutput(stdout)
	exitReviewID := flags.String(
		"exit-review-id",
		"",
		"exact verified-eligible exit review ID",
	)
	exitEventHash := flags.String(
		"exit-verification-event-hash",
		"",
		"exact current verified-eligible exit event hash",
	)
	decisionMode := flags.String(
		"decision-mode",
		"",
		"completed-transfer or no-transfer",
	)
	transferID := flags.String(
		"ownership-transfer-id",
		"",
		"exact completed transfer ID; completed-transfer only",
	)
	transferEventHash := flags.String(
		"ownership-transfer-completion-event-hash",
		"",
		"exact completed transfer event hash; completed-transfer only",
	)
	beneficiaryID := flags.String(
		"beneficiary-id",
		"",
		"bounded opaque non-personal contract beneficiary; no-transfer only",
	)
	contractReference := flags.String(
		"contract-reference",
		"",
		"bounded non-personal contractual decision reference",
	)
	contractTermsHash := flags.String(
		"contract-terms-hash",
		"",
		"sha256:<64 lowercase hex> commitment to the complete contractual terms",
	)
	evidenceHash := flags.String(
		"evidence-hash",
		"",
		"sha256:<64 lowercase hex> commitment to the complete supporting evidence",
	)
	allocatorID := flags.String(
		"allocator-id",
		"",
		"bounded non-personal allocator identifier",
	)
	idempotencyKey := flags.String(
		"idempotency-key",
		"",
		"8-128 character printable ASCII retry key",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry create-exit-allocation --exit-review-id ID --exit-verification-event-hash SHA256 --decision-mode completed-transfer|no-transfer [--ownership-transfer-id ID --ownership-transfer-completion-event-hash SHA256|--beneficiary-id ID] --contract-reference REF --contract-terms-hash SHA256 --evidence-hash SHA256 --allocator-id ID --idempotency-key KEY",
		)
		fmt.Fprintln(
			stdout,
			"Creates an append-only contractual allocation record. It stores no payment execution, bank details, tax data, or invoice.",
		)
		fmt.Fprintln(
			stdout,
			"For completed-transfer the beneficiary is derived from the exact transfer target group. For no-transfer, --beneficiary-id is required.",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *exitReviewID == "" ||
		*exitEventHash == "" ||
		*decisionMode == "" ||
		*contractReference == "" ||
		*contractTermsHash == "" ||
		*evidenceHash == "" ||
		*allocatorID == "" ||
		*idempotencyKey == "" {
		flags.Usage()
		return errors.New(
			"create-exit-allocation requires every documented common argument",
		)
	}
	switch *decisionMode {
	case protocol.ExitAllocationDecisionCompletedTransfer:
		if *transferID == "" ||
			*transferEventHash == "" ||
			*beneficiaryID != "" {
			flags.Usage()
			return errors.New(
				"completed-transfer requires both ownership-transfer fields and forbids beneficiary-id",
			)
		}
	case protocol.ExitAllocationDecisionNoTransfer:
		if *beneficiaryID == "" ||
			*transferID != "" ||
			*transferEventHash != "" {
			flags.Usage()
			return errors.New(
				"no-transfer requires beneficiary-id and forbids ownership-transfer fields",
			)
		}
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		result, err := registryService.CreateExitAllocation(
			ctx,
			service.ExitAllocationCreate{
				ExitReviewID:                         *exitReviewID,
				ExitVerificationEventHash:            *exitEventHash,
				DecisionMode:                         *decisionMode,
				OwnershipTransferID:                  *transferID,
				OwnershipTransferCompletionEventHash: *transferEventHash,
				BeneficiaryID:                        *beneficiaryID,
				ContractReference:                    *contractReference,
				ContractTermsHash:                    *contractTermsHash,
				EvidenceHash:                         *evidenceHash,
				AllocatorID:                          *allocatorID,
				IdempotencyKey:                       *idempotencyKey,
			},
		)
		if err != nil {
			return fmt.Errorf("create final exit allocation: %w", err)
		}
		return writeCLIJSON(stdout, result)
	})
}

func runVerifyExitAllocation(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("verify-exit-allocation", flag.ContinueOnError)
	flags.SetOutput(stdout)
	allocationID := flags.String(
		"allocation-id",
		"",
		"exact recorded final exit allocation ID",
	)
	verifierID := flags.String(
		"verifier-id",
		"",
		"bounded non-personal registry verifier identifier",
	)
	reference := flags.String(
		"reference",
		"",
		"bounded non-personal verification reference",
	)
	evidenceHash := flags.String(
		"evidence-hash",
		"",
		"sha256:<64 lowercase hex> verification evidence commitment",
	)
	idempotencyKey := flags.String(
		"idempotency-key",
		"",
		"8-128 character printable ASCII retry key",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry verify-exit-allocation --allocation-id ID --verifier-id ID --reference REF --evidence-hash SHA256 --idempotency-key KEY",
		)
		fmt.Fprintln(
			stdout,
			"Rechecks the live verified-exit and beneficiary decision boundaries, exact frozen settlement rows, and per-currency conservation before appending the terminal signed verified-final event.",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *allocationID == "" ||
		*verifierID == "" ||
		*reference == "" ||
		*evidenceHash == "" ||
		*idempotencyKey == "" {
		flags.Usage()
		return errors.New(
			"verify-exit-allocation requires every documented argument",
		)
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		result, err := registryService.VerifyExitAllocation(
			ctx,
			service.ExitAllocationVerification{
				AllocationID:   *allocationID,
				VerifierID:     *verifierID,
				Reference:      *reference,
				EvidenceHash:   *evidenceHash,
				IdempotencyKey: *idempotencyKey,
			},
		)
		if err != nil {
			return fmt.Errorf("verify final exit allocation: %w", err)
		}
		return writeCLIJSON(stdout, result)
	})
}

func runShowExitAllocation(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("show-exit-allocation", flag.ContinueOnError)
	flags.SetOutput(stdout)
	allocationID := flags.String(
		"allocation-id",
		"",
		"exact final exit allocation ID",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry show-exit-allocation --allocation-id ID",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *allocationID == "" {
		flags.Usage()
		return errors.New("show-exit-allocation requires --allocation-id")
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		allocation, err := registryService.ExitAllocation(ctx, *allocationID)
		if err != nil {
			return fmt.Errorf("show final exit allocation: %w", err)
		}
		return writeCLIJSON(stdout, allocation)
	})
}

func runListExitAllocations(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("list-exit-allocations", flag.ContinueOnError)
	flags.SetOutput(stdout)
	status := flags.String(
		"status",
		"",
		"optional recorded or verified-final filter",
	)
	decisionMode := flags.String(
		"decision-mode",
		"",
		"optional completed-transfer or no-transfer filter",
	)
	limit := flags.Int("limit", 50, "number of records (1-200)")
	beforeEventIndex := flags.Int64(
		"before-event-index",
		0,
		"exclusive cursor copied from next_event_index",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry list-exit-allocations [--status recorded|verified-final] [--decision-mode completed-transfer|no-transfer] [--limit N] [--before-event-index N]",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		page, err := registryService.ExitAllocations(
			ctx,
			*status,
			*decisionMode,
			*limit,
			*beforeEventIndex,
		)
		if err != nil {
			return fmt.Errorf("list final exit allocations: %w", err)
		}
		return writeCLIJSON(stdout, page)
	})
}
