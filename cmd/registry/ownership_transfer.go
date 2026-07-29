package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/fssrepository/myscoutee-registry/internal/service"
)

func runPrepareOwnershipTransfer(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("prepare-ownership-transfer", flag.ContinueOnError)
	flags.SetOutput(stdout)
	exitReviewID := flags.String(
		"exit-review-id",
		"",
		"exact verified exit review ID",
	)
	deploymentID := flags.String(
		"deployment-id",
		"",
		"exact source deployment ID",
	)
	claimActionID := flags.String(
		"claim-action-id",
		"",
		"exact approved active claim generation",
	)
	sourceGroupID := flags.String(
		"source-group-id",
		"",
		"exact source operator group",
	)
	targetGroupID := flags.String(
		"target-group-id",
		"",
		"existing target group with an active approved eligible claim",
	)
	exitEventHash := flags.String(
		"exit-verification-event-hash",
		"",
		"exact current verified-eligible exit event hash",
	)
	requesterID := flags.String(
		"requester-id",
		"",
		"bounded non-personal request-system identifier",
	)
	reference := flags.String(
		"reference",
		"",
		"bounded non-personal transfer request reference",
	)
	evidenceHash := flags.String(
		"evidence-hash",
		"",
		"optional sha256:<64 lowercase hex> request evidence commitment",
	)
	idempotencyKey := flags.String(
		"idempotency-key",
		"",
		"8-128 character printable ASCII retry key",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry prepare-ownership-transfer --exit-review-id ID --deployment-id ID --claim-action-id ID --source-group-id ID --target-group-id ID --exit-verification-event-hash SHA256 --requester-id ID --reference REF [--evidence-hash SHA256] --idempotency-key KEY",
		)
		fmt.Fprintln(
			stdout,
			"Pins the exact approved/eligible claim and current verified exit-review event. It does not change group membership or execute payment.",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *exitReviewID == "" ||
		*deploymentID == "" ||
		*claimActionID == "" ||
		*sourceGroupID == "" ||
		*targetGroupID == "" ||
		*exitEventHash == "" ||
		*requesterID == "" ||
		*reference == "" ||
		*idempotencyKey == "" {
		flags.Usage()
		return errors.New(
			"prepare-ownership-transfer requires every documented non-optional argument",
		)
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		result, err := registryService.PrepareOwnershipTransfer(
			ctx,
			service.OwnershipTransferPrepare{
				ExitReviewID:              *exitReviewID,
				TargetDeploymentID:        *deploymentID,
				ClaimActionID:             *claimActionID,
				SourceGroupID:             *sourceGroupID,
				TargetGroupID:             *targetGroupID,
				ExitVerificationEventHash: *exitEventHash,
				RequesterID:               *requesterID,
				Reference:                 *reference,
				EvidenceHash:              *evidenceHash,
				IdempotencyKey:            *idempotencyKey,
			},
		)
		if err != nil {
			return fmt.Errorf("prepare ownership transfer: %w", err)
		}
		return writeCLIJSON(stdout, result)
	})
}

func runDecideOwnershipTransfer(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("decide-ownership-transfer", flag.ContinueOnError)
	flags.SetOutput(stdout)
	transferID := flags.String("transfer-id", "", "exact ownership transfer ID")
	decision := flags.String("decision", "", "approve or reject")
	effectiveDate := flags.String(
		"effective-date",
		"",
		"non-future UTC decision date in YYYY-MM-DD",
	)
	managerID := flags.String(
		"manager-id",
		"",
		"bounded non-personal registry-manager identifier",
	)
	reference := flags.String(
		"reference",
		"",
		"bounded non-personal manager decision reference",
	)
	evidenceHash := flags.String(
		"evidence-hash",
		"",
		"optional sha256:<64 lowercase hex> decision evidence commitment",
	)
	reasonCode := flags.String(
		"reason-code",
		"",
		"required lowercase reason token for reject; empty for approve",
	)
	idempotencyKey := flags.String(
		"idempotency-key",
		"",
		"8-128 character printable ASCII retry key",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry decide-ownership-transfer --transfer-id ID --decision approve|reject --effective-date YYYY-MM-DD --manager-id ID --reference REF [--evidence-hash SHA256] [--reason-code TOKEN] --idempotency-key KEY",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *transferID == "" ||
		*decision == "" ||
		*effectiveDate == "" ||
		*managerID == "" ||
		*reference == "" ||
		*idempotencyKey == "" {
		flags.Usage()
		return errors.New(
			"decide-ownership-transfer requires every documented non-optional argument",
		)
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		result, err := registryService.DecideOwnershipTransfer(
			ctx,
			service.OwnershipTransferDecision{
				TransferID:     *transferID,
				Decision:       *decision,
				EffectiveDate:  *effectiveDate,
				ManagerID:      *managerID,
				Reference:      *reference,
				EvidenceHash:   *evidenceHash,
				ReasonCode:     *reasonCode,
				IdempotencyKey: *idempotencyKey,
			},
		)
		if err != nil {
			return fmt.Errorf("decide ownership transfer: %w", err)
		}
		return writeCLIJSON(stdout, result)
	})
}

func runCancelOwnershipTransfer(args []string, stdout io.Writer) error {
	return runOwnershipTransferStateChange(
		"cancel-ownership-transfer",
		true,
		args,
		stdout,
		func(
			ctx context.Context,
			registryService *service.Service,
			input service.OwnershipTransferStateChange,
		) (any, error) {
			return registryService.CancelOwnershipTransfer(ctx, input)
		},
	)
}

func runCompleteOwnershipTransfer(args []string, stdout io.Writer) error {
	return runOwnershipTransferStateChange(
		"complete-ownership-transfer",
		false,
		args,
		stdout,
		func(
			ctx context.Context,
			registryService *service.Service,
			input service.OwnershipTransferStateChange,
		) (any, error) {
			return registryService.CompleteOwnershipTransfer(ctx, input)
		},
	)
}

func runOwnershipTransferStateChange(
	command string,
	requireReason bool,
	args []string,
	stdout io.Writer,
	operation func(
		context.Context,
		*service.Service,
		service.OwnershipTransferStateChange,
	) (any, error),
) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stdout)
	transferID := flags.String("transfer-id", "", "exact ownership transfer ID")
	effectiveDate := flags.String(
		"effective-date",
		"",
		"UTC date in YYYY-MM-DD; completion must use today's UTC date",
	)
	managerID := flags.String(
		"manager-id",
		"",
		"bounded non-personal registry-manager identifier",
	)
	reference := flags.String(
		"reference",
		"",
		"bounded non-personal manager reference",
	)
	evidenceHash := flags.String(
		"evidence-hash",
		"",
		"optional sha256:<64 lowercase hex> evidence commitment",
	)
	reasonCode := flags.String(
		"reason-code",
		"",
		"required 3-64 lowercase token for cancel; empty for complete",
	)
	idempotencyKey := flags.String(
		"idempotency-key",
		"",
		"8-128 character printable ASCII retry key",
	)
	flags.Usage = func() {
		fmt.Fprintf(
			stdout,
			"Usage: /registry %s --transfer-id ID --effective-date YYYY-MM-DD --manager-id ID --reference REF [--evidence-hash SHA256]",
			command,
		)
		if requireReason {
			fmt.Fprint(stdout, " --reason-code TOKEN")
		}
		fmt.Fprintln(stdout, " --idempotency-key KEY")
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *transferID == "" ||
		*effectiveDate == "" ||
		*managerID == "" ||
		*reference == "" ||
		(requireReason && *reasonCode == "") ||
		*idempotencyKey == "" {
		flags.Usage()
		return fmt.Errorf(
			"%s requires every documented non-optional argument",
			command,
		)
	}
	input := service.OwnershipTransferStateChange{
		TransferID:     *transferID,
		EffectiveDate:  *effectiveDate,
		ManagerID:      *managerID,
		Reference:      *reference,
		EvidenceHash:   *evidenceHash,
		ReasonCode:     *reasonCode,
		IdempotencyKey: *idempotencyKey,
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		result, err := operation(ctx, registryService, input)
		if err != nil {
			return fmt.Errorf("%s: %w", command, err)
		}
		return writeCLIJSON(stdout, result)
	})
}

func runListOwnershipTransfers(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("list-ownership-transfers", flag.ContinueOnError)
	flags.SetOutput(stdout)
	status := flags.String(
		"status",
		"",
		"optional prepared, approved, rejected, cancelled, or completed",
	)
	limit := flags.Int("limit", 50, "number of transfer rows (1-200)")
	beforeEventIndex := flags.Int64(
		"before-event-index",
		0,
		"exclusive descending cursor copied from next_event_index",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry list-ownership-transfers [--status STATUS] [--limit N] [--before-event-index N]",
		)
		fmt.Fprintln(
			stdout,
			"Reads directly maintained append-only transfer state after cryptographic verification.",
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
		page, err := registryService.OwnershipTransfers(
			ctx,
			*status,
			*limit,
			*beforeEventIndex,
		)
		if err != nil {
			return fmt.Errorf("list ownership transfers: %w", err)
		}
		return writeCLIJSON(stdout, page)
	})
}

func runShowOwnershipTransfer(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("show-ownership-transfer", flag.ContinueOnError)
	flags.SetOutput(stdout)
	transferID := flags.String("transfer-id", "", "exact ownership transfer ID")
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry show-ownership-transfer --transfer-id ID",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *transferID == "" {
		flags.Usage()
		return errors.New("show-ownership-transfer requires --transfer-id")
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		transfer, err := registryService.OwnershipTransfer(ctx, *transferID)
		if err != nil {
			return fmt.Errorf("show ownership transfer: %w", err)
		}
		return writeCLIJSON(stdout, transfer)
	})
}
