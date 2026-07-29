package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/fssrepository/myscoutee-registry/internal/service"
)

func runFreezeExitReview(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("freeze-exit-review", flag.ContinueOnError)
	flags.SetOutput(stdout)
	recordDate := flags.String(
		"record-date",
		"",
		"completed UTC checkpoint date in YYYY-MM-DD",
	)
	deploymentID := flags.String(
		"deployment-id",
		"",
		"exact target deployment ID",
	)
	claimActionID := flags.String(
		"claim-action-id",
		"",
		"exact approved claim generation",
	)
	groupID := flags.String("group-id", "", "exact operator group ID")
	actorRole := flags.String("actor-role", "", "buyer or auditor")
	actorID := flags.String(
		"actor-id",
		"",
		"bounded non-personal buyer/auditor identifier",
	)
	reference := flags.String(
		"reference",
		"",
		"bounded non-personal external audit reference",
	)
	evidenceHash := flags.String(
		"evidence-hash",
		"",
		"optional sha256:<64 lowercase hex> evidence commitment",
	)
	idempotencyKey := flags.String(
		"idempotency-key",
		"",
		"8-128 character printable ASCII retry key",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry freeze-exit-review --record-date YYYY-MM-DD --deployment-id ID --claim-action-id ID --group-id ID --actor-role buyer|auditor --actor-id ID --reference REF [--evidence-hash SHA256] --idempotency-key KEY",
		)
		fmt.Fprintln(
			stdout,
			"Freezes checkpoint, Merkle, operator-review, exact group membership, and latest settlement boundaries. It does not transfer ownership or pay funds.",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *recordDate == "" ||
		*deploymentID == "" ||
		*claimActionID == "" ||
		*groupID == "" ||
		*actorRole == "" ||
		*actorID == "" ||
		*reference == "" ||
		*idempotencyKey == "" {
		flags.Usage()
		return errors.New("freeze-exit-review requires every documented non-optional argument")
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		result, err := registryService.FreezeExitReview(
			ctx,
			service.ExitReviewFreeze{
				RecordDate:         *recordDate,
				TargetDeploymentID: *deploymentID,
				ClaimActionID:      *claimActionID,
				GroupID:            *groupID,
				ActorRole:          *actorRole,
				ActorID:            *actorID,
				Reference:          *reference,
				EvidenceHash:       *evidenceHash,
				IdempotencyKey:     *idempotencyKey,
			},
		)
		if err != nil {
			return fmt.Errorf("freeze exit review: %w", err)
		}
		return writeCLIJSON(stdout, result)
	})
}

func runDecideExitReview(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("decide-exit-review", flag.ContinueOnError)
	flags.SetOutput(stdout)
	reviewID := flags.String("review-id", "", "exact frozen exit review ID")
	decision := flags.String("decision", "", "verify or reject")
	effectiveDate := flags.String(
		"effective-date",
		"",
		"non-future UTC effective date in YYYY-MM-DD",
	)
	actorRole := flags.String("actor-role", "", "buyer or auditor")
	actorID := flags.String("actor-id", "", "bounded non-personal actor identifier")
	reference := flags.String("reference", "", "bounded non-personal decision reference")
	evidenceHash := flags.String(
		"evidence-hash",
		"",
		"optional sha256:<64 lowercase hex> evidence commitment",
	)
	reasonCode := flags.String(
		"reason-code",
		"",
		"required lowercase reason token for reject; empty for verify",
	)
	idempotencyKey := flags.String(
		"idempotency-key",
		"",
		"8-128 character printable ASCII retry key",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry decide-exit-review --review-id ID --decision verify|reject --effective-date YYYY-MM-DD --actor-role buyer|auditor --actor-id ID --reference REF [--evidence-hash SHA256] [--reason-code TOKEN] --idempotency-key KEY",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *reviewID == "" ||
		*decision == "" ||
		*effectiveDate == "" ||
		*actorRole == "" ||
		*actorID == "" ||
		*reference == "" ||
		*idempotencyKey == "" {
		flags.Usage()
		return errors.New("decide-exit-review requires every documented non-optional argument")
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		result, err := registryService.DecideExitReview(
			ctx,
			service.ExitReviewDecision{
				ReviewID:       *reviewID,
				Decision:       *decision,
				EffectiveDate:  *effectiveDate,
				ActorRole:      *actorRole,
				ActorID:        *actorID,
				Reference:      *reference,
				EvidenceHash:   *evidenceHash,
				ReasonCode:     *reasonCode,
				IdempotencyKey: *idempotencyKey,
			},
		)
		if err != nil {
			return fmt.Errorf("decide exit review: %w", err)
		}
		return writeCLIJSON(stdout, result)
	})
}

func runDisputeExitReview(args []string, stdout io.Writer) error {
	return runExitReviewStateChange(
		"dispute-exit-review",
		args,
		stdout,
		func(
			ctx context.Context,
			registryService *service.Service,
			input service.ExitReviewStateChange,
		) (any, error) {
			return registryService.DisputeExitReview(ctx, input)
		},
	)
}

func runWithdrawExitReview(args []string, stdout io.Writer) error {
	return runExitReviewStateChange(
		"withdraw-exit-review",
		args,
		stdout,
		func(
			ctx context.Context,
			registryService *service.Service,
			input service.ExitReviewStateChange,
		) (any, error) {
			return registryService.WithdrawExitReview(ctx, input)
		},
	)
}

func runExitReviewStateChange(
	command string,
	args []string,
	stdout io.Writer,
	operation func(
		context.Context,
		*service.Service,
		service.ExitReviewStateChange,
	) (any, error),
) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stdout)
	reviewID := flags.String("review-id", "", "exact frozen exit review ID")
	effectiveDate := flags.String("effective-date", "", "UTC date in YYYY-MM-DD")
	actorRole := flags.String("actor-role", "", "buyer or auditor")
	actorID := flags.String("actor-id", "", "bounded non-personal actor identifier")
	reference := flags.String("reference", "", "bounded non-personal review reference")
	evidenceHash := flags.String(
		"evidence-hash",
		"",
		"optional sha256:<64 lowercase hex> evidence commitment",
	)
	reasonCode := flags.String(
		"reason-code",
		"",
		"required 3-64 character lowercase reason token",
	)
	idempotencyKey := flags.String(
		"idempotency-key",
		"",
		"8-128 character printable ASCII retry key",
	)
	flags.Usage = func() {
		fmt.Fprintf(
			stdout,
			"Usage: /registry %s --review-id ID --effective-date YYYY-MM-DD --actor-role buyer|auditor --actor-id ID --reference REF [--evidence-hash SHA256] --reason-code TOKEN --idempotency-key KEY\n",
			command,
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *reviewID == "" ||
		*effectiveDate == "" ||
		*actorRole == "" ||
		*actorID == "" ||
		*reference == "" ||
		*reasonCode == "" ||
		*idempotencyKey == "" {
		flags.Usage()
		return fmt.Errorf("%s requires every documented non-optional argument", command)
	}
	input := service.ExitReviewStateChange{
		ReviewID:       *reviewID,
		EffectiveDate:  *effectiveDate,
		ActorRole:      *actorRole,
		ActorID:        *actorID,
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

func runListExitReviews(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("list-exit-reviews", flag.ContinueOnError)
	flags.SetOutput(stdout)
	status := flags.String(
		"status",
		"",
		"optional review-pending, verified-eligible, rejected, disputed, or withdrawn",
	)
	limit := flags.Int("limit", 50, "number of review rows (1-200)")
	beforeEventIndex := flags.Int64(
		"before-event-index",
		0,
		"exclusive descending cursor copied from next_event_index",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry list-exit-reviews [--status STATUS] [--limit N] [--before-event-index N]",
		)
		fmt.Fprintln(
			stdout,
			"Reads directly maintained append-only query rows after cryptographic verification.",
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
		page, err := registryService.ExitReviews(
			ctx,
			*status,
			*limit,
			*beforeEventIndex,
		)
		if err != nil {
			return fmt.Errorf("list exit reviews: %w", err)
		}
		return writeCLIJSON(stdout, page)
	})
}

func runShowExitReview(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("show-exit-review", flag.ContinueOnError)
	flags.SetOutput(stdout)
	reviewID := flags.String("review-id", "", "exact frozen exit review ID")
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry show-exit-review --review-id ID",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *reviewID == "" {
		flags.Usage()
		return errors.New("show-exit-review requires --review-id")
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		review, err := registryService.ExitReview(ctx, *reviewID)
		if err != nil {
			return fmt.Errorf("show exit review: %w", err)
		}
		return writeCLIJSON(stdout, review)
	})
}
