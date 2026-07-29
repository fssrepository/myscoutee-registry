package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/fssrepository/myscoutee-registry/internal/service"
)

func runRejectOperatorClaim(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("reject-operator-claim", flag.ContinueOnError)
	flags.SetOutput(stdout)
	deploymentID := flags.String(
		"deployment-id",
		"",
		"exact deployment ID from show",
	)
	claimActionID := flags.String(
		"claim-action-id",
		"",
		"exact current claim action ID from show",
	)
	groupID := flags.String(
		"group-id",
		"",
		"exact operator group ID from show",
	)
	legalName := flags.String(
		"legal-name",
		"",
		"exact legal name from show",
	)
	reviewerID := flags.String(
		"reviewer-id",
		"",
		"non-personal registry review-team identifier",
	)
	reviewReference := flags.String(
		"review-reference",
		"",
		"non-personal external case/reference token",
	)
	reasonCode := flags.String(
		"reason-code",
		"",
		"3-64 character lowercase reason token; never an evidence body",
	)
	idempotencyKey := flags.String(
		"idempotency-key",
		"",
		"8-128 character printable ASCII retry key",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry reject-operator-claim --deployment-id ID --claim-action-id ID --group-id ID --legal-name NAME --reviewer-id ID --review-reference REF --reason-code CODE --idempotency-key KEY",
		)
		fmt.Fprintln(
			stdout,
			"All claim identity fields must be copied from show-operator-claim; stale targets fail closed.",
		)
		fmt.Fprintln(
			stdout,
			"Reviewer/reference/reason fields must be non-personal identifiers only; do not enter names, email addresses, notes, or evidence bodies.",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *deploymentID == "" ||
		*claimActionID == "" ||
		*groupID == "" ||
		*legalName == "" ||
		*reviewerID == "" ||
		*reviewReference == "" ||
		*reasonCode == "" ||
		*idempotencyKey == "" {
		flags.Usage()
		return errors.New(
			"reject-operator-claim requires every documented argument",
		)
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		result, err := registryService.RejectOperatorClaim(
			ctx,
			service.OperatorClaimRejection{
				DeploymentID:    *deploymentID,
				ClaimActionID:   *claimActionID,
				GroupID:         *groupID,
				LegalName:       *legalName,
				ReviewerID:      *reviewerID,
				ReviewReference: *reviewReference,
				ReasonCode:      *reasonCode,
				IdempotencyKey:  *idempotencyKey,
			},
		)
		if err != nil {
			return fmt.Errorf("reject operator claim: %w", err)
		}
		return writeCLIJSON(stdout, result)
	})
}
