package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/fssrepository/myscoutee-registry/internal/service"
)

type operatorClaimEligibilityCLIFlags struct {
	deploymentID      *string
	claimActionID     *string
	groupID           *string
	legalName         *string
	actorID           *string
	decisionReference *string
	reasonCode        *string
	idempotencyKey    *string
}

func addOperatorClaimEligibilityFlags(
	flags *flag.FlagSet,
	withReason bool,
) operatorClaimEligibilityCLIFlags {
	values := operatorClaimEligibilityCLIFlags{
		deploymentID: flags.String(
			"deployment-id", "", "exact deployment ID from show",
		),
		claimActionID: flags.String(
			"claim-action-id", "", "exact current claim action ID from show",
		),
		groupID: flags.String(
			"group-id", "", "exact operator group ID from show",
		),
		legalName: flags.String(
			"legal-name", "", "exact legal name from show",
		),
		actorID: flags.String(
			"actor-id", "", "non-personal registry authority identifier",
		),
		decisionReference: flags.String(
			"decision-reference",
			"",
			"non-personal review/case reference",
		),
		idempotencyKey: flags.String(
			"idempotency-key",
			"",
			"8-128 character printable ASCII retry key",
		),
	}
	if withReason {
		values.reasonCode = flags.String(
			"reason-code",
			"",
			"3-64 character lowercase reason token; never notes or evidence",
		)
	}
	return values
}

func (values operatorClaimEligibilityCLIFlags) complete(
	withReason bool,
) bool {
	return *values.deploymentID != "" &&
		*values.claimActionID != "" &&
		*values.groupID != "" &&
		*values.legalName != "" &&
		*values.actorID != "" &&
		*values.decisionReference != "" &&
		*values.idempotencyKey != "" &&
		(!withReason || *values.reasonCode != "")
}

func writeOperatorClaimEligibilityUsage(
	stdout io.Writer,
	command string,
	withReason bool,
) {
	reason := ""
	if withReason {
		reason = " --reason-code CODE"
	}
	fmt.Fprintf(
		stdout,
		"Usage: /registry %s --deployment-id ID --claim-action-id ID --group-id ID --legal-name NAME --actor-id ID --decision-reference REF%s --idempotency-key KEY\n",
		command,
		reason,
	)
	fmt.Fprintln(
		stdout,
		"Copy every claim identity field from show-operator-claim; stale or non-approved targets fail closed.",
	)
	fmt.Fprintln(
		stdout,
		"Actor, reference, and reason are bounded non-personal identifiers; never enter names, email addresses, notes, or evidence bodies.",
	)
}

func runSuspendOperatorClaim(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("suspend-operator-claim", flag.ContinueOnError)
	flags.SetOutput(stdout)
	values := addOperatorClaimEligibilityFlags(flags, true)
	flags.Usage = func() {
		writeOperatorClaimEligibilityUsage(
			stdout,
			"suspend-operator-claim",
			true,
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if !values.complete(true) {
		flags.Usage()
		return errors.New(
			"suspend-operator-claim requires every documented argument",
		)
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		result, err := registryService.SuspendOperatorClaim(
			ctx,
			service.OperatorClaimSuspension{
				DeploymentID:      *values.deploymentID,
				ClaimActionID:     *values.claimActionID,
				GroupID:           *values.groupID,
				LegalName:         *values.legalName,
				ActorID:           *values.actorID,
				DecisionReference: *values.decisionReference,
				ReasonCode:        *values.reasonCode,
				IdempotencyKey:    *values.idempotencyKey,
			},
		)
		if err != nil {
			return fmt.Errorf("suspend operator claim: %w", err)
		}
		return writeCLIJSON(stdout, result)
	})
}

func runReinstateOperatorClaim(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("reinstate-operator-claim", flag.ContinueOnError)
	flags.SetOutput(stdout)
	values := addOperatorClaimEligibilityFlags(flags, false)
	flags.Usage = func() {
		writeOperatorClaimEligibilityUsage(
			stdout,
			"reinstate-operator-claim",
			false,
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if !values.complete(false) {
		flags.Usage()
		return errors.New(
			"reinstate-operator-claim requires every documented argument",
		)
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		result, err := registryService.ReinstateOperatorClaim(
			ctx,
			service.OperatorClaimReinstatement{
				DeploymentID:      *values.deploymentID,
				ClaimActionID:     *values.claimActionID,
				GroupID:           *values.groupID,
				LegalName:         *values.legalName,
				ActorID:           *values.actorID,
				DecisionReference: *values.decisionReference,
				IdempotencyKey:    *values.idempotencyKey,
			},
		)
		if err != nil {
			return fmt.Errorf("reinstate operator claim: %w", err)
		}
		return writeCLIJSON(stdout, result)
	})
}
