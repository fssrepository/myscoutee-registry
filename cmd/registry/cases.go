package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/fssrepository/myscoutee-registry/internal/service"
)

func runListRegistryCases(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("list-registry-cases", flag.ContinueOnError)
	flags.SetOutput(stdout)
	status := flags.String("status", "OPEN", "OPEN, CLEARED, or an empty value")
	limit := flags.Int("limit", 50, "number of case rows (1-200)")
	beforeEventIndex := flags.Int64(
		"before-event-index",
		0,
		"exclusive descending cursor copied from next_event_index",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry list-registry-cases [--status OPEN|CLEARED] [--limit N] [--before-event-index N]",
		)
		fmt.Fprintln(
			stdout,
			"Reads the directly maintained case table after verifying its signed append-only event chain.",
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
		page, err := registryService.RegistryCases(
			ctx,
			*status,
			*limit,
			*beforeEventIndex,
		)
		if err != nil {
			return fmt.Errorf("list registry cases: %w", err)
		}
		return writeCLIJSON(stdout, page)
	})
}

func runShowRegistryCase(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("show-registry-case", flag.ContinueOnError)
	flags.SetOutput(stdout)
	caseID := flags.String("case-id", "", "exact registry case ID")
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry show-registry-case --case-id CASE_ID",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *caseID == "" {
		flags.Usage()
		return errors.New("show-registry-case requires --case-id")
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		item, err := registryService.RegistryCase(ctx, *caseID)
		if err != nil {
			return fmt.Errorf("show registry case: %w", err)
		}
		return writeCLIJSON(stdout, item)
	})
}

func runFlagRegistryCase(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("flag-registry-case", flag.ContinueOnError)
	flags.SetOutput(stdout)
	subjectType := flags.String(
		"subject-type",
		"",
		"deployment, claim, group, qmau, revenue, or ledger",
	)
	subjectID := flags.String("subject-id", "", "exact typed subject identifier")
	category := flags.String(
		"category",
		"",
		"bounded lowercase anomaly category token",
	)
	severity := flags.String(
		"severity",
		"",
		"info, warning, or critical",
	)
	evidenceHash := flags.String(
		"evidence-hash",
		"",
		"optional sha256:<64 lowercase hex> evidence digest; evidence itself is never stored",
	)
	reference := flags.String(
		"reference",
		"",
		"non-personal external review/case reference",
	)
	actorID := flags.String(
		"actor-id",
		"",
		"bounded registry-admin audit actor identifier",
	)
	idempotencyKey := flags.String(
		"idempotency-key",
		"",
		"8-128 character printable ASCII retry key",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry flag-registry-case --subject-type TYPE --subject-id ID --category TOKEN --severity LEVEL [--evidence-hash SHA256] --reference REF --actor-id ID --idempotency-key KEY",
		)
		fmt.Fprintln(
			stdout,
			"This records an audit case only; it does not suspend a claim, alter measured history, or change share eligibility.",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *subjectType == "" ||
		*subjectID == "" ||
		*category == "" ||
		*severity == "" ||
		*reference == "" ||
		*actorID == "" ||
		*idempotencyKey == "" {
		flags.Usage()
		return errors.New("flag-registry-case requires every documented non-optional argument")
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		result, err := registryService.FlagRegistryCase(
			ctx,
			service.RegistryCaseFlag{
				SubjectType:    *subjectType,
				SubjectID:      *subjectID,
				Category:       *category,
				Severity:       *severity,
				EvidenceHash:   *evidenceHash,
				Reference:      *reference,
				ActorID:        *actorID,
				IdempotencyKey: *idempotencyKey,
			},
		)
		if err != nil {
			return fmt.Errorf("flag registry case: %w", err)
		}
		return writeCLIJSON(stdout, result)
	})
}

func runClearRegistryCase(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("clear-registry-case", flag.ContinueOnError)
	flags.SetOutput(stdout)
	caseID := flags.String("case-id", "", "exact open registry case ID")
	evidenceHash := flags.String(
		"evidence-hash",
		"",
		"optional sha256:<64 lowercase hex> resolution-evidence digest",
	)
	reference := flags.String(
		"reference",
		"",
		"non-personal external resolution reference",
	)
	actorID := flags.String(
		"actor-id",
		"",
		"bounded registry-admin audit actor identifier",
	)
	idempotencyKey := flags.String(
		"idempotency-key",
		"",
		"8-128 character printable ASCII retry key",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry clear-registry-case --case-id CASE_ID [--evidence-hash SHA256] --reference REF --actor-id ID --idempotency-key KEY",
		)
		fmt.Fprintln(
			stdout,
			"Clearing appends a signed event and preserves the original flag; it does not rewrite measured or claim history.",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *caseID == "" ||
		*reference == "" ||
		*actorID == "" ||
		*idempotencyKey == "" {
		flags.Usage()
		return errors.New("clear-registry-case requires every documented non-optional argument")
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		result, err := registryService.ClearRegistryCase(
			ctx,
			service.RegistryCaseClear{
				CaseID:         *caseID,
				EvidenceHash:   *evidenceHash,
				Reference:      *reference,
				ActorID:        *actorID,
				IdempotencyKey: *idempotencyKey,
			},
		)
		if err != nil {
			return fmt.Errorf("clear registry case: %w", err)
		}
		return writeCLIJSON(stdout, result)
	})
}
