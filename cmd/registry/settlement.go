package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/fssrepository/myscoutee-registry/internal/service"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func runCalculateSettlement(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("calculate-settlement", flag.ContinueOnError)
	flags.SetOutput(stdout)
	period := flags.String(
		"period",
		"",
		"completed UTC settlement month in YYYY-MM form",
	)
	currency := flags.String(
		"currency",
		"",
		"one supported uppercase ISO-4217 settlement currency",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry calculate-settlement --period YYYY-MM --currency CODE",
		)
		fmt.Fprintln(
			stdout,
			"Appends one signed share-weighted settlement revision only when its pinned revenue/claim/eligibility source fingerprint changed.",
		)
		fmt.Fprintln(
			stdout,
			"The monthly distributable amount is 5% of accepted commission-basis revenue. The separately labelled non-binding indicative value uses TTM commission-basis revenue and the bounded three-month acceleration valuation rule.",
		)
		flags.PrintDefaults()
	}
	help, err := parseCLIFlags(flags, args)
	if err != nil || help {
		return err
	}
	if *period == "" || *currency == "" {
		flags.Usage()
		return errors.New(
			"calculate-settlement requires --period and --currency",
		)
	}
	return withRegistryService(func(
		ctx context.Context,
		registryService *service.Service,
	) error {
		result, err := registryService.CalculateSettlement(
			ctx,
			*period,
			*currency,
		)
		if err != nil {
			return fmt.Errorf("calculate settlement: %w", err)
		}
		if err := registryService.VerifyState(ctx); err != nil {
			return fmt.Errorf("verify registry after settlement: %w", err)
		}
		return writeCLIJSON(stdout, result)
	})
}

func runSettlements(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("settlements", flag.ContinueOnError)
	flags.SetOutput(stdout)
	period := flags.String("period", "", "optional exact YYYY-MM period")
	currency := flags.String(
		"currency",
		"",
		"optional uppercase ISO-4217 currency",
	)
	deploymentID := flags.String(
		"deployment-id",
		"",
		"optional deployment whose historical operator-group allocation is returned",
	)
	includeSuperseded := flags.Bool(
		"include-superseded",
		false,
		"include immutable older revisions",
	)
	limit := flags.Int("limit", 20, "number of settlement records (1-100)")
	afterPeriod := flags.String(
		"after-period",
		"",
		"exclusive period cursor copied from next_after_period",
	)
	afterSettlementID := flags.String(
		"after-settlement-id",
		"",
		"exclusive ID cursor copied from next_after_settlement_id",
	)
	flags.Usage = func() {
		fmt.Fprintln(
			stdout,
			"Usage: /registry settlements [--period YYYY-MM] [--currency CODE] [--deployment-id ID] [--include-superseded] [--limit N] [--after-period YYYY-MM --after-settlement-id ID]",
		)
		fmt.Fprintln(
			stdout,
			"Without --deployment-id, outputs every beneficiary allocation for each selected settlement. This local command can expose private financial allocations; do not publish its output.",
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
		page, err := registryService.SettlementHistoryForAdmin(
			ctx,
			store.SettlementHistoryQuery{
				DeploymentID:      *deploymentID,
				Period:            *period,
				CurrencyCode:      *currency,
				IncludeSuperseded: *includeSuperseded,
				Limit:             *limit,
				AfterPeriod:       *afterPeriod,
				AfterSettlementID: *afterSettlementID,
			},
		)
		if err != nil {
			return fmt.Errorf("query settlements: %w", err)
		}
		return writeCLIJSON(stdout, page)
	})
}
