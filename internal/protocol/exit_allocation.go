package protocol

import "strconv"

const (
	ExitAllocationRulesetVersion = "final-exit-allocation-v1"

	ExitAllocationDecisionCompletedTransfer = "completed-transfer"
	ExitAllocationDecisionNoTransfer        = "no-transfer"

	ExitAllocationBeneficiaryOperatorGroup = "OPERATOR_GROUP"
	ExitAllocationBeneficiaryContract      = "CONTRACT_BENEFICIARY"

	ExitAllocationStatusRecorded      = "recorded"
	ExitAllocationStatusVerifiedFinal = "verified-final"

	ExitAllocationActionCreate = "create"
	ExitAllocationActionVerify = "verify"

	ExitAllocationActorAllocator = "allocator"
	ExitAllocationActorVerifier  = "registry-verifier"

	ExitAllocationZeroHash = ZeroHash
)

// ExitAllocationSettlementSource copies one exact settlement revision from the
// frozen exit-review boundary and records only the exiting group's
// distributable network-pool amount. It is a technical allocation source, not
// a payment or invoice.
type ExitAllocationSettlementSource struct {
	BoundaryOrder             int64  `json:"boundary_order"`
	SettlementID              string `json:"settlement_id"`
	Period                    string `json:"period"`
	CurrencyCode              string `json:"currency_code"`
	FractionDigits            int64  `json:"fraction_digits"`
	Revision                  int64  `json:"revision"`
	LedgerIndex               int64  `json:"ledger_index"`
	SettlementHash            string `json:"settlement_hash"`
	SourceFingerprint         string `json:"source_fingerprint"`
	SettlementAllocationHash  string `json:"settlement_allocation_hash"`
	DistributableMinor        int64  `json:"distributable_minor"`
}

// ExitAllocationCurrency is the conserved per-currency result. V1 has exactly
// one beneficiary per allocation, so allocated_minor must equal
// distributable_minor independently for every currency.
type ExitAllocationCurrency struct {
	AllocationOrder  int64  `json:"allocation_order"`
	CurrencyCode     string `json:"currency_code"`
	FractionDigits   int64  `json:"fraction_digits"`
	DistributableMinor int64 `json:"distributable_minor"`
	AllocatedMinor   int64  `json:"allocated_minor"`
	BeneficiaryType  string `json:"beneficiary_type"`
	BeneficiaryID    string `json:"beneficiary_id"`
}

// ExitAllocationRecord is registry-local contractual evidence. It deliberately
// has no payment execution, bank-account, tax, or invoicing fields.
type ExitAllocationRecord struct {
	AllocationID                         string `json:"allocation_id"`
	RulesetVersion                       string `json:"ruleset_version"`
	ExitReviewID                         string `json:"exit_review_id"`
	TargetDeploymentID                   string `json:"target_deployment_id"`
	ClaimActionID                        string `json:"claim_action_id"`
	SourceGroupID                        string `json:"source_group_id"`
	ExitRecordHash                       string `json:"exit_record_hash"`
	ExitVerificationEventIndex           int64  `json:"exit_verification_event_index"`
	ExitVerificationEventHash            string `json:"exit_verification_event_hash"`
	ExitEvidenceHash                     string `json:"exit_evidence_hash"`
	DecisionMode                         string `json:"decision_mode"`
	OwnershipTransferID                  string `json:"ownership_transfer_id,omitempty"`
	OwnershipTransferCompletionEventIndex int64 `json:"ownership_transfer_completion_event_index"`
	OwnershipTransferCompletionEventHash string `json:"ownership_transfer_completion_event_hash"`
	ThroughOwnershipTransferEventIndex   int64  `json:"through_ownership_transfer_event_index"`
	OwnershipTransferHeadHash            string `json:"ownership_transfer_head_hash"`
	BeneficiaryType                      string `json:"beneficiary_type"`
	BeneficiaryID                        string `json:"beneficiary_id"`
	ContractReference                    string `json:"contract_reference"`
	ContractTermsHash                    string `json:"contract_terms_hash"`
	EvidenceHash                         string `json:"evidence_hash"`
	SettlementSourceCount                int64  `json:"settlement_source_count"`
	SettlementSourceHash                 string `json:"settlement_source_hash"`
	CurrencyAllocationCount              int64  `json:"currency_allocation_count"`
	CurrencyAllocationHash               string `json:"currency_allocation_hash"`
	CreatedAt                            string `json:"created_at"`
	RecordHash                           string `json:"record_hash"`
	RegistryScope                        string `json:"registry_scope"`
	RegistryKeyID                        string `json:"registry_key_id"`
	SettlementSources                    []ExitAllocationSettlementSource `json:"settlement_sources"`
	CurrencyAllocations                  []ExitAllocationCurrency `json:"currency_allocations"`
}

type ExitAllocationEvent struct {
	EventIndex                  int64  `json:"event_index"`
	EventID                     string `json:"event_id"`
	AllocationID                string `json:"allocation_id"`
	Action                      string `json:"action"`
	ResultingStatus             string `json:"resulting_status"`
	ActorRole                   string `json:"actor_role"`
	ActorID                     string `json:"actor_id"`
	Reference                   string `json:"reference"`
	EvidenceHash                string `json:"evidence_hash"`
	IdempotencyKey              string `json:"idempotency_key"`
	PayloadHash                 string `json:"payload_hash"`
	RecordHash                  string `json:"record_hash"`
	AcceptedAt                  string `json:"accepted_at"`
	PreviousEventHash           string `json:"previous_event_hash"`
	PreviousAllocationEventHash string `json:"previous_allocation_event_hash"`
	EventHash                   string `json:"event_hash"`
	RegistryScope               string `json:"registry_scope"`
	RegistryKeyID               string `json:"registry_key_id"`
	Signature                   string `json:"signature"`
}

type ExitAllocation struct {
	Record             ExitAllocationRecord `json:"record"`
	Status             string               `json:"status"`
	LatestEventIndex   int64                `json:"latest_event_index"`
	LatestEventHash    string               `json:"latest_event_hash"`
	LatestAction       string               `json:"latest_action"`
	LatestActorRole    string               `json:"latest_actor_role"`
	LatestActorID      string               `json:"latest_actor_id"`
	LatestReference    string               `json:"latest_reference"`
	LatestEvidenceHash string               `json:"latest_evidence_hash"`
	LatestAcceptedAt   string               `json:"latest_accepted_at"`
	Events             []ExitAllocationEvent `json:"events,omitempty"`
}

type ExitAllocationMutationResult struct {
	Duplicate  bool                `json:"duplicate"`
	Allocation ExitAllocation      `json:"allocation"`
	Event      ExitAllocationEvent `json:"event"`
}

type ExitAllocationPage struct {
	Items          []ExitAllocation `json:"items"`
	NextEventIndex int64            `json:"next_event_index,omitempty"`
}

func ExitAllocationSettlementSourceHash(
	sources []ExitAllocationSettlementSource,
) string {
	lines := []string{
		"myscoutee-registry-exit-allocation-settlement-sources-v1",
		strconv.Itoa(len(sources)),
	}
	for _, source := range sources {
		lines = append(
			lines,
			strconv.FormatInt(source.BoundaryOrder, 10),
			source.SettlementID,
			source.Period,
			source.CurrencyCode,
			strconv.FormatInt(source.FractionDigits, 10),
			strconv.FormatInt(source.Revision, 10),
			strconv.FormatInt(source.LedgerIndex, 10),
			source.SettlementHash,
			source.SourceFingerprint,
			source.SettlementAllocationHash,
			strconv.FormatInt(source.DistributableMinor, 10),
		)
	}
	return Digest(canonical(lines...))
}

func ExitAllocationCurrencyHash(
	allocations []ExitAllocationCurrency,
) string {
	lines := []string{
		"myscoutee-registry-exit-allocation-currencies-v1",
		strconv.Itoa(len(allocations)),
	}
	for _, allocation := range allocations {
		lines = append(
			lines,
			strconv.FormatInt(allocation.AllocationOrder, 10),
			allocation.CurrencyCode,
			strconv.FormatInt(allocation.FractionDigits, 10),
			strconv.FormatInt(allocation.DistributableMinor, 10),
			strconv.FormatInt(allocation.AllocatedMinor, 10),
			allocation.BeneficiaryType,
			allocation.BeneficiaryID,
		)
	}
	return Digest(canonical(lines...))
}

func ExitAllocationRecordHashMessage(record ExitAllocationRecord) []byte {
	return canonical(
		"myscoutee-registry-exit-allocation-record-v1",
		record.AllocationID,
		record.RulesetVersion,
		record.ExitReviewID,
		record.TargetDeploymentID,
		record.ClaimActionID,
		record.SourceGroupID,
		record.ExitRecordHash,
		strconv.FormatInt(record.ExitVerificationEventIndex, 10),
		record.ExitVerificationEventHash,
		record.ExitEvidenceHash,
		record.DecisionMode,
		record.OwnershipTransferID,
		strconv.FormatInt(
			record.OwnershipTransferCompletionEventIndex,
			10,
		),
		record.OwnershipTransferCompletionEventHash,
		strconv.FormatInt(record.ThroughOwnershipTransferEventIndex, 10),
		record.OwnershipTransferHeadHash,
		record.BeneficiaryType,
		record.BeneficiaryID,
		record.ContractReference,
		record.ContractTermsHash,
		record.EvidenceHash,
		strconv.FormatInt(record.SettlementSourceCount, 10),
		record.SettlementSourceHash,
		strconv.FormatInt(record.CurrencyAllocationCount, 10),
		record.CurrencyAllocationHash,
		record.CreatedAt,
		record.RegistryScope,
		record.RegistryKeyID,
	)
}

func ExitAllocationEventPayloadMessage(event ExitAllocationEvent) []byte {
	return canonical(
		"myscoutee-registry-exit-allocation-event-payload-v1",
		event.AllocationID,
		event.Action,
		event.ResultingStatus,
		event.ActorRole,
		event.ActorID,
		event.Reference,
		event.EvidenceHash,
		event.RecordHash,
	)
}

func ExitAllocationEventHashMessage(event ExitAllocationEvent) []byte {
	return canonical(
		"myscoutee-registry-exit-allocation-event-v1",
		strconv.FormatInt(event.EventIndex, 10),
		event.EventID,
		event.AllocationID,
		event.Action,
		event.ResultingStatus,
		event.ActorRole,
		event.ActorID,
		event.Reference,
		event.EvidenceHash,
		event.IdempotencyKey,
		event.PayloadHash,
		event.RecordHash,
		event.AcceptedAt,
		event.PreviousEventHash,
		event.PreviousAllocationEventHash,
		event.RegistryScope,
		event.RegistryKeyID,
	)
}

func ExitAllocationEventReceiptMessage(event ExitAllocationEvent) []byte {
	return canonical(
		"myscoutee-registry-exit-allocation-event-receipt-v1",
		event.EventHash,
		event.RegistryKeyID,
	)
}
