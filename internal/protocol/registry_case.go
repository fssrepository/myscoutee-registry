package protocol

import "strconv"

const (
	RegistryCaseActionFlag  = "flag"
	RegistryCaseActionClear = "clear"

	RegistryCaseStatusOpen    = "OPEN"
	RegistryCaseStatusCleared = "CLEARED"

	RegistryCaseSubjectDeployment = "deployment"
	RegistryCaseSubjectClaim      = "claim"
	RegistryCaseSubjectGroup      = "group"
	RegistryCaseSubjectQMAU       = "qmau"
	RegistryCaseSubjectRevenue    = "revenue"
	RegistryCaseSubjectLedger     = "ledger"

	RegistryCaseSeverityInfo     = "info"
	RegistryCaseSeverityWarning  = "warning"
	RegistryCaseSeverityCritical = "critical"

	RegistryCaseZeroHash = ZeroHash
)

// RegistryCaseEvent is an immutable registry-administrator action. It carries
// only bounded references and evidence digests; evidence bodies and personal
// review data must remain in the separately governed review system.
type RegistryCaseEvent struct {
	EventIndex        int64  `json:"event_index"`
	EventID           string `json:"event_id"`
	CaseID            string `json:"case_id"`
	Action            string `json:"action"`
	SubjectType       string `json:"subject_type"`
	SubjectID         string `json:"subject_id"`
	Category          string `json:"category"`
	Severity          string `json:"severity"`
	EvidenceHash      string `json:"evidence_hash"`
	Reference         string `json:"reference"`
	ActorID           string `json:"actor_id"`
	IdempotencyKey    string `json:"idempotency_key"`
	PayloadHash       string `json:"payload_hash"`
	AcceptedAt        string `json:"accepted_at"`
	PreviousEventHash string `json:"previous_event_hash"`
	EventHash         string `json:"event_hash"`
	RegistryScope     string `json:"registry_scope"`
	RegistryKeyID     string `json:"registry_key_id"`
	Signature         string `json:"signature"`
}

type RegistryCase struct {
	CaseID            string `json:"case_id"`
	Status            string `json:"status"`
	SubjectType       string `json:"subject_type"`
	SubjectID         string `json:"subject_id"`
	Category          string `json:"category"`
	Severity          string `json:"severity"`
	FlagEvidenceHash  string `json:"flag_evidence_hash"`
	FlagReference     string `json:"flag_reference"`
	FlagActorID       string `json:"flag_actor_id"`
	FlaggedAt         string `json:"flagged_at"`
	FlagEventIndex    int64  `json:"flag_event_index"`
	FlagEventHash     string `json:"flag_event_hash"`
	ClearEvidenceHash string `json:"clear_evidence_hash,omitempty"`
	ClearReference    string `json:"clear_reference,omitempty"`
	ClearActorID      string `json:"clear_actor_id,omitempty"`
	ClearedAt         string `json:"cleared_at,omitempty"`
	ClearEventIndex   int64  `json:"clear_event_index,omitempty"`
	ClearEventHash    string `json:"clear_event_hash,omitempty"`
	LatestEventIndex  int64  `json:"latest_event_index"`
	LatestEventHash   string `json:"latest_event_hash"`
}

type RegistryCaseMutationResult struct {
	Duplicate bool              `json:"duplicate"`
	Case      RegistryCase      `json:"case"`
	Event     RegistryCaseEvent `json:"event"`
}

type RegistryCasePage struct {
	Items          []RegistryCase `json:"items"`
	NextEventIndex int64          `json:"next_event_index,omitempty"`
}

func RegistryCasePayloadMessage(
	action string,
	caseID string,
	subjectType string,
	subjectID string,
	category string,
	severity string,
	evidenceHash string,
	reference string,
	actorID string,
) []byte {
	// A flag's case ID is registry-generated and therefore excluded from the
	// caller-intent digest so an exact idempotent retry can return the original
	// case. A clear targets an existing case and commits to that identifier.
	payloadCaseID := caseID
	if action == RegistryCaseActionFlag {
		payloadCaseID = ""
	}
	return canonical(
		"myscoutee-registry-case-payload-v1",
		action,
		payloadCaseID,
		subjectType,
		subjectID,
		category,
		severity,
		evidenceHash,
		reference,
		actorID,
	)
}

func RegistryCaseEventHashMessage(event RegistryCaseEvent) []byte {
	return canonical(
		"myscoutee-registry-case-event-v1",
		strconv.FormatInt(event.EventIndex, 10),
		event.EventID,
		event.CaseID,
		event.Action,
		event.SubjectType,
		event.SubjectID,
		event.Category,
		event.Severity,
		event.EvidenceHash,
		event.Reference,
		event.ActorID,
		event.IdempotencyKey,
		event.PayloadHash,
		event.AcceptedAt,
		event.PreviousEventHash,
		event.RegistryScope,
		event.RegistryKeyID,
	)
}

func RegistryCaseEventReceiptMessage(event RegistryCaseEvent) []byte {
	return canonical(
		"myscoutee-registry-case-event-receipt-v1",
		event.EventHash,
		event.RegistryKeyID,
	)
}
