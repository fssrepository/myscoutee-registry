package protocol

import "strconv"

const (
	OwnershipTransferRulesetVersion = "ownership-transfer-v1"

	OwnershipTransferStatusPrepared  = "prepared"
	OwnershipTransferStatusApproved  = "approved"
	OwnershipTransferStatusRejected  = "rejected"
	OwnershipTransferStatusCancelled = "cancelled"
	OwnershipTransferStatusCompleted = "completed"

	OwnershipTransferActionPrepare  = "prepare"
	OwnershipTransferActionApprove  = "approve"
	OwnershipTransferActionReject   = "reject"
	OwnershipTransferActionCancel   = "cancel"
	OwnershipTransferActionComplete = "complete"

	OwnershipTransferActorRequester = "requester"
	OwnershipTransferActorManager   = "registry-manager"

	OwnershipTransferZeroHash = ZeroHash
)

// OwnershipTransferRecord pins the immutable technical and legal-audit inputs
// to a transfer request. It contains commitments only; evidence bodies and
// payment instructions stay outside the registry.
type OwnershipTransferRecord struct {
	TransferID                 string `json:"transfer_id"`
	RulesetVersion             string `json:"ruleset_version"`
	ExitReviewID               string `json:"exit_review_id"`
	TargetDeploymentID         string `json:"target_deployment_id"`
	ClaimActionID              string `json:"claim_action_id"`
	SourceGroupID              string `json:"source_group_id"`
	TargetGroupID              string `json:"target_group_id"`
	LegalName                  string `json:"legal_name"`
	ExitRecordHash             string `json:"exit_record_hash"`
	ExitVerificationEventIndex int64  `json:"exit_verification_event_index"`
	ExitVerificationEventHash  string `json:"exit_verification_event_hash"`
	ExitEvidenceHash           string `json:"exit_evidence_hash"`
	PreparedAt                 string `json:"prepared_at"`
	RecordHash                 string `json:"record_hash"`
	RegistryScope              string `json:"registry_scope"`
	RegistryKeyID              string `json:"registry_key_id"`
}

type OwnershipTransferEvent struct {
	EventIndex                int64  `json:"event_index"`
	EventID                   string `json:"event_id"`
	TransferID                string `json:"transfer_id"`
	Action                    string `json:"action"`
	ResultingStatus           string `json:"resulting_status"`
	EffectiveDate             string `json:"effective_date"`
	ActorRole                 string `json:"actor_role"`
	ActorID                   string `json:"actor_id"`
	Reference                 string `json:"reference"`
	EvidenceHash              string `json:"evidence_hash"`
	ReasonCode                string `json:"reason_code,omitempty"`
	IdempotencyKey            string `json:"idempotency_key"`
	PayloadHash               string `json:"payload_hash"`
	RecordHash                string `json:"record_hash"`
	AcceptedAt                string `json:"accepted_at"`
	PreviousEventHash         string `json:"previous_event_hash"`
	PreviousTransferEventHash string `json:"previous_transfer_event_hash"`
	EventHash                 string `json:"event_hash"`
	RegistryScope             string `json:"registry_scope"`
	RegistryKeyID             string `json:"registry_key_id"`
	Signature                 string `json:"signature"`
}

type OwnershipTransferMembership struct {
	TransferID           string `json:"transfer_id"`
	CompletionEventIndex int64  `json:"completion_event_index"`
	CompletionEventHash  string `json:"completion_event_hash"`
	TargetDeploymentID   string `json:"target_deployment_id"`
	ClaimActionID        string `json:"claim_action_id"`
	SourceGroupID        string `json:"source_group_id"`
	TargetGroupID        string `json:"target_group_id"`
	EffectiveDate        string `json:"effective_date"`
	ThroughAuditIndex    int64  `json:"through_audit_index"`
	AuditHeadHash        string `json:"audit_head_hash"`
	CompletedAt          string `json:"completed_at"`
	MembershipHash       string `json:"membership_hash"`
}

type OwnershipTransfer struct {
	Record              OwnershipTransferRecord      `json:"record"`
	Status              string                       `json:"status"`
	LatestEventIndex    int64                        `json:"latest_event_index"`
	LatestEventHash     string                       `json:"latest_event_hash"`
	LatestAction        string                       `json:"latest_action"`
	LatestEffectiveDate string                       `json:"latest_effective_date"`
	LatestActorRole     string                       `json:"latest_actor_role"`
	LatestActorID       string                       `json:"latest_actor_id"`
	LatestReference     string                       `json:"latest_reference"`
	LatestEvidenceHash  string                       `json:"latest_evidence_hash"`
	LatestReasonCode    string                       `json:"latest_reason_code,omitempty"`
	LatestAcceptedAt    string                       `json:"latest_accepted_at"`
	Membership          *OwnershipTransferMembership `json:"membership,omitempty"`
	Events              []OwnershipTransferEvent     `json:"events,omitempty"`
}

type OwnershipTransferMutationResult struct {
	Duplicate bool                   `json:"duplicate"`
	Transfer  OwnershipTransfer      `json:"transfer"`
	Event     OwnershipTransferEvent `json:"event"`
}

type OwnershipTransferPage struct {
	Items          []OwnershipTransfer `json:"items"`
	NextEventIndex int64               `json:"next_event_index,omitempty"`
}

func OwnershipTransferRecordHashMessage(
	record OwnershipTransferRecord,
) []byte {
	return canonical(
		"myscoutee-registry-ownership-transfer-record-v1",
		record.TransferID,
		record.RulesetVersion,
		record.ExitReviewID,
		record.TargetDeploymentID,
		record.ClaimActionID,
		record.SourceGroupID,
		record.TargetGroupID,
		record.LegalName,
		record.ExitRecordHash,
		strconv.FormatInt(record.ExitVerificationEventIndex, 10),
		record.ExitVerificationEventHash,
		record.ExitEvidenceHash,
		record.PreparedAt,
		record.RegistryScope,
		record.RegistryKeyID,
	)
}

func OwnershipTransferEventPayloadMessage(
	event OwnershipTransferEvent,
) []byte {
	return canonical(
		"myscoutee-registry-ownership-transfer-event-payload-v1",
		event.TransferID,
		event.Action,
		event.ResultingStatus,
		event.EffectiveDate,
		event.ActorRole,
		event.ActorID,
		event.Reference,
		event.EvidenceHash,
		event.ReasonCode,
		event.RecordHash,
	)
}

func OwnershipTransferEventHashMessage(event OwnershipTransferEvent) []byte {
	return canonical(
		"myscoutee-registry-ownership-transfer-event-v1",
		strconv.FormatInt(event.EventIndex, 10),
		event.EventID,
		event.TransferID,
		event.Action,
		event.ResultingStatus,
		event.EffectiveDate,
		event.ActorRole,
		event.ActorID,
		event.Reference,
		event.EvidenceHash,
		event.ReasonCode,
		event.IdempotencyKey,
		event.PayloadHash,
		event.RecordHash,
		event.AcceptedAt,
		event.PreviousEventHash,
		event.PreviousTransferEventHash,
		event.RegistryScope,
		event.RegistryKeyID,
	)
}

func OwnershipTransferEventReceiptMessage(
	event OwnershipTransferEvent,
) []byte {
	return canonical(
		"myscoutee-registry-ownership-transfer-event-receipt-v1",
		event.EventHash,
		event.RegistryKeyID,
	)
}

func OwnershipTransferMembershipHashMessage(
	membership OwnershipTransferMembership,
) []byte {
	return canonical(
		"myscoutee-registry-ownership-transfer-membership-v1",
		membership.TransferID,
		strconv.FormatInt(membership.CompletionEventIndex, 10),
		membership.CompletionEventHash,
		membership.TargetDeploymentID,
		membership.ClaimActionID,
		membership.SourceGroupID,
		membership.TargetGroupID,
		membership.EffectiveDate,
		strconv.FormatInt(membership.ThroughAuditIndex, 10),
		membership.AuditHeadHash,
		membership.CompletedAt,
	)
}
