package protocol

import "strconv"

const (
	GlobalIdentityVOPRFKeyPath       = "/v1/global-identities/voprf-keys/current"
	GlobalIdentityEvaluatePath       = "/v1/global-identities/evaluate"
	GlobalIdentityLinkPath           = "/v1/global-identities/links"
	GlobalIdentityLinkActionPath     = "/v1/global-identities/link-actions"
	GlobalIdentityPresenceBatchPath  = "/v1/global-identities/presence-batches"
	GlobalIdentityDedupPathPrefix    = "/v1/global-identities/dedup/"

	GlobalIdentityVOPRFSuite = "P256-SHA256"
	GlobalIdentityVOPRFMode  = "VOPRF"

	GlobalIdentityConsentVersion = "global-dedup-consent-v1"
	GlobalIdentityRulesetVersion = "global-identity-dedup-v1"

	GlobalIdentityKeyActive  = "ACTIVE"
	GlobalIdentityKeyRetired = "RETIRED"

	GlobalIdentityActionLink       = "LINK"
	GlobalIdentityActionUnlink     = "UNLINK"
	GlobalIdentityActionCorrect    = "CORRECT"
	GlobalIdentityActionPresence   = "QUALIFIED_PRESENCE"
	GlobalIdentityActionSnapshot   = "PERIOD_SNAPSHOT"

	GlobalIdentityLinkActive   = "ACTIVE"
	GlobalIdentityLinkUnlinked = "UNLINKED"
)

// GlobalIdentityVOPRFKey contains public, registry-attested RFC 9497 key
// metadata. The corresponding seed/private scalar is a registry-host secret
// and is never stored in SQLite or returned by HTTP.
type GlobalIdentityVOPRFKey struct {
	ProtocolVersion   string `json:"protocol_version"`
	RegistryScope     string `json:"registry_scope"`
	KeyVersion        int64  `json:"key_version"`
	Suite             string `json:"suite"`
	Mode              string `json:"mode"`
	PublicKey         string `json:"public_key"`
	Status            string `json:"status"`
	ActivatedAt       string `json:"activated_at"`
	RegistryKeyID     string `json:"registry_key_id"`
	RegistryPublicKey string `json:"registry_public_key"`
	Signature         string `json:"signature"`
}

type GlobalIdentityEvaluationRequest struct {
	ProtocolVersion string `json:"protocol_version"`
	RegistryScope   string `json:"registry_scope"`
	DeploymentID    string `json:"deployment_id"`
	Timestamp       string `json:"timestamp"`
	Nonce           string `json:"nonce"`
	IdempotencyKey  string `json:"idempotency_key"`
	KeyVersion      int64  `json:"key_version"`
	Suite           string `json:"suite"`
	BlindedElement  string `json:"blinded_element"`
	PayloadHash     string `json:"payload_hash"`
	Signature       string `json:"signature"`
}

type GlobalIdentityEvaluationResponse struct {
	ProtocolVersion   string `json:"protocol_version"`
	RegistryScope     string `json:"registry_scope"`
	DeploymentID      string `json:"deployment_id"`
	KeyVersion        int64  `json:"key_version"`
	Suite             string `json:"suite"`
	PublicKey         string `json:"public_key"`
	EvaluatedElement  string `json:"evaluated_element"`
	Proof              string `json:"proof"`
	RequestHash        string `json:"request_hash"`
	ResponseHash       string `json:"response_hash"`
	EvaluatedAt        string `json:"evaluated_at"`
	RegistryKeyID      string `json:"registry_key_id"`
	RegistryPublicKey  string `json:"registry_public_key"`
	ReceiptSignature   string `json:"receipt_signature"`
	Duplicate          bool   `json:"duplicate"`
}

// GlobalIdentityLinkRequest accepts only an opaque commitment derived from an
// RFC 9497 VOPRF output. There is intentionally no field for email, phone,
// Firebase UID, provider subject, local profile ID, or a plain identifier hash.
type GlobalIdentityLinkRequest struct {
	ProtocolVersion           string `json:"protocol_version"`
	RegistryScope             string `json:"registry_scope"`
	DeploymentID              string `json:"deployment_id"`
	Timestamp                 string `json:"timestamp"`
	Nonce                     string `json:"nonce"`
	IdempotencyKey            string `json:"idempotency_key"`
	KeyVersion                int64  `json:"key_version"`
	Suite                     string `json:"suite"`
	NetworkIdentityCommitment string `json:"network_identity_commitment"`
	ConsentVersion            string `json:"consent_version"`
	ConsentEvidenceCommitment string `json:"consent_evidence_commitment"`
	VerifiedAt                string `json:"verified_at"`
	EffectivePeriod           string `json:"effective_period"`
	PayloadHash               string `json:"payload_hash"`
	Signature                 string `json:"signature"`
}

type GlobalIdentityLinkActionRequest struct {
	ProtocolVersion             string `json:"protocol_version"`
	RegistryScope               string `json:"registry_scope"`
	DeploymentID                string `json:"deployment_id"`
	Timestamp                   string `json:"timestamp"`
	Nonce                       string `json:"nonce"`
	IdempotencyKey              string `json:"idempotency_key"`
	Action                      string `json:"action"`
	LinkID                      string `json:"link_id"`
	ReplacementKeyVersion       int64  `json:"replacement_key_version,omitempty"`
	ReplacementSuite            string `json:"replacement_suite,omitempty"`
	ReplacementCommitment       string `json:"replacement_commitment,omitempty"`
	ConsentVersion              string `json:"consent_version,omitempty"`
	ConsentEvidenceCommitment   string `json:"consent_evidence_commitment,omitempty"`
	VerifiedAt                  string `json:"verified_at,omitempty"`
	EffectivePeriod             string `json:"effective_period"`
	ReasonCommitment            string `json:"reason_commitment"`
	PayloadHash                 string `json:"payload_hash"`
	Signature                   string `json:"signature"`
}

type GlobalIdentityLink struct {
	LinkID            string `json:"link_id"`
	DeploymentID      string `json:"deployment_id"`
	Status            string `json:"status"`
	KeyVersion        int64  `json:"key_version"`
	Suite             string `json:"suite"`
	ActiveFromPeriod  string `json:"active_from_period"`
	InactiveFromPeriod string `json:"inactive_from_period,omitempty"`
	ConsentVersion    string `json:"consent_version"`
	VerifiedAt        string `json:"verified_at"`
	LatestEventIndex  int64  `json:"latest_event_index"`
	LatestEventHash   string `json:"latest_event_hash"`
}

// GlobalIdentityEvent is the public privacy ledger view. Identity
// commitments, internal global IDs, and consent evidence commitments are
// deliberately absent; AggregateCommitment binds the separately governed
// direct rows without publishing their contents.
type GlobalIdentityEvent struct {
	EventIndex          int64  `json:"event_index"`
	EventID             string `json:"event_id"`
	Action              string `json:"action"`
	DeploymentID        string `json:"deployment_id,omitempty"`
	Period              string `json:"period"`
	AggregateCommitment string `json:"aggregate_commitment"`
	ReportedCount       int64  `json:"reported_count"`
	DeduplicatedCount   int64  `json:"deduplicated_count"`
	AcceptedAt          string `json:"accepted_at"`
	PreviousEventHash   string `json:"previous_event_hash"`
	EventHash           string `json:"event_hash"`
	RegistryScope       string `json:"registry_scope"`
	RegistryKeyID       string `json:"registry_key_id"`
	Signature           string `json:"signature"`
}

type GlobalIdentityMutationResponse struct {
	ProtocolVersion   string              `json:"protocol_version"`
	RegistryScope     string              `json:"registry_scope"`
	Link              GlobalIdentityLink  `json:"link"`
	Event             GlobalIdentityEvent `json:"event"`
	RegistryPublicKey string              `json:"registry_public_key"`
	Duplicate         bool                `json:"duplicate"`
}

// GlobalIdentityPresenceBatchRequest is the private, deployment-signed
// qualified-person input needed to deduplicate aggregate QMAU correctly.
// Commitments MUST be sorted bytewise and may repeat: repeated values represent
// multiple locally counted accounts that collapse to one network identity.
type GlobalIdentityPresenceBatchRequest struct {
	ProtocolVersion   string   `json:"protocol_version"`
	RegistryScope     string   `json:"registry_scope"`
	DeploymentID      string   `json:"deployment_id"`
	Timestamp         string   `json:"timestamp"`
	Nonce             string   `json:"nonce"`
	IdempotencyKey    string   `json:"idempotency_key"`
	Period            string   `json:"period"`
	Revision          int64    `json:"revision"`
	SupersedesBatchID string   `json:"supersedes_batch_id,omitempty"`
	ReportedQMAUCount int64    `json:"reported_qmau_count"`
	KeyVersion        int64    `json:"key_version"`
	Suite             string   `json:"suite"`
	Commitments       []string `json:"network_identity_commitments"`
	PayloadHash       string   `json:"payload_hash"`
	Signature         string   `json:"signature"`
}

type GlobalIdentityPresenceBatchResponse struct {
	ProtocolVersion  string                       `json:"protocol_version"`
	RegistryScope    string                       `json:"registry_scope"`
	BatchID          string                       `json:"batch_id"`
	DeploymentID     string                       `json:"deployment_id"`
	Period           string                       `json:"period"`
	Revision         int64                        `json:"revision"`
	LinkedCount      int64                        `json:"linked_count"`
	UnlinkedCount    int64                        `json:"unlinked_count"`
	Event            GlobalIdentityEvent          `json:"event"`
	Snapshot         GlobalIdentityDedupSnapshot  `json:"snapshot"`
	Duplicate        bool                         `json:"duplicate"`
}

type GlobalIdentityDedupSnapshot struct {
	ProtocolVersion             string `json:"protocol_version"`
	RegistryScope               string `json:"registry_scope"`
	Period                      string `json:"period"`
	Revision                    int64  `json:"revision"`
	ReportedQMAUCount           int64  `json:"reported_qmau_count"`
	LinkedObservationCount      int64  `json:"linked_observation_count"`
	GloballyUniqueLinkedCount   int64  `json:"globally_unique_linked_count"`
	UnlinkedQMAUCount           int64  `json:"unlinked_qmau_count"`
	DeduplicatedNetworkQMAU     int64  `json:"deduplicated_network_qmau"`
	DuplicateReduction          int64  `json:"duplicate_reduction"`
	CoveredDeploymentCount      int64  `json:"covered_deployment_count"`
	AggregateCommitment         string `json:"aggregate_commitment"`
	ThroughEventIndex           int64  `json:"through_event_index"`
	ThroughEventHash            string `json:"through_event_hash"`
	GeneratedAt                 string `json:"generated_at"`
}

func GlobalIdentityVOPRFKeyMessage(key GlobalIdentityVOPRFKey) []byte {
	return canonical(
		"myscoutee-registry-global-identity-voprf-key-v1",
		key.ProtocolVersion,
		key.RegistryScope,
		strconv.FormatInt(key.KeyVersion, 10),
		key.Suite,
		key.Mode,
		key.PublicKey,
		key.Status,
		key.ActivatedAt,
		key.RegistryKeyID,
	)
}

func GlobalIdentityEvaluationPayload(
	keyVersion int64,
	suite string,
	blindedElement string,
) []byte {
	return canonical(
		"myscoutee-registry-global-identity-evaluate-payload-v1",
		strconv.FormatInt(keyVersion, 10),
		suite,
		blindedElement,
	)
}

func GlobalIdentityEvaluationResult(
	keyVersion int64,
	suite string,
	publicKey string,
	evaluatedElement string,
	proof string,
) []byte {
	return canonical(
		"myscoutee-registry-global-identity-evaluation-result-v1",
		strconv.FormatInt(keyVersion, 10),
		suite,
		publicKey,
		evaluatedElement,
		proof,
	)
}

func GlobalIdentityEvaluationReceiptMessage(
	protocolVersion string,
	registryScope string,
	deploymentID string,
	keyVersion int64,
	suite string,
	requestHash string,
	responseHash string,
	evaluatedAt string,
	registryKeyID string,
) []byte {
	return canonical(
		"myscoutee-registry-global-identity-evaluation-receipt-v1",
		protocolVersion,
		registryScope,
		deploymentID,
		strconv.FormatInt(keyVersion, 10),
		suite,
		requestHash,
		responseHash,
		evaluatedAt,
		registryKeyID,
	)
}

func NetworkIdentityCommitmentMessage(
	keyVersion int64,
	suite string,
	voprfOutput string,
) []byte {
	return canonical(
		"myscoutee-network-identity-commitment-v1",
		strconv.FormatInt(keyVersion, 10),
		suite,
		voprfOutput,
	)
}

func GlobalIdentityLinkPayload(request GlobalIdentityLinkRequest) []byte {
	return canonical(
		"myscoutee-registry-global-identity-link-payload-v1",
		strconv.FormatInt(request.KeyVersion, 10),
		request.Suite,
		request.NetworkIdentityCommitment,
		request.ConsentVersion,
		request.ConsentEvidenceCommitment,
		request.VerifiedAt,
		request.EffectivePeriod,
	)
}

func GlobalIdentityLinkActionPayload(
	request GlobalIdentityLinkActionRequest,
) []byte {
	return canonical(
		"myscoutee-registry-global-identity-link-action-payload-v1",
		request.Action,
		request.LinkID,
		strconv.FormatInt(request.ReplacementKeyVersion, 10),
		request.ReplacementSuite,
		request.ReplacementCommitment,
		request.ConsentVersion,
		request.ConsentEvidenceCommitment,
		request.VerifiedAt,
		request.EffectivePeriod,
		request.ReasonCommitment,
	)
}

func GlobalIdentityPresenceBatchPayload(
	request GlobalIdentityPresenceBatchRequest,
) []byte {
	fields := []string{
		"myscoutee-registry-global-identity-presence-batch-v1",
		request.Period,
		strconv.FormatInt(request.Revision, 10),
		request.SupersedesBatchID,
		strconv.FormatInt(request.ReportedQMAUCount, 10),
		strconv.FormatInt(request.KeyVersion, 10),
		request.Suite,
		strconv.Itoa(len(request.Commitments)),
	}
	fields = append(fields, request.Commitments...)
	return canonical(fields...)
}

func GlobalIdentityPrivateEventCommitment(
	action string,
	deploymentID string,
	linkID string,
	keyVersion int64,
	networkIdentityCommitment string,
	consentEvidenceCommitment string,
	reasonCommitment string,
	period string,
	payloadHash string,
) []byte {
	return canonical(
		"myscoutee-registry-global-identity-private-event-v1",
		action,
		deploymentID,
		linkID,
		strconv.FormatInt(keyVersion, 10),
		networkIdentityCommitment,
		consentEvidenceCommitment,
		reasonCommitment,
		period,
		payloadHash,
	)
}

func GlobalIdentityEventHashMessage(event GlobalIdentityEvent) []byte {
	return canonical(
		"myscoutee-registry-global-identity-event-v1",
		strconv.FormatInt(event.EventIndex, 10),
		event.EventID,
		event.Action,
		event.DeploymentID,
		event.Period,
		event.AggregateCommitment,
		strconv.FormatInt(event.ReportedCount, 10),
		strconv.FormatInt(event.DeduplicatedCount, 10),
		event.AcceptedAt,
		event.PreviousEventHash,
		event.RegistryScope,
		event.RegistryKeyID,
	)
}

func GlobalIdentityEventReceiptMessage(event GlobalIdentityEvent) []byte {
	return canonical(
		"myscoutee-registry-global-identity-event-receipt-v1",
		event.EventHash,
		event.RegistryKeyID,
	)
}

func GlobalIdentitySnapshotCommitmentMessage(
	period string,
	revision int64,
	reportedQMAUCount int64,
	linkedObservationCount int64,
	globallyUniqueLinkedCount int64,
	unlinkedQMAUCount int64,
	deduplicatedNetworkQMAU int64,
	duplicateReduction int64,
	coveredDeploymentCount int64,
	throughEventIndex int64,
	privateEventHash string,
) []byte {
	return canonical(
		"myscoutee-registry-global-identity-snapshot-v1",
		period,
		strconv.FormatInt(revision, 10),
		strconv.FormatInt(reportedQMAUCount, 10),
		strconv.FormatInt(linkedObservationCount, 10),
		strconv.FormatInt(globallyUniqueLinkedCount, 10),
		strconv.FormatInt(unlinkedQMAUCount, 10),
		strconv.FormatInt(deduplicatedNetworkQMAU, 10),
		strconv.FormatInt(duplicateReduction, 10),
		strconv.FormatInt(coveredDeploymentCount, 10),
		strconv.FormatInt(throughEventIndex, 10),
		privateEventHash,
	)
}
