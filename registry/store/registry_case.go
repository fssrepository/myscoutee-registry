package store

import "context"

type RegistryCaseEventInput struct {
	Action           string
	CaseID           string
	SubjectType      string
	SubjectID        string
	Category         string
	Severity         string
	EvidenceHash     string
	Reference        string
	ActorID          string
	IdempotencyKey   string
	PayloadHash      string
	CandidateEventID string
	AcceptedAt       string
	RegistryScope    string
	RegistryKeyID    string
}

type RegistryCaseEvent struct {
	EventIndex        int64
	EventID           string
	CaseID            string
	Action            string
	SubjectType       string
	SubjectID         string
	Category          string
	Severity          string
	EvidenceHash      string
	Reference         string
	ActorID           string
	IdempotencyKey    string
	PayloadHash       string
	AcceptedAt        string
	PreviousEventHash string
	EventHash         string
	RegistryScope     string
	RegistryKeyID     string
	Signature         []byte
}

type RegistryCase struct {
	CaseID            string
	Status            string
	SubjectType       string
	SubjectID         string
	Category          string
	Severity          string
	FlagEvidenceHash  string
	FlagReference     string
	FlagActorID       string
	FlaggedAt         string
	FlagEventIndex    int64
	FlagEventHash     string
	ClearEvidenceHash string
	ClearReference    string
	ClearActorID      string
	ClearedAt         string
	ClearEventIndex   int64
	ClearEventHash    string
	LatestEventIndex  int64
	LatestEventHash   string
}

type RegistryCaseQuery struct {
	Status           string
	Limit            int
	BeforeEventIndex int64
}

type RegistryCasePage struct {
	Items          []RegistryCase
	NextEventIndex int64
}

type RegistryCaseEventSigner func(RegistryCaseEvent) ([]byte, error)

type RegistryCaseStore interface {
	AppendRegistryCaseEvent(
		context.Context,
		RegistryCaseEventInput,
		RegistryCaseEventSigner,
	) (RegistryCaseEvent, RegistryCase, bool, error)
	RegistryCase(context.Context, string) (RegistryCase, error)
	RegistryCases(context.Context, RegistryCaseQuery) (RegistryCasePage, error)
	VerifyRegistryCases(context.Context, []byte, string, string) error
}
