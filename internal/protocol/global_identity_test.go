package protocol

import (
	"reflect"
	"strings"
	"testing"
)

func TestGlobalIdentityPresenceCanonicalPayloadIncludesKeyVersionAndOrder(
	t *testing.T,
) {
	t.Parallel()
	request := GlobalIdentityPresenceBatchRequest{
		SubmissionID:         "gipsub_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Period:               "2026-07",
		Revision:             3,
		SupersedesBatchID:    "batch_previous",
		ReportedQMAUCount:    8,
		KeyVersion:           2,
		Suite:                GlobalIdentityVOPRFSuite,
		ChunkIndex:           1,
		ChunkCount:           3,
		TotalCommitmentCount: 8,
		CommitmentSetHash:    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Commitments: []string{
			"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}
	want := "" +
		"myscoutee-registry-global-identity-presence-chunk-v2\n" +
		request.SubmissionID + "\n" +
		"2026-07\n" +
		"3\n" +
		"batch_previous\n" +
		"8\n" +
		"2\n" +
		"P256-SHA256\n" +
		"1\n" +
		"3\n" +
		"8\n" +
		request.CommitmentSetHash + "\n" +
		"2\n" +
		request.Commitments[0] + "\n" +
		request.Commitments[1] + "\n"
	if got := string(GlobalIdentityPresenceBatchPayload(request)); got != want {
		t.Fatalf("canonical presence payload mismatch:\nwant %q\n got %q", want, got)
	}
}

func TestGlobalIdentityPresenceSetCanonicalPayloadRetainsDuplicates(
	t *testing.T,
) {
	t.Parallel()
	commitments := []string{
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	want := "" +
		"myscoutee-registry-global-identity-presence-set-v1\n" +
		"3\n" +
		commitments[0] + "\n" +
		commitments[1] + "\n" +
		commitments[2] + "\n"
	if got := string(
		GlobalIdentityPresenceCommitmentSetMessage(commitments),
	); got != want {
		t.Fatalf(
			"canonical presence set mismatch:\nwant %q\n got %q",
			want,
			got,
		)
	}
}

func TestGlobalIdentityPresenceChunkReceiptCanonicalOrder(
	t *testing.T,
) {
	t.Parallel()
	response := GlobalIdentityPresenceBatchResponse{
		ProtocolVersion:      Version,
		RegistryScope:        "example:region-a",
		SubmissionID:         "gipsub_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		DeploymentID:         "dep_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Period:               "2026-07",
		Revision:             3,
		ChunkIndex:           1,
		ChunkCount:           3,
		ReceivedChunkCount:   2,
		TotalCommitmentCount: 8,
		CommitmentSetHash:    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Complete:             false,
		RequestHash:          "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		PayloadHash:          "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		AcceptedAt:           "2026-07-29T00:00:01Z",
		RegistryKeyID:        "rkey_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	want := "" +
		"myscoutee-registry-global-identity-presence-chunk-receipt-v2\n" +
		"1\n" +
		"example:region-a\n" +
		response.DeploymentID + "\n" +
		response.SubmissionID + "\n" +
		"2026-07\n" +
		"3\n" +
		"1\n" +
		"3\n" +
		"2\n" +
		"8\n" +
		response.CommitmentSetHash + "\n" +
		response.RequestHash + "\n" +
		response.PayloadHash + "\n" +
		response.AcceptedAt + "\n" +
		"false\n" +
		"\n" +
		"\n" +
		response.RegistryKeyID + "\n"
	if got := string(
		GlobalIdentityPresenceChunkReceiptMessage(response),
	); got != want {
		t.Fatalf(
			"canonical presence chunk receipt mismatch:\nwant %q\n got %q",
			want,
			got,
		)
	}
}

func TestGlobalIdentityPublicTypesContainNoDirectIdentifierOrCommitment(
	t *testing.T,
) {
	t.Parallel()
	publicTypes := []any{
		GlobalIdentityLink{},
		GlobalIdentityEvent{},
		GlobalIdentityMutationResponse{},
		GlobalIdentityDedupSnapshot{},
	}
	for _, value := range publicTypes {
		typ := reflect.TypeOf(value)
		for index := 0; index < typ.NumField(); index++ {
			tag := strings.Split(
				typ.Field(index).Tag.Get("json"),
				",",
			)[0]
			switch tag {
			case "email",
				"phone",
				"firebase_uid",
				"provider_subject",
				"local_profile_id",
				"global_identity_id",
				"network_identity_commitment",
				"consent_evidence_commitment":
				t.Fatalf(
					"private field %q leaked into public type %s",
					tag,
					typ.Name(),
				)
			}
		}
	}
}
