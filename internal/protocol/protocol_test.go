package protocol

import "testing"

func TestCanonicalMessagesUseExactFieldsAndFinalLF(t *testing.T) {
	t.Parallel()

	request := string(CanonicalRequest(
		"post",
		RegistrationPath,
		"1",
		"example:region-a",
		"sha256:abc",
		"2026-07-28T00:00:00Z",
		"nonce_12345678",
		"registration_12345678",
		"sha256:def",
	))
	expectedRequest := "" +
		"myscoutee-registry-request-v1\n" +
		"POST\n" +
		"/v1/deployments/register\n" +
		"1\n" +
		"example:region-a\n" +
		"sha256:abc\n" +
		"2026-07-28T00:00:00Z\n" +
		"nonce_12345678\n" +
		"registration_12345678\n" +
		"sha256:def\n"
	if request != expectedRequest {
		t.Fatalf("canonical request mismatch:\nwant %q\n got %q", expectedRequest, request)
	}

	identity := string(RegistryIdentityMessage(
		"1",
		"example:region-a",
		"rkey_0123456789abcdef0123456789abcdef",
		"MCowBQYDK2VwAyEA...",
	))
	expectedIdentity := "" +
		"myscoutee-registry-identity-v1\n" +
		"1\n" +
		"example:region-a\n" +
		"rkey_0123456789abcdef0123456789abcdef\n" +
		"MCowBQYDK2VwAyEA...\n"
	if identity != expectedIdentity {
		t.Fatalf("canonical registry identity mismatch:\nwant %q\n got %q", expectedIdentity, identity)
	}

	entry := LedgerEntry{
		ProtocolVersion:   "1",
		RegistryScope:     "example:region-a",
		LedgerIndex:       7,
		EntryType:         InstallationEntryType,
		DeploymentID:      "dep_1",
		BatchID:           "batch_1",
		Kind:              InstallationTestKind,
		Period:            "2026-07",
		RulesetVersion:    InstallationTestRuleset,
		QualifiedMAUCount: 0,
		BatchHash:         "sha256:batch",
		PreviousEntryHash: "sha256:previous",
		AcceptedAt:        "2026-07-28T00:00:02Z",
	}
	expectedLedger := "" +
		"myscoutee-registry-ledger-entry-v1\n" +
		"1\n" +
		"example:region-a\n" +
		"7\n" +
		"INSTALLATION_TEST_BATCH_ACCEPTED\n" +
		"dep_1\n" +
		"batch_1\n" +
		"installation-test\n" +
		"2026-07\n" +
		"installation-test-v1\n" +
		"0\n" +
		"sha256:batch\n" +
		"sha256:previous\n" +
		"2026-07-28T00:00:02Z\n"
	if actual := string(LedgerEntryMessage(entry)); actual != expectedLedger {
		t.Fatalf("canonical ledger entry mismatch:\nwant %q\n got %q", expectedLedger, actual)
	}
}

func TestDigestAndCanonicalBase64Validation(t *testing.T) {
	t.Parallel()

	if got := Digest([]byte("abc")); got != "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("unexpected SHA-256 digest: %s", got)
	}
	if !IsDigest(ZeroHash) {
		t.Fatalf("zero hash must be a valid protocol digest")
	}
	if IsDigest("sha256:ABC") || IsDigest("sha256:1234") {
		t.Fatalf("non-canonical digests must be rejected")
	}
	if _, err := ParseSignature("AA"); err == nil {
		t.Fatalf("unpadded or wrong-size signatures must be rejected")
	}
}
