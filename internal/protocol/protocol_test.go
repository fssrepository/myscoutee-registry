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

func TestCanonicalRevenuePayloadAndReceiptCommitExactOrderedFields(
	t *testing.T,
) {
	t.Parallel()
	currencies := []RevenueCurrency{
		{
			CurrencyCode:             "EUR",
			FractionDigits:           2,
			CapturedMinor:            12_345,
			RefundedMinor:            345,
			NetMinor:                 12_000,
			CommissionBasisMinor:     12_000,
			EstimatedCommissionMinor: 600,
			PaymentCount:             4,
		},
		{
			CurrencyCode:             "JPY",
			FractionDigits:           0,
			CapturedMinor:            20_000,
			RefundedMinor:            0,
			NetMinor:                 20_000,
			CommissionBasisMinor:     20_000,
			EstimatedCommissionMinor: 1_000,
			PaymentCount:             2,
		},
	}
	payload := string(RevenuePayload(
		RevenueKind,
		"2026-07-27",
		2,
		"revbatch_00000000000000000000000000000001",
		RevenueRulesetVersion,
		RevenueCommissionBasisPoints,
		currencies,
	))
	wantPayload := "" +
		"myscoutee-registry-revenue-batch-payload-v1\n" +
		"daily-revenue\n" +
		"2026-07-27\n" +
		"2\n" +
		"revbatch_00000000000000000000000000000001\n" +
		"net-captured-revenue-v1\n" +
		"500\n" +
		"2\n" +
		"EUR\n2\n12345\n345\n12000\n12000\n600\n4\n" +
		"JPY\n0\n20000\n0\n20000\n20000\n1000\n2\n"
	if payload != wantPayload {
		t.Fatalf("canonical revenue payload mismatch:\nwant %q\n got %q", wantPayload, payload)
	}

	receipt := string(RevenueReceiptMessage(
		Version,
		"example:region-a",
		"revbatch_00000000000000000000000000000002",
		"dep_00000000000000000000000000000001",
		7,
		"sha256:entry",
		"sha256:previous",
		"sha256:batch",
		RevenueKind,
		"2026-07-27",
		2,
		"revbatch_00000000000000000000000000000001",
		RevenueRulesetVersion,
		RevenueCommissionBasisPoints,
		2,
		"2026-07-28T00:00:00Z",
		"2026-07-28",
		"rkey_0123456789abcdef0123456789abcdef",
	))
	wantReceipt := "" +
		"myscoutee-registry-revenue-receipt-v1\n" +
		"1\nexample:region-a\n" +
		"revbatch_00000000000000000000000000000002\n" +
		"dep_00000000000000000000000000000001\n" +
		"7\nsha256:entry\nsha256:previous\nsha256:batch\n" +
		"daily-revenue\n2026-07-27\n2\n" +
		"revbatch_00000000000000000000000000000001\n" +
		"net-captured-revenue-v1\n500\n2\n" +
		"2026-07-28T00:00:00Z\n2026-07-28\n" +
		"rkey_0123456789abcdef0123456789abcdef\n"
	if receipt != wantReceipt {
		t.Fatalf("canonical revenue receipt mismatch:\nwant %q\n got %q", wantReceipt, receipt)
	}
}

func TestRevenueCurrencyMetadataAndCommissionAreDeterministic(t *testing.T) {
	t.Parallel()
	for code, want := range map[string]int64{
		"EUR": 2,
		"HUF": 2,
		"JPY": 0,
		"BHD": 3,
		"CLF": 4,
	} {
		got, ok := ISO4217FractionDigits(code)
		if !ok || got != want {
			t.Fatalf("currency %s fraction digits = %d/%v, want %d/true", code, got, ok, want)
		}
	}
	if _, ok := ISO4217FractionDigits("ZZZ"); ok {
		t.Fatalf("unknown currency code unexpectedly accepted")
	}
	if got := RevenueCommissionMinor(19); got != 0 {
		t.Fatalf("commission floor for 19 minor units = %d, want 0", got)
	}
	if got := RevenueCommissionMinor(12_345); got != 617 {
		t.Fatalf("commission floor for 12345 minor units = %d, want 617", got)
	}
}

func TestStructuredOperatorClaimCanonicalPayloadCommitsEveryField(t *testing.T) {
	t.Parallel()
	payload := string(OperatorClaimPayload(
		"Example Cooperative",
		"REG-42",
		"Slovakia",
		"Main Street 1",
		"https://example.test",
		"Alex Reviewer",
		"Director",
		"alex@example.test",
		true,
		"https://example.test/avatar.png",
	))
	want := "" +
		"myscoutee-registry-operator-claim-payload-v2\n" +
		"claim\n" +
		"Example Cooperative\n" +
		"REG-42\n" +
		"Slovakia\n" +
		"Main Street 1\n" +
		"https://example.test\n" +
		"Alex Reviewer\n" +
		"Director\n" +
		"alex@example.test\n" +
		"true\n" +
		"https://example.test/avatar.png\n"
	if payload != want {
		t.Fatalf("canonical operator claim payload mismatch:\nwant %q\n got %q", want, payload)
	}
	changed := OperatorClaimPayload(
		"Example Cooperative",
		"REG-42",
		"Slovakia",
		"Changed address",
		"https://example.test",
		"Alex Reviewer",
		"Director",
		"alex@example.test",
		true,
		"https://example.test/avatar.png",
	)
	if Digest([]byte(payload)) == Digest(changed) {
		t.Fatalf("changing a private claim field must change the canonical digest")
	}
}
