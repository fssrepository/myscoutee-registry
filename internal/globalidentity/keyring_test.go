package globalidentity

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/circl/oprf"
)

func TestRFC9497P256VOPRFVector(t *testing.T) {
	t.Parallel()

	privateBytes := mustHex(
		t,
		"ca5d94c8807817669a51b196c34c1b7f8442fde4334a7121ae4736364312fca6",
	)
	privateKey := new(oprf.PrivateKey)
	if err := privateKey.UnmarshalBinary(oprf.SuiteP256, privateBytes); err != nil {
		t.Fatalf("decode RFC 9497 private key: %v", err)
	}
	publicKey, err := privateKey.Public().MarshalBinary()
	if err != nil {
		t.Fatalf("encode RFC 9497 public key: %v", err)
	}
	if want := mustHex(
		t,
		"03e17e70604bcabe198882c0a1f27a92441e774224ed9c702e51dd17038b102462",
	); !bytes.Equal(publicKey, want) {
		t.Fatalf("RFC 9497 public key mismatch")
	}

	blind := oprf.SuiteP256.Group().NewScalar()
	if err := blind.UnmarshalBinary(mustHex(
		t,
		"3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364",
	)); err != nil {
		t.Fatalf("decode RFC 9497 blind: %v", err)
	}
	client := oprf.NewVerifiableClient(oprf.SuiteP256, privateKey.Public())
	finalize, request, err := client.DeterministicBlind(
		[][]byte{{0}},
		[]oprf.Blind{blind},
	)
	if err != nil {
		t.Fatalf("apply RFC 9497 deterministic blind: %v", err)
	}
	encodedBlinded, err := request.Elements[0].MarshalBinaryCompress()
	if err != nil {
		t.Fatalf("encode RFC 9497 blinded element: %v", err)
	}
	if want := mustHex(
		t,
		"02dd05901038bb31a6fae01828fd8d0e49e35a486b5c5d4b4994013648c01277da",
	); !bytes.Equal(encodedBlinded, want) {
		t.Fatalf("RFC 9497 blinded element mismatch")
	}
	evaluation, err := oprf.NewVerifiableServer(
		oprf.SuiteP256,
		privateKey,
	).Evaluate(request)
	if err != nil {
		t.Fatalf("evaluate RFC 9497 request: %v", err)
	}
	encodedEvaluated, err :=
		evaluation.Elements[0].MarshalBinaryCompress()
	if err != nil {
		t.Fatalf("encode RFC 9497 evaluated element: %v", err)
	}
	if want := mustHex(
		t,
		"0209f33cab60cf8fe69239b0afbcfcd261af4c1c5632624f2e9ba29b90ae83e4a2",
	); !bytes.Equal(encodedEvaluated, want) {
		t.Fatalf("RFC 9497 evaluated element mismatch")
	}
	outputs, err := client.Finalize(finalize, evaluation)
	if err != nil {
		t.Fatalf("verify and finalize RFC 9497 evaluation: %v", err)
	}
	if len(outputs) != 1 || !bytes.Equal(
		outputs[0],
		mustHex(
			t,
			"0412e8f78b02c415ab3a288e228978376f99927767ff37c5718d420010a645a1",
		),
	) {
		t.Fatalf("RFC 9497 output mismatch")
	}
}

func TestKeyRingPersistsAndRotatesWithoutReplacingOldKey(
	t *testing.T,
) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "voprf-keyring.json")
	firstTime := func() time.Time {
		return time.Date(2026, 7, 29, 1, 0, 0, 0, time.UTC)
	}
	ring, generated, err := LoadOrGenerate(path, true, firstTime)
	if err != nil {
		t.Fatalf("generate VOPRF keyring: %v", err)
	}
	if !generated ||
		ring.ActivePublicKey().Version != 1 ||
		len(ring.ActivePublicKey().PublicKey) != 33 {
		t.Fatalf("unexpected initial VOPRF keyring")
	}
	firstPublic := append(
		[]byte(nil),
		ring.ActivePublicKey().PublicKey...,
	)
	rotated, err := Rotate(path, func() time.Time {
		return firstTime().Add(time.Hour)
	})
	if err != nil {
		t.Fatalf("rotate VOPRF keyring: %v", err)
	}
	if rotated.Version != 2 || len(rotated.PublicKey) != 33 {
		t.Fatalf("unexpected rotated VOPRF key")
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload rotated VOPRF keyring: %v", err)
	}
	old, ok := loaded.PublicKey(1)
	if !ok || !bytes.Equal(old.PublicKey, firstPublic) || old.Active {
		t.Fatalf("rotation did not retain the retired key")
	}
	if current := loaded.ActivePublicKey(); current.Version != 2 ||
		!bytes.Equal(current.PublicKey, rotated.PublicKey) {
		t.Fatalf("rotation did not activate the new key")
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode test vector: %v", err)
	}
	return decoded
}
