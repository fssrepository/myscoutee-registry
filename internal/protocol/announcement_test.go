package protocol

import (
	"strings"
	"testing"
)

func TestPackageSigningIdentityAndCanonicalMessage(t *testing.T) {
	der := []byte("complete-test-spki-der")
	expectedDigest := Digest(der)
	expectedKeyID := "pkey_" +
		expectedDigest[len("sha256:"):len("sha256:")+32]
	if PackageSigningKeyID(der) != expectedKeyID {
		t.Fatalf(
			"package key ID = %q, want %q",
			PackageSigningKeyID(der),
			expectedKeyID,
		)
	}

	manifest := UpdateManifest{
		ReleaseVersion:    "1.2.3",
		Channel:           "stable",
		ArtifactSizeBytes: 123456,
		ArtifactSHA256:    "sha256:" + strings.Repeat("a", 64),
	}
	expected := "myscoutee-release-package-v1\n" +
		"1.2.3\n" +
		"stable\n" +
		"123456\n" +
		manifest.ArtifactSHA256 + "\n"
	if string(UpdatePackageSignatureMessage(manifest)) != expected {
		t.Fatalf(
			"package signature message = %q, want %q",
			UpdatePackageSignatureMessage(manifest),
			expected,
		)
	}
}
