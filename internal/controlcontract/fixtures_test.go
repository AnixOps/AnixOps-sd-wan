package controlcontract

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const fixtureManifestSchemaV1 = "anixops.sdwan.delivery-fixture/v1"

type fixtureManifest struct {
	SchemaVersion    string         `json:"schema_version"`
	SigningDomain    string         `json:"signing_domain"`
	PublicKeyBase64  string         `json:"public_key_base64"`
	VerificationTime time.Time      `json:"verification_time"`
	Fixtures         []fixtureEntry `json:"fixtures"`
}

type fixtureEntry struct {
	File                    string `json:"file"`
	ExpectedSigningInputHex string `json:"expected_signing_input_hex"`
}

func TestV1FixturesVerifyAndHaveStableSigningInput(t *testing.T) {
	manifestData, err := os.ReadFile(controlContractFixturePath("manifest.json"))
	if err != nil {
		t.Fatalf("read fixture manifest: %v", err)
	}

	var manifest fixtureManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("decode fixture manifest: %v", err)
	}
	if manifest.SchemaVersion != fixtureManifestSchemaV1 {
		t.Fatalf("fixture schema = %q, want %q", manifest.SchemaVersion, fixtureManifestSchemaV1)
	}
	if manifest.SigningDomain != signingDomainV1 {
		t.Fatalf("fixture signing domain = %q, want %q", manifest.SigningDomain, signingDomainV1)
	}
	if manifest.VerificationTime.IsZero() {
		t.Fatal("fixture verification time is required")
	}
	if len(manifest.Fixtures) != 2 {
		t.Fatalf("fixture count = %d, want 2", len(manifest.Fixtures))
	}

	publicKey, err := base64.StdEncoding.DecodeString(manifest.PublicKeyBase64)
	if err != nil {
		t.Fatalf("decode fixture public key: %v", err)
	}
	verifier, err := NewVerifier(ed25519.PublicKey(publicKey))
	if err != nil {
		t.Fatalf("new fixture verifier: %v", err)
	}

	seen := make(map[string]struct{}, len(manifest.Fixtures))
	for _, entry := range manifest.Fixtures {
		if _, exists := seen[entry.File]; exists {
			t.Fatalf("duplicate fixture entry %q", entry.File)
		}
		seen[entry.File] = struct{}{}

		wire, err := os.ReadFile(controlContractFixturePath(entry.File))
		if err != nil {
			t.Fatalf("read fixture %q: %v", entry.File, err)
		}
		var signed SignedEnvelope
		if err := json.Unmarshal(wire, &signed); err != nil {
			t.Fatalf("decode fixture %q: %v", entry.File, err)
		}
		if err := verifier.Verify(signed, manifest.VerificationTime); err != nil {
			t.Fatalf("verify fixture %q: %v", entry.File, err)
		}
		input, err := SigningInputV1(signed.UnsignedEnvelope)
		if err != nil {
			t.Fatalf("signing input fixture %q: %v", entry.File, err)
		}
		if got := hex.EncodeToString(input); got != entry.ExpectedSigningInputHex {
			t.Fatalf("fixture %q signing input = %s, want %s", entry.File, got, entry.ExpectedSigningInputHex)
		}
	}

	for _, required := range []string{"client-envelope.json", "pop-envelope.json"} {
		if _, exists := seen[required]; !exists {
			t.Fatalf("missing fixture %q", required)
		}
	}
}

func controlContractFixturePath(parts ...string) string {
	path := []string{"..", "..", "testdata", "controlcontract", "v1"}
	path = append(path, parts...)
	return filepath.Join(path...)
}
