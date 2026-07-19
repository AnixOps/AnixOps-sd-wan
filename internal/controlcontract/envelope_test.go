package controlcontract

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignerRoundTripVerifiesTypedClientPayload(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := NewSigner(privateKey)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	verifier, err := NewVerifier(publicKey)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	signed, err := signer.Sign(validClientEnvelope(t, now))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if signed.Algorithm != SignatureAlgorithm {
		t.Fatalf("algorithm = %q, want %q", signed.Algorithm, SignatureAlgorithm)
	}
	if len(signed.PayloadSHA256) != 64 {
		t.Fatalf("payload hash length = %d, want 64", len(signed.PayloadSHA256))
	}
	if err := verifier.Verify(signed, now.Add(time.Minute)); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVerifierRejectsPayloadMutationSignatureMutationAndExpiration(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := NewSigner(privateKey)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	verifier, err := NewVerifier(publicKey)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}

	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	signed, err := signer.Sign(validClientEnvelope(t, now))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	t.Run("payload mutation", func(t *testing.T) {
		mutated := signed
		mutated.Payload = json.RawMessage(strings.Replace(string(signed.Payload), "device-1", "device-2", 1))
		err := verifier.Verify(mutated, now.Add(time.Minute))
		if err == nil || !strings.Contains(err.Error(), "payload hash") {
			t.Fatalf("Verify() error = %v, want payload hash error", err)
		}
	})

	t.Run("signature mutation", func(t *testing.T) {
		mutated := signed
		signature, err := base64.StdEncoding.DecodeString(mutated.Signature)
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		signature[0] ^= 0xff
		mutated.Signature = base64.StdEncoding.EncodeToString(signature)
		err = verifier.Verify(mutated, now.Add(time.Minute))
		if err == nil || !strings.Contains(err.Error(), "signature verification") {
			t.Fatalf("Verify() error = %v, want signature verification error", err)
		}
	})

	t.Run("expiration", func(t *testing.T) {
		err := verifier.Verify(signed, signed.ExpiresAt)
		if err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("Verify() error = %v, want expired error", err)
		}
	})
}

func TestSignerRejectsTargetMismatchAndInvalidMetadata(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := NewSigner(privateKey)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)

	targetMismatch := validClientEnvelope(t, now)
	targetMismatch.TargetID = "device-2"
	if _, err := signer.Sign(targetMismatch); err == nil || !strings.Contains(err.Error(), "target ID") {
		t.Fatalf("Sign() error = %v, want target binding error", err)
	}

	zeroSequence := validClientEnvelope(t, now)
	zeroSequence.Sequence = 0
	if _, err := signer.Sign(zeroSequence); err == nil || !strings.Contains(err.Error(), "sequence") {
		t.Fatalf("Sign() error = %v, want sequence error", err)
	}

	expiryBeforeIssue := validClientEnvelope(t, now)
	expiryBeforeIssue.ExpiresAt = expiryBeforeIssue.IssuedAt
	if _, err := signer.Sign(expiryBeforeIssue); err == nil || !strings.Contains(err.Error(), "expires") {
		t.Fatalf("Sign() error = %v, want expiration ordering error", err)
	}
}

func TestSigningInputV1ChangesWhenSignedMetadataChanges(t *testing.T) {
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	envelope := validClientEnvelope(t, now)
	first, err := SigningInputV1(envelope)
	if err != nil {
		t.Fatalf("SigningInputV1() error = %v", err)
	}

	envelope.Sequence++
	second, err := SigningInputV1(envelope)
	if err != nil {
		t.Fatalf("SigningInputV1() error = %v", err)
	}
	if string(first) == string(second) {
		t.Fatal("signing input did not change after sequence change")
	}
}

func validClientEnvelope(t *testing.T, now time.Time) UnsignedEnvelope {
	t.Helper()

	profile := Profile{
		SchemaVersion: SchemaVersionV1,
		Kind:          BundleKindClient,
		Client:        validClientProfile(),
	}
	payload, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal client profile: %v", err)
	}
	return UnsignedEnvelope{
		SchemaVersion: SchemaVersionV1,
		BundleKind:    BundleKindClient,
		BundleID:      "bundle-1",
		TenantID:      "tenant-1",
		TargetID:      "device-1",
		Sequence:      7,
		IssuedAt:      now,
		ExpiresAt:     now.Add(time.Hour),
		KeyID:         "key-1",
		Payload:       payload,
	}
}
