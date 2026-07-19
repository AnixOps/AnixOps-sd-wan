package linuxgw

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"anixops-sd-wan/internal/controlcontract"
)

func TestPrepareSignedServiceChainDeliveryBuildsVerifiedPlan(t *testing.T) {
	now := serviceChainDeliveryNow()
	request := validPopServiceChainDeliveryRequest(t, now)

	prepared, err := PrepareSignedServiceChainDelivery(request)
	if err != nil {
		t.Fatalf("prepare signed delivery: %v", err)
	}
	if prepared.BundleID != "pop-delivery-1" || prepared.TenantID != "tenant-1" || prepared.TargetID != "pop-a" {
		t.Fatalf("prepared delivery metadata = %+v", prepared)
	}
	if prepared.Sequence != 8 {
		t.Fatalf("prepared sequence = %d, want 8", prepared.Sequence)
	}
	if !prepared.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("prepared expiry = %s, want %s", prepared.ExpiresAt, now.Add(time.Hour))
	}
	if prepared.Plan.LocalPOPID != "pop-a" || len(prepared.Plan.Routes) != 1 {
		t.Fatalf("prepared plan = %+v", prepared.Plan)
	}
	if route := prepared.Plan.Routes[0]; route.NextPOPID != "pop-b" || route.Mark != DefaultServiceChainMarkBase {
		t.Fatalf("prepared route = %+v", route)
	}
}

func TestPrepareSignedServiceChainDeliveryRejectsNonPopBundle(t *testing.T) {
	now := serviceChainDeliveryNow()
	profile := controlcontract.Profile{
		SchemaVersion: controlcontract.SchemaVersionV1,
		Kind:          controlcontract.BundleKindClient,
		Client: &controlcontract.ClientProfile{
			ID:          "client-profile-1",
			PrincipalID: "device-1",
			Transport:   controlcontract.TransportIKEv2,
			POPs:        []controlcontract.PopReference{{ID: "pop-a", Endpoint: "198.51.100.10:500"}},
		},
	}
	request := validPopServiceChainDeliveryRequest(t, now)
	request.EnvelopeJSON = signedServiceChainEnvelopeJSON(t, profile, "device-1", 8, now.Add(-time.Minute), now.Add(time.Hour))

	_, err := PrepareSignedServiceChainDelivery(request)
	assertServiceChainDeliveryError(t, err, "must be a POP bundle")
}

func TestPrepareSignedServiceChainDeliveryRejectsWrongTargetPOP(t *testing.T) {
	now := serviceChainDeliveryNow()
	request := validPopServiceChainDeliveryRequest(t, now)
	profile := validPopServiceChainProfile("pop-b")
	request.EnvelopeJSON = signedServiceChainEnvelopeJSON(t, profile, "pop-b", 8, now.Add(-time.Minute), now.Add(time.Hour))

	_, err := PrepareSignedServiceChainDelivery(request)
	assertServiceChainDeliveryError(t, err, "does not match local POP")
}

func TestPrepareSignedServiceChainDeliveryRejectsExpiredEnvelope(t *testing.T) {
	now := serviceChainDeliveryNow()
	request := validPopServiceChainDeliveryRequest(t, now)
	request.EnvelopeJSON = signedServiceChainEnvelopeJSON(t, validPopServiceChainProfile("pop-a"), "pop-a", 8, now.Add(-2*time.Hour), now.Add(-time.Minute))

	_, err := PrepareSignedServiceChainDelivery(request)
	assertServiceChainDeliveryError(t, err, "expired")
}

func TestPrepareSignedServiceChainDeliveryRejectsReplayedSequence(t *testing.T) {
	now := serviceChainDeliveryNow()
	request := validPopServiceChainDeliveryRequest(t, now)
	request.LastAcceptedSequence = 8

	_, err := PrepareSignedServiceChainDelivery(request)
	assertServiceChainDeliveryError(t, err, "not greater than last accepted sequence")
}

func TestPrepareSignedServiceChainDeliveryRejectsInvalidSignature(t *testing.T) {
	now := serviceChainDeliveryNow()
	request := validPopServiceChainDeliveryRequest(t, now)
	var envelope controlcontract.SignedEnvelope
	if err := json.Unmarshal(request.EnvelopeJSON, &envelope); err != nil {
		t.Fatalf("decode test envelope: %v", err)
	}
	envelope.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	var err error
	request.EnvelopeJSON, err = json.Marshal(envelope)
	if err != nil {
		t.Fatalf("encode tampered envelope: %v", err)
	}

	_, err = PrepareSignedServiceChainDelivery(request)
	assertServiceChainDeliveryError(t, err, "signature verification failed")
}

func TestPrepareSignedServiceChainDeliveryRequiresVerificationTime(t *testing.T) {
	request := validPopServiceChainDeliveryRequest(t, serviceChainDeliveryNow())
	request.VerificationTime = time.Time{}

	_, err := PrepareSignedServiceChainDelivery(request)
	assertServiceChainDeliveryError(t, err, "verification time is required")
}

func validPopServiceChainDeliveryRequest(t *testing.T, now time.Time) PopServiceChainDeliveryRequest {
	t.Helper()
	return PopServiceChainDeliveryRequest{
		EnvelopeJSON:          signedServiceChainEnvelopeJSON(t, validPopServiceChainProfile("pop-a"), "pop-a", 8, now.Add(-time.Minute), now.Add(time.Hour)),
		VerificationKey:        serviceChainDeliveryPrivateKey().Public().(ed25519.PublicKey),
		VerificationTime:       now,
		LastAcceptedSequence:   7,
		Targets:                serviceChainTargets(),
		ServiceChainOptions:    serviceChainOptions(),
	}
}

func validPopServiceChainProfile(principalID string) controlcontract.Profile {
	return controlcontract.Profile{
		SchemaVersion: controlcontract.SchemaVersionV1,
		Kind:          controlcontract.BundleKindPop,
		Pop: &controlcontract.PopProfile{
			ID:          "pop-profile-1",
			PrincipalID: principalID,
			Routes: []controlcontract.RoutePolicy{{
				ID:       "enterprise",
				Selector: controlcontract.RouteSelector{DestinationCIDR: "203.0.113.0/24"},
				Chain:    controlcontract.ServiceChain{ID: "a-b-c-d", Hops: []string{"pop-b", "pop-c", "pop-d"}},
			}},
		},
	}
}

func signedServiceChainEnvelopeJSON(t *testing.T, profile controlcontract.Profile, targetID string, sequence uint64, issuedAt, expiresAt time.Time) []byte {
	t.Helper()
	payload, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	signer, err := controlcontract.NewSigner(serviceChainDeliveryPrivateKey())
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	envelope, err := signer.Sign(controlcontract.UnsignedEnvelope{
		SchemaVersion: controlcontract.SchemaVersionV1,
		BundleKind:    profile.Kind,
		BundleID:      "pop-delivery-1",
		TenantID:      "tenant-1",
		TargetID:      targetID,
		Sequence:      sequence,
		IssuedAt:      issuedAt,
		ExpiresAt:     expiresAt,
		KeyID:         "test-key-1",
		Payload:       payload,
	})
	if err != nil {
		t.Fatalf("sign envelope: %v", err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return encoded
}

func serviceChainDeliveryPrivateKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte("01234567890123456789012345678901"))
}

func serviceChainDeliveryNow() time.Time {
	return time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC)
}

func assertServiceChainDeliveryError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}
