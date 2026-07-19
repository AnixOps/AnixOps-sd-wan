package linuxgw

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"anixops-sd-wan/internal/controlcontract"
)

// PopServiceChainDeliveryRequest contains the verified-delivery inputs needed
// to prepare a pure POP service-chain plan.
type PopServiceChainDeliveryRequest struct {
	EnvelopeJSON         []byte
	VerificationKey      ed25519.PublicKey
	VerificationTime     time.Time
	LastAcceptedSequence uint64
	Targets              []ServiceChainTransportTarget
	ServiceChainOptions  ServiceChainCompileOptions
}

// PreparedServiceChainDelivery contains immutable envelope metadata and the
// compiled service-chain plan. It does not persist or apply the plan.
type PreparedServiceChainDelivery struct {
	BundleID  string
	TenantID  string
	TargetID  string
	KeyID     string
	Sequence  uint64
	ExpiresAt time.Time
	Plan      ServiceChainPlan
}

// PrepareSignedServiceChainDelivery verifies a POP delivery envelope and
// compiles its profile into a service-chain plan without applying system state.
func PrepareSignedServiceChainDelivery(request PopServiceChainDeliveryRequest) (PreparedServiceChainDelivery, error) {
	if request.VerificationTime.IsZero() {
		return PreparedServiceChainDelivery{}, fmt.Errorf("verification time is required")
	}

	var envelope controlcontract.SignedEnvelope
	if err := json.Unmarshal(request.EnvelopeJSON, &envelope); err != nil {
		return PreparedServiceChainDelivery{}, fmt.Errorf("decode signed delivery envelope: %w", err)
	}

	verifier, err := controlcontract.NewVerifier(request.VerificationKey)
	if err != nil {
		return PreparedServiceChainDelivery{}, fmt.Errorf("create delivery verifier: %w", err)
	}
	if err := verifier.Verify(envelope, request.VerificationTime); err != nil {
		return PreparedServiceChainDelivery{}, fmt.Errorf("verify signed delivery envelope: %w", err)
	}

	if envelope.BundleKind != controlcontract.BundleKindPop {
		return PreparedServiceChainDelivery{}, fmt.Errorf("signed delivery must be a POP bundle")
	}

	localPOPID := strings.TrimSpace(request.ServiceChainOptions.LocalPOPID)
	if envelope.TargetID != localPOPID {
		return PreparedServiceChainDelivery{}, fmt.Errorf("envelope target POP %q does not match local POP %q", envelope.TargetID, localPOPID)
	}
	if envelope.Sequence <= request.LastAcceptedSequence {
		return PreparedServiceChainDelivery{}, fmt.Errorf("envelope sequence %d is not greater than last accepted sequence %d", envelope.Sequence, request.LastAcceptedSequence)
	}

	profile, err := controlcontract.ParseProfile(envelope.Payload)
	if err != nil {
		return PreparedServiceChainDelivery{}, fmt.Errorf("parse verified POP profile: %w", err)
	}
	if profile.Kind != controlcontract.BundleKindPop || profile.Pop == nil {
		return PreparedServiceChainDelivery{}, fmt.Errorf("verified payload must be a POP profile")
	}

	plan, err := CompileServiceChainPlan(*profile.Pop, request.Targets, request.ServiceChainOptions)
	if err != nil {
		return PreparedServiceChainDelivery{}, fmt.Errorf("compile verified POP service-chain plan: %w", err)
	}

	return PreparedServiceChainDelivery{
		BundleID:  envelope.BundleID,
		TenantID:  envelope.TenantID,
		TargetID:  envelope.TargetID,
		KeyID:     envelope.KeyID,
		Sequence:  envelope.Sequence,
		ExpiresAt: envelope.ExpiresAt,
		Plan:      plan,
	}, nil
}
