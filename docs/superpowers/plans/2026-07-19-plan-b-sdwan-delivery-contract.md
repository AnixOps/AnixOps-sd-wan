# Plan B SD-WAN Delivery Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Add a typed, versioned, tamper-evident delivery contract so the SD-WAN controller can issue client and POP profiles without relying on untyped key/value configuration.

**Architecture:** A new internal/controlcontract package owns strongly typed profile validation and a detached Ed25519 envelope. It signs a length-prefixed binary representation of stable envelope fields plus the SHA-256 digest of exact payload bytes. The wire format uses payload_base64 so JSON serialization cannot reformat signed bytes, avoiding cross-language canonicalization hazards. Existing internal/config.ConfigSigner remains intact for legacy domain.ConfigBundle consumers.

**Tech Stack:** Go standard library crypto/ed25519, crypto/sha256, encoding/binary, encoding/json, encoding/base64; existing repository Go test tooling; GitHub Actions for acceptance.

## Global Constraints

- The draft-locked documents under docs/specs/ are not edited by this plan.
- The controller accepts only anixops.sdwan.delivery/v1 envelopes.
- Decoded payload bytes are signed exactly; the JSON wire field is payload_base64, not a language-specific JSON map.
- A profile has one target kind: client or pop.
- Required routes are fail-closed; validation rejects direct-fallback fields.
- The first profile schema carries no CA private key, raw capture option, payload logging option, or arbitrary endpoint next-hop.
- Each task is one independently testable feature commit. Push it and wait for the relevant GitHub Actions run before starting the next task.

---

### Task 1: Typed Client and POP Profile Validation

**Files:**

- Create: internal/controlcontract/profile.go
- Create: internal/controlcontract/profile_test.go

**Interfaces:**

- Produces: SchemaVersionV1, BundleKind, Profile, ClientProfile, PopProfile, PopReference, RouteSelector, RoutePolicy, ServiceChain.
- Produces: Profile.Validate(), ClientProfile.Validate(), and PopProfile.Validate().
- Consumes: no production package; types must remain usable by a later Rust fixture verifier.

- [ ] **Step 1: Write failing validation tests**

~~~go
func TestProfileValidateAcceptsClientProfile(t *testing.T) {
    profile := Profile{
        SchemaVersion: SchemaVersionV1,
        Kind: BundleKindClient,
        Client: &ClientProfile{
            ID: "client-profile-1",
            PrincipalID: "device-1",
            Transport: "ikev2",
            POPs: []PopReference{{ID: "pop-a", Endpoint: "198.51.100.10:500"}},
        },
    }
    if err := profile.Validate(); err != nil {
        t.Fatalf("Validate() error = %v", err)
    }
}

func TestProfileValidateRejectsClientWithPopPayload(t *testing.T) {
    profile := Profile{
        SchemaVersion: SchemaVersionV1,
        Kind: BundleKindClient,
        Client: validClientProfile(),
        POP: &PopProfile{ID: "pop-profile-1", PrincipalID: "pop-a"},
    }
    if err := profile.Validate(); err == nil {
        t.Fatal("Validate() error = nil, want mutually exclusive payload error")
    }
}

func TestProfileValidateRejectsDirectFallbackAndEmptyServiceChain(t *testing.T) {
    profile := Profile{
        SchemaVersion: SchemaVersionV1,
        Kind: BundleKindPop,
        POP: &PopProfile{
            ID: "pop-profile-1",
            PrincipalID: "pop-a",
            Routes: []RoutePolicy{{
                ID: "route-1",
                Selector: RouteSelector{DestinationCIDR: "203.0.113.0/24"},
                Chain: ServiceChain{ID: "chain-1"},
                DirectFallback: true,
            }},
        },
    }
    if err := profile.Validate(); err == nil {
        t.Fatal("Validate() error = nil, want fail-closed service-chain error")
    }
}
~~~

- [ ] **Step 2: Verify the test fails for the intended reason**

Run: go test ./internal/controlcontract -run TestProfileValidate -count=1

Expected: FAIL because internal/controlcontract does not exist.

- [ ] **Step 3: Implement the minimal model**

~~~go
const SchemaVersionV1 = "anixops.sdwan.delivery/v1"

type BundleKind string

const (
    BundleKindClient BundleKind = "client"
    BundleKindPop BundleKind = "pop"
)

type Profile struct {
    SchemaVersion string
    Kind BundleKind
    Client *ClientProfile
    POP *PopProfile
}

func (p Profile) Validate() error {
    if p.SchemaVersion != SchemaVersionV1 {
        return fmt.Errorf("unsupported profile schema %q", p.SchemaVersion)
    }
    switch p.Kind {
    case BundleKindClient:
        if p.Client == nil || p.POP != nil {
            return fmt.Errorf("client profile must contain only client payload")
        }
        return p.Client.Validate()
    case BundleKindPop:
        if p.POP == nil || p.Client != nil {
            return fmt.Errorf("pop profile must contain only pop payload")
        }
        return p.POP.Validate()
    default:
        return fmt.Errorf("unsupported profile kind %q", p.Kind)
    }
}
~~~

Implement ClientProfile.Validate to require ID, PrincipalID, transport ikev2, and
one valid POP reference. Implement PopProfile.Validate to require ID,
PrincipalID, at least one route, valid source/destination CIDRs when present,
a TCP or UDP protocol when present, a valid inclusive port range when present,
and non-empty ordered ServiceChain.Hops. Define DirectFallback bool for wire
compatibility but reject true unconditionally.

- [ ] **Step 4: Verify focused and full tests**

Run: go test ./internal/controlcontract -count=1

Expected: PASS with profile validation tests passing.

Run: go test ./...

Expected: PASS with no regression in existing packages.

- [ ] **Step 5: Commit, push, and wait for CI**

~~~bash
git add internal/controlcontract/profile.go internal/controlcontract/profile_test.go
git commit -m "feat: add typed delivery profile validation"
git push -u origin feat/plan-b-sdwan-control
~~~

Use gh run list --branch feat/plan-b-sdwan-control and wait for the SD-WAN
GitHub Actions run to conclude successfully before Task 2.

### Task 2: Detached Ed25519 Delivery Envelope

**Files:**

- Create: internal/controlcontract/envelope.go
- Create: internal/controlcontract/envelope_test.go

**Interfaces:**

- Consumes: Profile.Validate() from Task 1.
- Produces: UnsignedEnvelope, SignedEnvelope, Signer, NewSigner,
  NewVerifier, Sign, Verify, and SigningInputV1.
- SigningInputV1 is the cross-language fixture boundary.

- [ ] **Step 1: Write failing signature and expiry tests**

~~~go
func TestSignerRoundTripVerifiesExactPayload(t *testing.T) {
    publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
    if err != nil { t.Fatal(err) }
    signer, err := NewSigner(privateKey)
    if err != nil { t.Fatal(err) }
    verifier, err := NewVerifier(publicKey)
    if err != nil { t.Fatal(err) }

    now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
    signed, err := signer.Sign(UnsignedEnvelope{
        SchemaVersion: SchemaVersionV1,
        BundleKind: BundleKindClient,
        BundleID: "bundle-1",
        TenantID: "tenant-1",
        TargetID: "device-1",
        Sequence: 7,
        IssuedAt: now,
        ExpiresAt: now.Add(time.Hour),
        KeyID: "key-1",
        Payload: json.RawMessage("{\"kind\":\"client\"}"),
    })
    if err != nil { t.Fatal(err) }
    if err := verifier.Verify(signed, now.Add(time.Minute)); err != nil {
        t.Fatalf("Verify() error = %v", err)
    }
}
~~~

Add a second test that replaces one payload byte after signing and asserts
hash/signature failure, and verifies the unchanged envelope after ExpiresAt
and asserts an expiration error.

- [ ] **Step 2: Verify the test fails for missing envelope APIs**

Run: go test ./internal/controlcontract -run 'Test(Signer|Verifier)' -count=1

Expected: FAIL because the envelope types and signer APIs do not exist.

- [ ] **Step 3: Implement deterministic detached signing**

~~~go
func SigningInputV1(envelope UnsignedEnvelope) ([]byte, error) {
    if err := envelope.ValidateMetadata(); err != nil {
        return nil, err
    }
    digest := sha256.Sum256(envelope.Payload)
    fields := [][]byte{
        []byte("anixops.sdwan.delivery-signature/v1"),
        []byte(envelope.SchemaVersion),
        []byte(envelope.BundleKind),
        []byte(envelope.BundleID),
        []byte(envelope.TenantID),
        []byte(envelope.TargetID),
        []byte(strconv.FormatUint(envelope.Sequence, 10)),
        []byte(envelope.IssuedAt.UTC().Format(time.RFC3339Nano)),
        []byte(envelope.ExpiresAt.UTC().Format(time.RFC3339Nano)),
        []byte(envelope.KeyID),
        digest[:],
    }
    var output bytes.Buffer
    for _, field := range fields {
        if err := binary.Write(&output, binary.BigEndian, uint32(len(field))); err != nil {
            return nil, err
        }
        if _, err := output.Write(field); err != nil {
            return nil, err
        }
    }
    return output.Bytes(), nil
}
~~~

Sign computes payload_sha256 from the exact json.RawMessage bytes and
base64-encodes the Ed25519 signature. Verify recomputes the hash, rejects an
unsupported schema, zero or inverted timestamps, expiration at or before the
supplied time, and an invalid public-key signature. It does not rewrite payload
bytes before hashing.

- [ ] **Step 4: Verify focused and full tests**

Run: go test ./internal/controlcontract -count=1

Expected: PASS with profile and envelope tests passing.

Run: go test ./...

Expected: PASS with no regression in existing packages.

- [ ] **Step 5: Commit, push, and wait for CI**

~~~bash
git add internal/controlcontract/envelope.go internal/controlcontract/envelope_test.go
git commit -m "feat: sign versioned delivery envelopes"
git push
~~~

Wait for the SD-WAN GitHub Actions run for this commit to conclude successfully
before Task 3.

### Task 3: Cross-Language Contract Fixtures

**Files:**

- Create: testdata/controlcontract/v1/client-envelope.json
- Create: testdata/controlcontract/v1/pop-envelope.json
- Create: testdata/controlcontract/v1/README.md
- Create: internal/controlcontract/fixtures_test.go

**Interfaces:**

- Consumes: Signer, Verifier, and SigningInputV1 from Task 2.
- Produces: immutable JSON fixture bytes, public key, expected payload digest,
  and expected signing-input hex for NetworkCore Rust verification.

- [ ] **Step 1: Write a failing fixture stability test**

~~~go
func TestV1FixtureVerifiesAndHasStableSigningInput(t *testing.T) {
    fixture := loadFixture(t, "testdata/controlcontract/v1/client-envelope.json")
    signed := decodeSignedEnvelope(t, fixture)
    verifier := mustFixtureVerifier(t)
    if err := verifier.Verify(signed, fixtureIssuedAt.Add(time.Minute)); err != nil {
        t.Fatal(err)
    }
    input, err := SigningInputV1(signed.UnsignedEnvelope)
    if err != nil { t.Fatal(err) }
    if got := hex.EncodeToString(input); got != fixtureExpectedInputHex {
        t.Fatalf("input = %s", got)
    }
}
~~~

- [ ] **Step 2: Verify the test fails because fixtures are absent**

Run: go test ./internal/controlcontract -run TestV1Fixture -count=1

Expected: FAIL because fixture files and loader do not exist.

- [ ] **Step 3: Generate fixed-time, fixed-key public fixtures**

Use a test-only deterministic private key inside the Go fixture generator test
or a checked-in public verification key. Commit only the public key, signed
envelope, digest, and expected signing-input hex. The JSON files contain one
client and one pop envelope with RFC 3339 UTC timestamps and no secrets.

- [ ] **Step 4: Verify focused and full tests**

Run: go test ./internal/controlcontract -count=1

Expected: PASS with fixture verification succeeding.

Run: go test ./...

Expected: PASS with no existing package regression.

- [ ] **Step 5: Commit, push, and wait for CI**

~~~bash
git add internal/controlcontract/fixtures_test.go testdata/controlcontract/v1
git commit -m "test: publish delivery contract fixtures"
git push
~~~

Wait for CI before starting the NetworkCore verifier plan. The following
cross-repository change consumes fixture bytes, not a copied Go type.
