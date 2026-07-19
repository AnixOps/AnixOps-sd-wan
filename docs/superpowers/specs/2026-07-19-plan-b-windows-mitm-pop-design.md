# Plan B: Managed Windows MITM and Linux POP Service Chains

> Status: accepted working design for implementation on 2026-07-19.
> This document does not amend the draft-locked specifications in docs/specs/.

## Outcome

Deliver an enterprise-usable SD-WAN for a small operations team. Linux POPs are
the routing authority, NetworkCore is the cross-platform endpoint host, and
mitm_anixops stays a policy/plugin dependency rather than a second proxy
product. The first managed Windows release includes policy-scoped HTTPS
inspection. iOS uses the operating system native IKEv2 client and needs no
NetworkCore application for the initial launch.

The system supports an explicit A -> B -> C -> D service chain. A client never
selects an arbitrary next hop. The controller signs a profile, POP A maps the
authenticated device to that profile, and every POP enforces the configured
next hop. A missing required hop denies the matching flow instead of routing it
directly to the internet.

## Fixed Decisions

| Area | Decision |
| --- | --- |
| POP overlay | EasyTier is used only for Linux POP-to-POP transport. It is never a policy authority or endpoint control plane. |
| Failure behavior | A required service chain is fail-closed. A future signed profile may name an alternate chain; it never silently falls back to direct egress. |
| Windows MITM scope | Only enrolled, authorized Windows devices and policy allowlisted domains are intercepted. Matched QUIC, certificate-pinned, and unsupported traffic is blocked. |
| Windows trust | The managed Windows service owns a machine-level inspection CA lifecycle with consent, health checks, and complete rollback. |
| iOS | MDM deploys a native IKEv2/EAP-TLS profile. A signed configuration profile is a controlled fallback. |
| PKI | Production uses the operator enterprise CA and MDM. Development and CI use isolated test CAs only. |
| Deployment | This program changes source, fixtures, CI, and deployment documentation only. It does not modify live A/B/C/D hosts, MDM, or production CA state. |
| Telemetry | Request bodies, response bodies, and sensitive headers are never emitted. Minimal operational metadata is retained for seven days. |
| Delivery | Each independently testable feature has one commit on a feature branch. NetworkCore and MITM acceptance comes from GitHub Actions. |

All collection and interception capabilities apply only to devices, accounts,
and traffic that the operator owns or is explicitly authorized to administer.

## Repository Ownership

| Repository | Owns | Does not own |
| --- | --- | --- |
| AnixOps-sd-wan | Typed control contract, Ed25519 delivery signer, tenant/device/policy data, Linux POP policy compiler, service-chain desired state, audit metadata | Windows TLS proxy, CA private-key storage, script runtime, generic TUN implementation |
| networkcore_anixops | Endpoint enrollment/runtime, platform adapters, signed-profile verification, Windows service lifecycle, TUN capture adapter, local TLS/HTTP data plane, CA platform operations, native iOS profile artifacts | POP-to-POP route authority, MITM policy grammar or C ABI ownership |
| mitm_anixops | Versioned policy grammar, C ABI, allow/deny decisions, URL/header/body plans, plugin dispatch metadata and diagnostics | TLS termination, socket I/O, trust-store mutation, packet capture, JavaScript host privileges, platform installer |

The current SD-WAN draft states that the overseas core is pure WireGuard and
that FRR/BGP owns dynamic routing. EasyTier is therefore a separately named
Linux POP transport adapter. Before protected-branch integration, record that
interpretation through the SD-WAN open-question and decision process; do not
silently rewrite locked architecture documents.

## Data Plane

~~~text
Managed Windows endpoint
  -> sing-box TUN capture for matched traffic
  -> NetworkCore loopback HTTPS proxy and TLS session host
  -> native IKEv2 interface-bound upstream connection
  -> Linux POP A identity and policy enforcement
  -> EasyTier or WireGuard POP transport A -> B -> C -> D
  -> selected egress

Native iOS client
  -> IKEv2/EAP-TLS
  -> Linux POP A identity and policy enforcement
  -> configured service chain
~~~

The Windows capture component exempts loopback traffic and binds upstream
connections to the active IKEv2 interface. This prevents a local proxy loop and
prevents the tunnel's own packets from being recaptured. Strict-route or its
platform-equivalent leak prevention applies to matched traffic. The
implementation uses a mature sing-box TUN adapter and does not create a custom
Windows packet driver or TCP/IP stack.

At POP A, the IKEv2 authenticated identity maps to exactly one tenant and
principal. nftables writes a policy mark only after that mapping and restores
the mark through conntrack for reply traffic. ip rule and dedicated route
tables forward the marked flow to the next configured POP transport. Each
intermediate POP repeats an allowlist and anti-spoofing check. No default route
substitutes for an unavailable configured hop.

## Signed Delivery Contract

The controller distributes a versioned typed profile. ConfigBundle.Values
remains compatible with existing agents but is not sufficient for this protocol
because it cannot safely express typed chains and capability gates.

~~~text
DeliveryEnvelope v1
  schema_version     anixops.sdwan.delivery/v1
  bundle_kind        client | pop
  bundle_id          immutable identifier
  tenant_id          authenticated tenant scope
  target_id          device or POP scope
  sequence           strictly increasing unsigned integer
  issued_at          UTC timestamp
  expires_at         UTC timestamp
  key_id             public signing-key identifier
  payload            exact JSON bytes
  payload_sha256     SHA-256 of those exact bytes
  signature          Ed25519 over deterministic binary signing input
~~~

The signing input uses length-prefixed UTF-8 fields and the binary SHA-256
digest. It does not depend on JSON map ordering. A receiver first verifies the
payload hash and signature, then validates schema version, tenant/target
binding, expiration, and monotonic sequence before parsing the typed payload.
Replayed, expired, cross-tenant, or capability-incompatible profiles are
rejected without changing the active configuration.

ClientProfile contains the principal, IKEv2 POP descriptors, DNS policy,
allowed routing profiles, and an optional MITM profile. PopProfile contains
identity bindings, selectors, exact service chains, return-chain requirements,
next-hop transport references, and explicit deny-direct behavior. A selector
supports source CIDR, destination CIDR, domain class, L4 protocol, and port
range. A service chain is an ordered list of POP IDs, not a free-form gateway
submitted by an endpoint.

## Windows HTTPS Inspection

NetworkCore owns this lifecycle:

1. Verify an active signed profile authorizes inspection for the device,
   consent state, and allowlisted domain scope.
2. Create or obtain an enterprise-subordinate inspection CA only through the
   enterprise PKI interface. Store private material under the Windows service
   account and OS-backed key protection; never serialize it into a profile or
   event stream.
3. Install the machine CA after explicit consent and record the previous state
   in an installation transaction.
4. Route only matched traffic from the TUN adapter to a loopback listener.
   Bind upstream sockets to IKEv2 and exempt local control traffic.
5. Terminate downstream TLS with a short-lived per-host leaf using rustls,
   validate a separate upstream TLS connection, and parse HTTP/1.1 and HTTP/2
   with hyper rather than custom framing code.
6. Send bounded request/response views to the MITM policy adapter. Apply only
   complete policy plans; a parser, quota, TLS, or upstream error never emits
   a partially modified message.
7. Block selected QUIC, certificate-pinned, unsupported, and non-allowlisted
   traffic when the active inspection profile requires it.
8. On disable, expiration, health failure, uninstall, or rollback, stop
   capture first, drain local sessions, remove only transaction-owned trust,
   restore prior state, and emit redacted metadata.

The NetworkCore script host uses rquickjs behind a deny-by-default module
loader, no filesystem/process/network host APIs, per-invocation
time/memory/stack/cancel limits, and a namespaced persistent store with quota
and atomic updates.
mitm_anixops only supplies dispatch metadata and bounded mutation plans. The
inspection service never writes raw HTTP payloads or authorization secrets to
logs.

## Native iOS Boundary

iOS v1 is a native IKEv2/EAP-TLS consumer. MDM supplies server identity,
user/device certificate reference, allowed DNS/routing policy, and removal
behavior. The signed configuration profile fallback has the same constraints.
There is no initial iOS MITM CA, Network Extension interceptor, remote script
runtime, or additional endpoint application requirement.

## Release Dependency Rules

1. mitm_anixops publishes a CI-validated ABI-compatible commit or release
   artifact with immutable header, export list, fixtures, and capability
   metadata.
2. NetworkCore updates its submodule and safe wrapper to that immutable
   revision, proves fixture parity in GitHub Actions, and exposes the host
   capability version.
3. SD-WAN profiles declare minimum NetworkCore and MITM capability versions.
   A device that cannot meet a profile refuses it before activation.
4. The controller does not issue an inspection-enabled profile until the
   matching NetworkCore capability and rollback checks are CI-validated.

## Failure Invariants

| Condition | Required result |
| --- | --- |
| Signature, hash, target, sequence, or expiry failure | Keep the last valid profile and reject the new profile with a redacted reason. |
| Required POP hop unhealthy | Deny the matching policy flow; do not direct-route it. |
| Windows capture cannot bind IKEv2 upstream | Do not activate capture; retain prior known-good state. |
| CA install or validation failure | Roll back only transaction-owned trust and do not enable interception. |
| Selected QUIC, pinning, or unsupported protocol | Block the selected flow and record no path, body, or headers. |
| Plugin/runtime quota or parse failure | Apply the explicit terminal action and never partially mutate bytes. |
| Profile expiry | Stop new inspected sessions, drain for a bounded period, then roll back inspection state. |

## Validation Matrix

| Layer | Required proof |
| --- | --- |
| SD-WAN Go contract | Unit tests for typed validation, hash/signature input, expiry, replay, target binding, and fixture serialization. |
| Linux POP compiler | Unit tests plus Linux network-namespace integration for source/L4 selectors, conntrack return marks, A -> B -> C -> D path, and failed-hop deny. |
| MITM policy core | GitHub Actions ABI/export, parser, byte-body, resource-limit, and shared-fixture tests. |
| NetworkCore host | GitHub Actions on Linux/macOS/Windows for envelope parity, capability gate, service state machine, TUN configuration, certificate transaction, and proxy boundaries. |
| Windows lab | Machine CA rollback, HTTP/1.1 and HTTP/2 HTTPS flows, blocked QUIC/pinning, no direct leak, restart recovery, and no payload logging. |
| iOS lab | MDM IKEv2/EAP-TLS install, reconnect, removal, fail-closed behavior, and signed-profile fallback. |

No feature is enterprise-ready solely because unit tests pass. The release gate
requires relevant GitHub Actions workflows plus the platform/lab evidence
listed above.

## Delivery Sequence

1. Define and sign the typed delivery envelope in AnixOps-sd-wan.
2. Extend policy selectors and compile Linux POP service-chain desired state.
3. Publish immutable shared contract fixtures and verify NetworkCore parsing.
4. Promote MITM policy-core release metadata and pin it in NetworkCore.
5. Add NetworkCore capability gates, Windows service transaction model, and
   TUN-to-loopback configuration generation.
6. Add TLS session, HTTP mutation, script runtime, and Windows trust-store
   increments in separate CI-gated changes.
7. Add IKEv2/EAP-TLS MDM and signed-profile artifacts with explicit iOS scope.
8. Run full cross-repository CI and lab acceptance before a release candidate.

The first detailed plan is
docs/superpowers/plans/2026-07-19-plan-b-sdwan-delivery-contract.md.
