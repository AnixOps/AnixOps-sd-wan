# Delivery Contract v1 Fixtures

These fixtures are a cross-language verification boundary for the SD-WAN
delivery envelope.

- manifest.json contains the public Ed25519 verification key, fixed verification
  time, and expected length-prefixed signing input for each envelope.
- client-envelope.json is an inspection-enabled IKEv2 client profile with the
  required domain allowlist, consent, QUIC block, pinned-TLS block, and
  seven-day metadata retention.
- pop-envelope.json is a fail-closed A -> B -> C -> D POP route with a TCP
  port selector and explicit return hops.

Each envelope is direct SignedEnvelope JSON. payload_base64 decodes to the exact
profile bytes used to calculate payload_sha256 and the Ed25519 signing input.
The fixture key is public-only; no production key, private key, or seed belongs
in this directory.
