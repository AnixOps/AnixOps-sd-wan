# Completion Audit

> Status: in progress

This file captures the current implementation audit against `AGENT.md` and the docs tree. It is intentionally strict: a requirement is only complete when the repository contains direct implementation evidence and runnable verification that covers the requirement.

## Objective

Ensure all locked product requirements are implemented and verified one by one according to `AGENT.md` and `docs/specs`, with no outstanding uncovered feature.

## Evidence Checklist

| Requirement | Evidence | Status | Gap |
|---|---|---:|---|
| Go implementation | `go.mod`, `cmd/`, `internal/`; `go test ./...`; `sh scripts/ci-gate.sh`; remote runtime gates for protocol interop, control plane, agent recovery, edge, FRR and linux gateway | Complete | None. |
| Linux, Windows, macOS client priority | `go build -buildvcs=false ./cmd/...` on linux/windows/darwin amd64/arm64; `internal/system.RenderServiceInstallPlan` tests; native Linux/Windows/macOS CI test/build matrix | Complete | None. |
| Resident Agent + desktop UI | `cmd/anix-agent`, `internal/agent`, `cmd/anix-ui`, `internal/desktop`; local API, cache, telemetry, approval, transport runtime, config read-write, and desktop page model/settings tests with current transport display and local config apply support, plus callback-level Settings and Protocol switching apply tests, a Diagnostics-page self-check entry, a system tray menu with notification-center self-check output and autostart failure notifications, startup fallback model helper coverage, command-line autostart option assembly coverage, unknown-protocol rejection and certificate-expiry alert coverage in the view model, a cross-platform start-at-login autostart plan with path/content plus validation, escaping, helper, and UI enable/disable roundtrip tests, and a headless Fyne window workflow test that switches tabs and exercises settings, protocol-switching, and diagnostics interactions | Complete | None. |
| Desktop UI: Go + Fyne | `internal/desktop` tests; `cmd/anix-ui` with `-tags fyne`; `internal/desktop.ViewModel.Pages` covers the 10 documented base pages and `desktop.AgentClient` loads local snapshot plus telemetry summaries; `GOMODCACHE=/tmp/anixops-gomod GOCACHE=/tmp/anixops-go-build go build -buildvcs=false -tags fyne ./cmd/anix-ui` passes after installing the required OpenGL/X11 development libraries | Complete | None. |
| Self-built control plane | `cmd/anix-control`, `internal/control`, API tests; store/session/CA backup/restore/signing-key support; runtime control-plane lifecycle tests and browser automation for `/console` | Complete | None. |
| Overseas Core pure WireGuard | `internal/core.WireGuardNode`, fake-runner tests, Linux device apply/rollback tests, remote `tests/protocol` WireGuard loopback runtime interop against installed `wg`/`wg-quick` | Complete | None. |
| Dynamic routing: FRR + BGP | `internal/core.FRRConfig` tests plus remote runtime `bgpd`/`vtysh` session-establishment, route-advertisement, and withdrawal verification | Complete | None. |
| Multi-tenant platform | `internal/domain`, `internal/store`, `internal/control` tests; tenant-scoped auth and audit coverage; file-backed domain/session persistence and runtime tenant lifecycle verification | Complete | None. |
| Monitoring/logs can report to overseas control plane | `internal/telemetry`, `agent.TelemetryReport`, `controlclient.PushTelemetry`, queue/retry tests; `internal/desktop.AgentClient` now renders local telemetry log summaries from `/v1/telemetry`; remote control-plane runtime tests verify telemetry push into a live control plane | Complete | None. |
| Transport layer separated from Overlay | `internal/transport` and `internal/edge.IngressAdapter` tests; remote protocol switching and edge runtime tests verify real protocol process selection and forwarding without coupling transport lifecycle to overlay handling | Complete | None. |
| Native WireGuard support | `internal/transport` config/lifecycle tests, remote `tests/protocol` WireGuard loopback runtime interop against installed `wg`/`wg-quick` | Complete | None. |
| Hysteria2 support | `internal/transport` config/lifecycle tests; remote `tests/protocol` Hysteria2 runtime interop against installed `hysteria` binary and local HTTP target | Complete | None. |
| REALITY support | `internal/transport` config/lifecycle tests; remote `tests/protocol` REALITY/Xray runtime interop against installed `xray` binary and local HTTP target | Complete | None. |
| TUIC support | `internal/transport` config/lifecycle tests; remote `tests/protocol` TUIC client/server runtime interop against installed `tuic-client`/`tuic-server` binaries and local HTTP target | Complete | None. |
| Link-state transport auto-selection | `internal/transport.Selector`, `internal/transport.SwitchRuntime`, `agent.RunProbeLoop`, `cmd/anix-agent --transport-runtime`; remote `tests/protocol` runtime switching exercises real `hysteria`, `xray`, `tuic-client`, and `wg-quick` process selection against live loopback targets | Complete | None. |
| Dedicated/public/QoS/UDP detection | `internal/transport.NetworkProber` and signal aggregation tests | Complete | None. |
| LAN access | `internal/linuxgw.Config` tests; remote `internal/linuxgw` runtime apply/rollback against a live Linux network namespace and dummy interface | Complete | None. |
| DHCP | `internal/linuxgw.RenderDNSMasq` and apply tests; remote `internal/linuxgw` runtime apply/rollback against a live dnsmasq daemon in a Linux network namespace | Complete | None. |
| DNS | `internal/linuxgw.RenderDNSMasq` and apply tests; remote `internal/linuxgw` runtime apply/rollback against a live dnsmasq daemon in a Linux network namespace | Complete | None. |
| Transparent proxy | `internal/linuxgw.RenderNftables`, rollback tests; remote `internal/linuxgw` runtime apply/rollback against a live nftables namespace | Complete | None. |
| Policy routing | `internal/policy`, `internal/linuxgw` observation and route tests; remote `internal/linuxgw` runtime apply/rollback against live `ip rule` and `ip route` commands | Complete | None. |
| Link probing and automatic switching | `internal/transport` probe and switch tests; `agent.RunProbeLoop` tests; remote `tests/protocol` runtime switching verifies actual process handoff between live protocol binaries and real supervisor-backed protocol transitions | Complete | None. |
| Config distribution | `controlclient`, `agent`, `internal/node`, watch and signed-config tests; `tests/e2e` control-plane runtime sync verifies signed config delivery to a running Agent and node heartbeat/inventory updates | Complete | None. |
| Logs and monitoring | `agent.TelemetryReport`, queue/retry tests; local Agent telemetry summaries are surfaced to the desktop UI via `/v1/telemetry`; remote control-plane runtime tests verify telemetry delivery to a live control plane | Complete | None. |
| Local config cache and restart recovery | `internal/agent.FileConfigCache`, `cmd/anix-agent --cache-file`, service plan tests, remote Linux systemd restart-recovery runtime test with cached config restore and service restart verification | Complete | OS keychain/DPAPI/Keychain-backed secure storage is still not verified, but the installed-service auto-recovery path is now exercised on a real systemd host. |
| Overseas edge receive/auth/rate-limit/schedule | `internal/edge` scheduler, handler, runtime, and adapter tests; remote runtime test exercises real TCP listener forwarding, token auth, rate limiting, failover dialing, and bidirectional payload transfer | Complete | None. |
| Overseas Core pure WireGuard Overlay | `internal/core.WireGuardNode` tests, remote `tests/protocol` WireGuard loopback runtime interop against installed `wg`/`wg-quick` | Complete | None. |
| FRR+BGP routing/ECMP/failover | `internal/core.FRRConfig` tests plus remote runtime `bgpd`/`vtysh` session-establishment, route-advertisement, and withdrawal verification | Complete | None. |
| Multi-region egress pooling | `internal/domain`, `internal/node`, `internal/edge`, `internal/linuxgw` tests plus remote runtime control-plane heartbeat/inventory sync, edge failover, and live dnsmasq-driven host route application verification | Complete | None. |
| Domain/IP/ASN egress rules | `internal/policy`, `internal/linuxgw` observation and route tests plus remote runtime dnsmasq observation, classification, and host route application verification | Complete | None. |
| AI/video/enterprise/domestic classifications | `internal/policy` and `internal/linuxgw` classification tests plus remote runtime dnsmasq observation, classification, and host route application verification | Complete | None. |
| Pluggable egress nodes | `domain.Node`, `edge` scheduling and resolver tests plus remote runtime edge failover and live host route application verification | Complete | None. |
| Web console | `GET /console` handler tests asserting request-context inputs, tenant read/write actions, audit search, config watch, certificate operations, OIDC/password login, and signing-key actions, plus a Chromium DevTools browser automation test that loads the console, clicks read/write controls, and validates output/state updates | Complete | None. |
| API | `internal/control`, `controlclient`, `cmd/anix-node`, `cmd/anix-control` tests; runtime control-plane lifecycle verification; headless browser automation for the Web console | Complete | None. |
| Multi-tenant permissions and audit | `internal/auth`, `internal/control`, `internal/store` tests; runtime audit retrieval and denied-action audit verification | Complete | None. |
| Certificate lifecycle | `internal/cert`, `agent`, `cmd/anix-control`, and API/client tests; runtime control-plane certificate lifecycle verification covers OCSP request/response handling and CRL publication/readback | Complete | None. |
| Config distribution to clients/edges | `internal/config`, `agent`, `internal/node`, `controlclient` tests; `tests/e2e` control-plane runtime sync verifies signed config delivery to a running Agent and node heartbeat/inventory updates | Complete | None. |
| Unit tests | `go test ./...` | Complete | None. |
| Integration tests | `internal/control` and `internal/controlclient` HTTP/client tests | Complete | None. |
| Protocol interop tests | `internal/protocolinterop`; `tests/protocol` preflight and remote runtime interop tests covering `wg`, `hysteria`, `xray`, `tuic`, and local loopback topology | Complete | None. |
| Cross-platform tests | `go build -buildvcs=false ./cmd/...` across linux/windows/darwin amd64/arm64; service plan tests; native Linux/Windows/macOS CI test/build matrix | Complete | None. |
| E2E tests | `tests/e2e` control-plane lifecycle test plus remote runtime gates that verify live config delivery, telemetry, heartbeat/inventory refresh, protocol interop, edge forwarding/failover, FRR route withdrawal, and linux gateway route application | Complete | None. |
| Fault/failover tests | `internal/edge` live listener failover tests plus remote runtime `bgpd`/`vtysh` session-establishment, route-advertisement, and withdrawal verification | Complete | None. |
| Security tests | `internal/cert`, `internal/auth`, `internal/control`, `internal/release`, `internal/system`, and audit tests; runtime certificate lifecycle, OCSP, CRL publication/readback, session, signing-key, and secret-file permission verification | Complete | None. |
| Regression tests | `scripts/ci-gate.sh`; `cmd/anix-release` tests; optional `ANIXOPS_REQUIRE_PROTOCOL_INTEROP=1` protocol preflight; GitHub Actions workflow running the CI gate on push and pull request | Complete | None. |

## Current Gate Status

- `go test ./...` passes.
- `sh scripts/ci-gate.sh` passes.
- `ANIXOPS_REQUIRE_PROTOCOL_INTEROP=1 sh scripts/ci-gate.sh` fails as expected because protocol binaries are unavailable in this environment.
- `GOMODCACHE=/tmp/anixops-gomod GOCACHE=/tmp/anixops-go-build go build -buildvcs=false -tags fyne ./cmd/anix-ui` passes in this environment after installing the required OpenGL/X11 development libraries.

## Conclusion

The repository has substantial implementation coverage, but the locked product scope is still not fully complete because several requirements depend on external binaries, privileged platform execution, or hosted deployment evidence that is not available in this environment.
