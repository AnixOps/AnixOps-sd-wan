# Plan B Linux POP Service-Chain Compiler Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compile a signed POP profile into deterministic, fail-closed Linux nftables marking rules and `ip rule`/route-table commands for the configured first POP hop of an A -> B -> C -> D service chain.

**Architecture:** `internal/linuxgw` gains a pure compiler that consumes `controlcontract.PopProfile` plus operator-owned POP transport targets. It rejects an unavailable next hop, a local-hop loop, unsupported selectors, family conflicts, and table ambiguity before producing desired state. It never invokes `nft`, `ip`, EasyTier, WireGuard, or a production host.

**Tech Stack:** Go standard library, existing `internal/controlcontract`, existing GitHub Actions Go matrix, no new dependency.

## Global Constraints

- This task is one functional commit: `feat: compile fail-closed pop service chains`.
- EasyTier is only an operator-supplied POP transport interface/gateway. It is not a policy authority and no EasyTier SDK/process control is added.
- The signed `controlcontract.PopProfile` is the sole policy input. Clients never supply gateway or next-hop data.
- A route uses only `Chain.Hops[0]`. Missing target, local first hop, duplicate/ambiguous target table, or invalid selector returns an error and emits no direct route.
- Preserve ordered `ReturnHops` as desired-state metadata. This compiler does not claim to enforce remote return forwarding; each POP will compile its own profile in a later activation feature.
- Restore `meta mark` from `ct mark` for `established,related` traffic before matching an unmarked new flow. A selected flow writes both `meta mark` and `ct mark`.
- This increment supports source CIDR, destination CIDR, TCP/UDP, and ports only. A nonblank `domain_suffix` or `traffic_class` rejects as classifier-required instead of being ignored.
- A compiled selector needs a source or destination CIDR to determine one IP family. Mixed IPv4/IPv6 CIDRs reject. IPv4 renders `ip`; IPv6 renders `ip6` and `ip -6`.
- No private key, CA material, packet payload, sensitive header, or real POP address enters source, tests, or logs.
- Run focused Go tests locally, then push `feat/plan-b-sdwan-control` and wait for the full GitHub Actions matrix before any following functional feature.

## File Structure

- `internal/linuxgw/service_chain.go`: transport validation, profile compilation, typed desired state, nftables rendering, and route-command rendering.
- `internal/linuxgw/service_chain_test.go`: A -> B -> C -> D, conntrack, IPv4/IPv6, and fail-closed contract tests.
- `docs/superpowers/plans/2026-07-19-plan-b-pop-service-chain.md`: this feature's plan.

---

### Task 1: Compile POP Service-Chain Desired State

**Files:**

- Create: `internal/linuxgw/service_chain.go`
- Create: `internal/linuxgw/service_chain_test.go`
- Create: `docs/superpowers/plans/2026-07-19-plan-b-pop-service-chain.md`

**Interfaces:**

- Produces `CompileServiceChainPlan(profile controlcontract.PopProfile, targets []ServiceChainTransportTarget, options ServiceChainCompileOptions) (ServiceChainPlan, error)`.
- Produces `ServiceChainPlan.RenderNftables() (string, error)` and `ServiceChainPlan.RenderIPRouteCommands() ([]string, error)`.
- Imports only existing `internal/controlcontract` and standard-library packages. It does not import `internal/system`, endpoint code, MITM code, or an EasyTier SDK.

- [ ] **Step 1: Write the failing tests first**

Create `internal/linuxgw/service_chain_test.go` before the production file. Define a POP A profile with an enterprise TCP/443 route, source `10.10.0.0/16`, destination `203.0.113.0/24`, chain `pop-b`, `pop-c`, `pop-d`, and return hops `pop-d`, `pop-c`, `pop-b`.

```go
func TestCompileServiceChainPlanBuildsABCDConntrackPlan(t *testing.T) {
	profile := controlcontract.PopProfile{
		ID: "pop-a-profile", PrincipalID: "pop-a",
		Routes: []controlcontract.RoutePolicy{{
			ID: "enterprise",
			Selector: controlcontract.RouteSelector{
				SourceCIDR: "10.10.0.0/16", DestinationCIDR: "203.0.113.0/24",
				Protocol: controlcontract.ProtocolTCP,
				Ports: &controlcontract.PortRange{Start: 443, End: 443},
			},
			Chain: controlcontract.ServiceChain{
				ID: "a-b-c-d", Hops: []string{"pop-b", "pop-c", "pop-d"},
				ReturnHops: []string{"pop-d", "pop-c", "pop-b"},
			},
		}},
	}
	plan, err := CompileServiceChainPlan(profile,
		[]ServiceChainTransportTarget{{POPID: "pop-b", Gateway: "100.64.0.2", Interface: "easytier0", Table: 4200}},
		ServiceChainCompileOptions{LocalPOPID: "pop-a", IngressInterface: "xfrm0", MarkBase: 4000, PreferenceBase: 14000},
	)
	if err != nil { t.Fatalf("compile plan: %v", err) }
	if got := plan.Routes[0]; got.NextPOPID != "pop-b" || got.Mark != 4000 || got.Preference != 14000 || got.ChainID != "a-b-c-d" { t.Fatalf("unexpected route: %+v", got) }
	nft, err := plan.RenderNftables(); if err != nil { t.Fatalf("render nftables: %v", err) }
	for _, want := range []string{
		"ct state established,related meta mark set ct mark",
		`iifname "xfrm0" ct mark 0 ip saddr 10.10.0.0/16 ip daddr 203.0.113.0/24 tcp dport 443-443 meta mark set 4000 ct mark set 4000`,
	} { if !strings.Contains(nft, want) { t.Fatalf("missing %q in:\n%s", want, nft) } }
	commands, err := plan.RenderIPRouteCommands(); if err != nil { t.Fatalf("render routes: %v", err) }
	want := []string{"ip route replace 0.0.0.0/0 via 100.64.0.2 dev easytier0 table 4200", "ip rule add fwmark 4000 table 4200 priority 14000"}
	if !reflect.DeepEqual(want, commands) { t.Fatalf("commands got %v, want %v", commands, want) }
}
```

Add named tests that reject unknown first-hop targets, local first-hop loops, nonblank `domain_suffix`, nonblank `traffic_class`, mixed source/destination families, no CIDR selector, duplicate target IDs, and duplicate target tables. Add an IPv6 route test that checks `ip6 saddr`, `ip6 daddr`, `ip -6 route replace ::/0`, and `ip -6 rule add`.

- [ ] **Step 2: Establish the red state**

Run:

```bash
go test ./internal/linuxgw -run 'TestCompileServiceChainPlan|TestServiceChain' -count=1
```

Expected: FAIL because the service-chain types and compiler do not exist. Confirm it fails for missing implementation, not a test typo.

- [ ] **Step 3: Implement the pure compiler**

Create `internal/linuxgw/service_chain.go` with this public model:

```go
const (
	DefaultServiceChainMarkBase       = 4000
	DefaultServiceChainPreferenceBase = 14000
)

type ServiceChainIPFamily string

const (
	ServiceChainIPv4 ServiceChainIPFamily = "ipv4"
	ServiceChainIPv6 ServiceChainIPFamily = "ipv6"
)

type ServiceChainTransportTarget struct {
	POPID string
	Gateway string
	Interface string
	Table int
}

type ServiceChainCompileOptions struct {
	LocalPOPID string
	IngressInterface string
	MarkBase int
	PreferenceBase int
}

type ServiceChainRoute struct {
	RouteID string
	ChainID string
	NextPOPID string
	ReturnHops []string
	Selector controlcontract.RouteSelector
	Family ServiceChainIPFamily
	Mark int
	Preference int
	Target ServiceChainTransportTarget
}

type ServiceChainPlan struct {
	LocalPOPID string
	IngressInterface string
	Routes []ServiceChainRoute
}
```

`CompileServiceChainPlan` calls `profile.Validate()`, requires `LocalPOPID` to match `profile.PrincipalID` after trimming, normalizes defaults `4000` and `14000`, validates all targets, and rejects two distinct targets sharing a table. It preserves route order; for each route it chooses exactly `Chain.Hops[0]`, requires a target, rejects `LocalPOPID` as that hop, copies return hops, and assigns `MarkBase + index` and `PreferenceBase + index` with overflow checks.

The selector compiler must return an error when `DomainSuffix` or `TrafficClass` is nonblank, when both CIDRs are blank, or when CIDR families differ. Otherwise it retains the validated selector and determines IPv4/IPv6 from its nonblank CIDR. It must never convert an unsupported selector to an unconstrained match.

`RenderNftables` validates the plan, emits `table inet anixops_service_chain`, then a `prerouting` mangle chain containing:

```text
ct state established,related meta mark set ct mark
iifname "<ingress>" ct mark 0 [ip/ip6 source and destination selectors] [tcp/udp port selector] meta mark set <mark> ct mark set <mark>
```

Render routes in plan order. `RenderIPRouteCommands` validates the plan, installs one default route per unique `(family, table)` before each associated policy rule, and never emits a main-table/direct fallback. IPv4 lines are `ip route replace 0.0.0.0/0 [via <gateway>] dev <interface> table <table>` and `ip rule add fwmark <mark> table <table> priority <preference>`; IPv6 uses `ip -6 route replace ::/0` and `ip -6 rule add`.

- [ ] **Step 4: Verify green locally**

Run:

```bash
go test ./internal/linuxgw -run 'TestCompileServiceChainPlan|TestServiceChain' -count=1
go test ./internal/linuxgw -count=1
git diff --check
git diff -- internal/linuxgw/service_chain.go internal/linuxgw/service_chain_test.go docs/superpowers/plans/2026-07-19-plan-b-pop-service-chain.md
git status --short
```

Expected: both Go test commands pass and static checks show only the task files.

- [ ] **Step 5: Commit, push, and wait for CI**

```bash
git add internal/linuxgw/service_chain.go internal/linuxgw/service_chain_test.go docs/superpowers/plans/2026-07-19-plan-b-pop-service-chain.md
git commit -m "feat: compile fail-closed pop service chains"
git push origin feat/plan-b-sdwan-control
```

The push triggers CI. Wait for the Linux gate plus Ubuntu, Windows, and macOS tests/builds. If CI fails, use only the CI log to create a narrow corrective commit and wait for a new green run. Do not begin another functional feature until that exact run succeeds.
