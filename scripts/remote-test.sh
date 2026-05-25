#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE="$ROOT_DIR/.env"
REMOTE_USER=${REMOTE_USER:-root}
REMOTE_DIR=${REMOTE_DIR:-/tmp/anixops-sd-wan}
SSH_OPTS=${SSH_OPTS:--o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null}

get_env_value() {
	awk -F= -v key="$1" '
		$1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
			sub("^[[:space:]]*[^=]+[[:space:]]*=[[:space:]]*", "", $0)
			sub(/[[:space:]]+$/, "", $0)
			print
			exit
		}
	' "$ENV_FILE"
}

IP=$(get_env_value IP)
PORT=$(get_env_value port)
PASSWORD=$(get_env_value password)

if [ -z "${IP:-}" ] || [ -z "${PORT:-}" ] || [ -z "${PASSWORD:-}" ]; then
	printf 'failed to parse remote connection details from %s\n' "$ENV_FILE" >&2
	exit 1
fi

run_ssh() {
	sshpass -p "$PASSWORD" ssh $SSH_OPTS -p "$PORT" "$REMOTE_USER@$IP" "$@"
}

ensure_go() {
	if run_ssh "command -v go >/dev/null 2>&1"; then
		return 0
	fi
	printf '\n+ install go on remote host\n'
	run_ssh "DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y golang-go"
}

ensure_protocol_binaries() {
	printf '\n+ ensure protocol binaries on remote host\n'
	run_ssh '
		set -eu
		if ! command -v wg >/dev/null 2>&1; then
			DEBIAN_FRONTEND=noninteractive apt-get update
			DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools
		fi
		if ! command -v hysteria >/dev/null 2>&1; then
			curl -fsSL https://get.hy2.sh/ | bash
		fi
		if ! command -v xray >/dev/null 2>&1; then
			bash -lc '\''bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --without-geodata'\''
		fi
		if ! command -v tuic >/dev/null 2>&1; then
			curl -fL https://github.com/EAimTY/tuic/releases/download/tuic-server-1.0.0/tuic-server-1.0.0-x86_64-unknown-linux-gnu -o /usr/local/bin/tuic-server
			chmod +x /usr/local/bin/tuic-server
			ln -sf /usr/local/bin/tuic-server /usr/local/bin/tuic
		elif ! command -v tuic-server >/dev/null 2>&1; then
			ln -sf "$(command -v tuic)" /usr/local/bin/tuic-server
		fi
		if ! command -v tuic-client >/dev/null 2>&1; then
			curl -fL https://github.com/EAimTY/tuic/releases/download/tuic-client-1.0.0/tuic-client-1.0.0-x86_64-unknown-linux-gnu -o /usr/local/bin/tuic-client
			chmod +x /usr/local/bin/tuic-client
		fi
	'
}

ensure_linuxgw_runtime_deps() {
	printf '\n+ ensure linux gateway runtime deps on remote host\n'
	run_ssh '
		set -eu
		missing=""
		for bin in ip nft dnsmasq; do
			if ! command -v "$bin" >/dev/null 2>&1; then
				missing="$missing $bin"
			fi
		done
		if [ -n "$missing" ]; then
			DEBIAN_FRONTEND=noninteractive apt-get update
			DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2 nftables dnsmasq
		fi
	'
}

ensure_frr_runtime_deps() {
	printf '\n+ ensure frr runtime deps on remote host\n'
	run_ssh '
		set -eu
		if [ ! -x /usr/lib/frr/bgpd ] || [ ! -x /usr/bin/vtysh ]; then
			DEBIAN_FRONTEND=noninteractive apt-get update
			DEBIAN_FRONTEND=noninteractive apt-get install -y frr
		fi
	'
}

sync_repo() {
	printf '\n+ sync repo to %s@%s:%s\n' "$REMOTE_USER" "$IP" "$REMOTE_DIR"
	tar \
		--exclude=.git \
		--exclude=.agents \
		--exclude=.codex \
		--exclude=.env \
		--exclude=anix-ui \
		-cf - -C "$ROOT_DIR" . \
	| sshpass -p "$PASSWORD" ssh $SSH_OPTS -p "$PORT" "$REMOTE_USER@$IP" "rm -rf '$REMOTE_DIR' && mkdir -p '$REMOTE_DIR' && tar -xf - -C '$REMOTE_DIR'"
}

run_remote() {
	printf '\n+ %s\n' "$*"
	run_ssh "cd '$REMOTE_DIR' && $*"
}

mode=${1:-all}

sync_repo
ensure_go

REMOTE_ENV='GOCACHE=/tmp/anixops-go-build GOMODCACHE=/tmp/anixops-gomod'

case "$mode" in
	protocol)
		ensure_protocol_binaries
		run_remote "$REMOTE_ENV ANIXOPS_REQUIRE_PROTOCOL_INTEROP=1 go test -count=1 ./tests/protocol -run 'TestProtocolInteropPrerequisites|TestProtocolRuntimeInterop|TestProtocolRuntimeSwitching' -v"
		;;
	control)
		run_remote "$REMOTE_ENV ANIXOPS_REQUIRE_CONTROL_PLANE_RUNTIME=1 go test ./internal/control ./internal/controlclient ./tests/e2e"
		;;
	agent-recovery)
		run_remote "$REMOTE_ENV ANIXOPS_REQUIRE_AGENT_RECOVERY_RUNTIME=1 go test ./internal/agent -run TestLocalConfigCacheAndRestartRecovery -count=1 -v"
		;;
	edge)
		run_remote "$REMOTE_ENV ANIXOPS_REQUIRE_EDGE_RUNTIME=1 go test ./internal/edge -run TestIngressRuntimeLiveForwardingAndFailover -count=1 -v"
		;;
	linuxgw)
		ensure_linuxgw_runtime_deps
		run_remote "$REMOTE_ENV ANIXOPS_REQUIRE_LINUXGW_RUNTIME=1 go test ./internal/linuxgw -run 'TestLinuxGatewayRuntimeApplyAndRollback|TestLinuxGatewayRuntimeLiveDNSObservationAndRouteApplication' -count=1 -v"
		;;
	frr)
		ensure_frr_runtime_deps
		run_remote "$REMOTE_ENV ANIXOPS_REQUIRE_FRR_RUNTIME=1 go test ./internal/core -run TestFRRRuntimeSessionAndRouteWithdrawal -count=1 -v"
		;;
	all)
		status=0
		ensure_protocol_binaries
		run_remote "$REMOTE_ENV ANIXOPS_REQUIRE_PROTOCOL_INTEROP=1 go test -count=1 ./tests/protocol -run 'TestProtocolInteropPrerequisites|TestProtocolRuntimeInterop|TestProtocolRuntimeSwitching' -v" || status=$?
		run_remote "$REMOTE_ENV ANIXOPS_REQUIRE_CONTROL_PLANE_RUNTIME=1 go test ./internal/control ./internal/controlclient ./tests/e2e" || status=$?
		run_remote "$REMOTE_ENV ANIXOPS_REQUIRE_AGENT_RECOVERY_RUNTIME=1 go test ./internal/agent -run TestLocalConfigCacheAndRestartRecovery -count=1 -v" || status=$?
		run_remote "$REMOTE_ENV ANIXOPS_REQUIRE_EDGE_RUNTIME=1 go test ./internal/edge -run TestIngressRuntimeLiveForwardingAndFailover -count=1 -v" || status=$?
		ensure_frr_runtime_deps
		run_remote "$REMOTE_ENV ANIXOPS_REQUIRE_FRR_RUNTIME=1 go test ./internal/core -run TestFRRRuntimeSessionAndRouteWithdrawal -count=1 -v" || status=$?
		ensure_linuxgw_runtime_deps
		run_remote "$REMOTE_ENV ANIXOPS_REQUIRE_LINUXGW_RUNTIME=1 go test ./internal/linuxgw -run 'TestLinuxGatewayRuntimeApplyAndRollback|TestLinuxGatewayRuntimeLiveDNSObservationAndRouteApplication' -count=1 -v" || status=$?
		exit "$status"
		;;
	*)
		printf 'usage: %s [protocol|control|agent-recovery|edge|frr|linuxgw|all]\n' "$0" >&2
		exit 2
		;;
esac
