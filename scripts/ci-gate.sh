#!/usr/bin/env sh
set -eu

: "${GOCACHE:=/tmp/anixops-go-build}"
: "${GOMODCACHE:=/tmp/anixops-gomod}"
export GOCACHE GOMODCACHE

run() {
	printf '\n+ %s\n' "$*"
	"$@"
}

run go test ./...
if [ "${ANIXOPS_REQUIRE_PROTOCOL_INTEROP:-0}" = "1" ]; then
	run env ANIXOPS_REQUIRE_PROTOCOL_INTEROP=1 go test ./tests/protocol -run TestProtocolInteropPrerequisites -v
fi
run go vet ./...
run go build -buildvcs=false ./cmd/...

for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64; do
	goos=${target%/*}
	goarch=${target#*/}
	printf '\n+ GOOS=%s GOARCH=%s go build -buildvcs=false ./cmd/...\n' "$goos" "$goarch"
	GOOS=$goos GOARCH=$goarch go build -buildvcs=false ./cmd/...
done

printf '\nci gate passed\n'
