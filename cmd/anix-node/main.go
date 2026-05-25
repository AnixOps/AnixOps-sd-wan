package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"anixops-sd-wan/internal/auth"
	"anixops-sd-wan/internal/buildinfo"
	"anixops-sd-wan/internal/controlclient"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/node"
)

func main() {
	once := flag.Bool("once", false, "print one node snapshot and exit")
	syncOnce := flag.Bool("sync-once", false, "fetch control-plane node config, push heartbeat once, print snapshot and exit")
	controlURL := flag.String("control-url", "", "control plane base URL for config and heartbeat sync")
	syncInterval := flag.Duration("sync-interval", 30*time.Second, "control plane sync interval")
	tenantID := flag.String("tenant-id", "tenant-default", "node tenant id")
	nodeID := flag.String("node-id", "node-default", "node id")
	role := flag.String("role", string(domain.NodeOverseasEdge), "node role: overseas-edge, core or egress")
	region := flag.String("region", "default", "node region")
	endpoint := flag.String("endpoint", "", "node endpoint advertised through heartbeat")
	healthy := flag.Bool("healthy", true, "node heartbeat health flag")
	configVersion := flag.String("config-version", "bootstrap", "initial local node config version")
	actorID := flag.String("actor-id", "", "control plane actor id; defaults to node id")
	roles := flag.String("roles", string(auth.RoleAgent), "comma-separated control plane roles")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	info := buildinfo.Current("anix-node")
	if *showVersion {
		fmt.Printf("%s %s %s %s\n", info.Name, info.Version, info.Commit, info.Date)
		return
	}
	if *once && *syncOnce {
		fmt.Fprintln(os.Stderr, "--once and --sync-once cannot be used together")
		os.Exit(2)
	}

	service, err := node.NewService(node.Snapshot{
		TenantID:      *tenantID,
		NodeID:        *nodeID,
		Role:          domain.NodeRole(strings.TrimSpace(*role)),
		Region:        *region,
		Endpoint:      *endpoint,
		Healthy:       *healthy,
		ConfigVersion: *configVersion,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "node config error: %v\n", err)
		os.Exit(1)
	}
	if *once {
		encode(service.Snapshot())
		return
	}

	client := mustControlClient(*controlURL, *tenantID, *nodeID, *actorID, *roles)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *syncOnce {
		if err := service.SyncOnce(ctx, client); err != nil {
			fmt.Fprintf(os.Stderr, "node sync error: %v\n", err)
			os.Exit(1)
		}
		encode(service.Snapshot())
		return
	}

	fmt.Fprintln(os.Stderr, "anix-node starting")
	err = service.RunSyncLoop(ctx, client, *syncInterval)
	stop()
	if err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "node stopped with error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "anix-node stopped")
}

func encode(value interface{}) {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		fmt.Fprintf(os.Stderr, "encode output: %v\n", err)
		os.Exit(1)
	}
}

func mustControlClient(baseURL, tenantID, nodeID, actorID, roles string) *controlclient.Client {
	if baseURL == "" {
		fmt.Fprintln(os.Stderr, "control url is required for sync")
		os.Exit(2)
	}
	if actorID == "" {
		actorID = nodeID
	}
	client, err := controlclient.NewWithCredentials(baseURL, nil, controlclient.Credentials{
		TenantID: tenantID,
		ActorID:  actorID,
		Roles:    parseRoles(roles),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "control client error: %v\n", err)
		os.Exit(1)
	}
	return client
}

func parseRoles(raw string) []auth.Role {
	parts := strings.Split(raw, ",")
	roles := make([]auth.Role, 0, len(parts))
	for _, part := range parts {
		role := strings.TrimSpace(part)
		if role == "" {
			continue
		}
		roles = append(roles, auth.Role(role))
	}
	return roles
}
