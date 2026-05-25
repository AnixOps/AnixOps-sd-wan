package edge

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type EgressTarget struct {
	NodeID  string `json:"node_id"`
	Region  string `json:"region"`
	Address string `json:"address"`
}

func (t EgressTarget) Validate() error {
	if strings.TrimSpace(t.NodeID) == "" {
		return fmt.Errorf("egress target node id is required")
	}
	if strings.TrimSpace(t.Region) == "" {
		return fmt.Errorf("egress target region is required")
	}
	if strings.TrimSpace(t.Address) == "" {
		return fmt.Errorf("egress target address is required")
	}
	return nil
}

type EgressResolver interface {
	ResolveEgress(Candidate) (EgressTarget, error)
}

type StaticEgressResolver map[string]EgressTarget

func NewStaticEgressResolver(targets []EgressTarget) (StaticEgressResolver, error) {
	resolver := make(StaticEgressResolver, len(targets))
	for _, target := range targets {
		if err := target.Validate(); err != nil {
			return nil, err
		}
		if _, exists := resolver[target.NodeID]; exists {
			return nil, fmt.Errorf("duplicate egress target %s", target.NodeID)
		}
		resolver[target.NodeID] = target
	}
	if len(resolver) == 0 {
		return nil, fmt.Errorf("at least one egress target is required")
	}
	return resolver, nil
}

func (r StaticEgressResolver) ResolveEgress(candidate Candidate) (EgressTarget, error) {
	if strings.TrimSpace(candidate.ID) == "" {
		return EgressTarget{}, fmt.Errorf("candidate id is required")
	}
	target, ok := r[candidate.ID]
	if !ok {
		return EgressTarget{}, fmt.Errorf("no egress target for node %s", candidate.ID)
	}
	if err := target.Validate(); err != nil {
		return EgressTarget{}, err
	}
	return target, nil
}

type EgressDialer interface {
	DialEgress(context.Context, EgressTarget) (net.Conn, error)
}

type EgressDialFunc func(context.Context, EgressTarget) (net.Conn, error)

func (f EgressDialFunc) DialEgress(ctx context.Context, target EgressTarget) (net.Conn, error) {
	if f == nil {
		return nil, fmt.Errorf("egress dial function is required")
	}
	return f(ctx, target)
}

type NetDialer struct {
	Dialer  *net.Dialer
	Network string
}

func (d NetDialer) DialEgress(ctx context.Context, target EgressTarget) (net.Conn, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	network := strings.TrimSpace(d.Network)
	if network == "" {
		network = "tcp"
	}
	dialer := d.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	return dialer.DialContext(ctx, network, target.Address)
}

type IngressForwardResult struct {
	Credential Credential        `json:"credential"`
	Assignment IngressAssignment `json:"assignment"`
	Target     EgressTarget      `json:"target"`
	Stats      ForwardStats      `json:"stats"`
}

type IngressRuntime struct {
	auth      *Authenticator
	limiter   *WindowLimiter
	tracker   *HealthTracker
	scheduler Scheduler
	resolver  EgressResolver
	dialer    EgressDialer
	now       func() time.Time
	ttl       time.Duration
}

func NewIngressRuntime(auth *Authenticator, limiter *WindowLimiter, tracker *HealthTracker, scheduler Scheduler, resolver EgressResolver, dialer EgressDialer) (*IngressRuntime, error) {
	if auth == nil {
		return nil, fmt.Errorf("authenticator is required")
	}
	if limiter == nil {
		return nil, fmt.Errorf("limiter is required")
	}
	if tracker == nil {
		return nil, fmt.Errorf("health tracker is required")
	}
	if resolver == nil {
		return nil, fmt.Errorf("egress resolver is required")
	}
	if dialer == nil {
		return nil, fmt.Errorf("egress dialer is required")
	}
	return &IngressRuntime{
		auth:      auth,
		limiter:   limiter,
		tracker:   tracker,
		scheduler: scheduler,
		resolver:  resolver,
		dialer:    dialer,
		now:       func() time.Time { return time.Now().UTC() },
		ttl:       time.Minute,
	}, nil
}

func (r *IngressRuntime) HandleConnection(ctx context.Context, token string, client net.Conn) (IngressForwardResult, error) {
	if client == nil {
		return IngressForwardResult{}, fmt.Errorf("client connection is required")
	}
	credential, ok := r.auth.Authenticate(strings.TrimSpace(token))
	if !ok {
		_ = client.Close()
		return IngressForwardResult{}, fmt.Errorf("edge credential is invalid")
	}
	now := r.now()
	limitKey := credential.TenantID + ":" + credential.DeviceID
	if !r.limiter.Allow(limitKey, now) {
		_ = client.Close()
		return IngressForwardResult{}, fmt.Errorf("edge request rate limit exceeded")
	}
	candidates, err := r.scheduler.Rank(r.tracker.Candidates(now))
	if err != nil {
		_ = client.Close()
		return IngressForwardResult{}, err
	}

	var selected Candidate
	var target EgressTarget
	var egress net.Conn
	var attemptErrors []string
	for _, candidate := range candidates {
		resolved, err := r.resolver.ResolveEgress(candidate)
		if err != nil {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s resolve: %v", candidate.ID, err))
			continue
		}
		conn, err := r.dialer.DialEgress(ctx, resolved)
		if err != nil {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s dial: %v", resolved.NodeID, err))
			continue
		}
		if conn == nil {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s dial: nil connection", resolved.NodeID))
			continue
		}
		selected = candidate
		target = resolved
		egress = conn
		break
	}
	if egress == nil {
		_ = client.Close()
		return IngressForwardResult{}, fmt.Errorf("no reachable egress candidate: %s", strings.Join(attemptErrors, "; "))
	}
	assignment := IngressAssignment{
		TenantID:     credential.TenantID,
		DeviceID:     credential.DeviceID,
		EgressNodeID: selected.ID,
		Region:       selected.Region,
		ExpiresAt:    now.Add(r.ttl),
	}
	stats, err := ForwardBidirectional(ctx, client, egress)
	result := IngressForwardResult{
		Credential: credential,
		Assignment: assignment,
		Target:     target,
		Stats:      stats,
	}
	if err != nil {
		return result, err
	}
	return result, nil
}

type ConnListener interface {
	Accept() (net.Conn, error)
	Close() error
	Addr() net.Addr
}

type TokenExtractor interface {
	ExtractToken(context.Context, net.Conn) (string, error)
}

type TokenExtractorFunc func(context.Context, net.Conn) (string, error)

func (f TokenExtractorFunc) ExtractToken(ctx context.Context, conn net.Conn) (string, error) {
	if f == nil {
		return "", fmt.Errorf("token extractor is required")
	}
	return f(ctx, conn)
}

func (r *IngressRuntime) Serve(ctx context.Context, listener ConnListener, extractor TokenExtractor) error {
	if listener == nil {
		return fmt.Errorf("listener is required")
	}
	if extractor == nil {
		return fmt.Errorf("token extractor is required")
	}
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	go func() {
		<-serveCtx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			contextErr := serveCtx.Err()
			closed := expectedCloseError(err)
			cancel()
			wg.Wait()
			if contextErr != nil {
				return contextErr
			}
			if closed {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func(conn net.Conn) {
			defer wg.Done()
			token, err := extractor.ExtractToken(serveCtx, conn)
			if err != nil {
				_ = conn.Close()
				return
			}
			_, _ = r.HandleConnection(serveCtx, token, conn)
		}(conn)
	}
}
