package enrichment

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

var errUnsafe = errors.New("unsafe_endpoint")
var errInvalid = errors.New("invalid_response")
var errLarge = errors.New("response_too_large")
var errUnavailable = errors.New("registry_unavailable")

type rateError struct{ until time.Time }

func (*rateError) Error() string { return "rate_limited" }
func reason(err error) string {
	var rate *rateError
	switch {
	case errors.As(err, &rate):
		return "rate_limited"
	case errors.Is(err, errUnsafe):
		return "unsafe_endpoint"
	case errors.Is(err, errInvalid):
		return "invalid_response"
	case errors.Is(err, errLarge):
		return "response_too_large"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "lookup_timeout"
	}
	switch err.Error() {
	case "fallback_unsupported", "registry_missing":
		return err.Error()
	}
	return "registry_unavailable"
}
func fallbackEligible(err error) bool { return errors.Is(err, errUnavailable) }

type hostSlot struct {
	token chan struct{}
	next  time.Time
}
type hostGate struct {
	mu      sync.Mutex
	slots   map[string]*hostSlot
	spacing time.Duration
}

func newHostGate(spacing time.Duration) *hostGate {
	return &hostGate{slots: map[string]*hostSlot{}, spacing: spacing}
}

var productionGate = newHostGate(time.Second)

func (g *hostGate) acquire(ctx context.Context, host string) (func(time.Time), error) {
	g.mu.Lock()
	slot := g.slots[host]
	if slot == nil {
		slot = &hostSlot{token: make(chan struct{}, 1)}
		slot.token <- struct{}{}
		g.slots[host] = slot
	}
	g.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-slot.token:
	}
	// next is protected by this slot's token, never by a mutex during waiting/I/O.
	if delay := time.Until(slot.next); delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			slot.token <- struct{}{}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		slot.token <- struct{}{}
		return nil, err
	}
	return func(cooldown time.Time) {
		slot.next = time.Now().Add(g.spacing)
		if cooldown.After(slot.next) {
			slot.next = cooldown
		}
		slot.token <- struct{}{}
	}, nil
}

type networkGuard struct {
	resolve func(context.Context, string, string) ([]netip.Addr, error)
	dial    func(context.Context, string, string) (net.Conn, error)
}

func newNetworkGuard() *networkGuard {
	d := &net.Dialer{Timeout: requestTimeout, KeepAlive: -1}
	return &networkGuard{resolve: net.DefaultResolver.LookupNetIP, dial: d.DialContext}
}
func (g *networkGuard) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || network != "tcp" {
		return nil, errUnsafe
	}
	_, rir := rirBases[host]
	if !((port == "443" && (rir || host == "data.iana.org")) || (port == "43" && host == "whois.ripe.net")) {
		return nil, errUnsafe
	}
	ips, err := g.resolve(ctx, "ip", host)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errUnavailable
	}
	if len(ips) == 0 {
		return nil, errUnsafe
	}
	// Validate every answer before dialing any address. The validated literal is
	// passed to DialContext, so DNS cannot rebind between validation and connect.
	for i, ip := range ips {
		canonical, ok := publicAddress(ip.String())
		if !ok {
			return nil, errUnsafe
		}
		ips[i] = canonical
	}
	// Reserve time for each validated answer, so unreachable IPv6 cannot
	// consume the entire request budget on an IPv4-only installation.
	for i, ip := range ips {
		budget := requestTimeout / time.Duration(len(ips)-i)
		if deadline, ok := ctx.Deadline(); ok {
			budget = time.Until(deadline) / time.Duration(len(ips)-i)
		}
		attempt, cancel := context.WithTimeout(ctx, budget)
		conn, err := g.dial(attempt, "tcp", net.JoinHostPort(ip.String(), port))
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		remoteHost, remotePort, err := net.SplitHostPort(conn.RemoteAddr().String())
		remote, ok := publicAddress(remoteHost)
		if err != nil || !ok || remote != ip || remotePort != port {
			conn.Close()
			return nil, errUnsafe
		}
		return conn, nil
	}
	return nil, errUnavailable
}
func (g *networkGuard) transport() *http.Transport {
	return &http.Transport{Proxy: nil, DialContext: g.dialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: requestTimeout, ResponseHeaderTimeout: requestTimeout, MaxResponseHeaderBytes: 64 << 10, DisableKeepAlives: true, MaxConnsPerHost: 1, ForceAttemptHTTP2: false}
}
func (g *networkGuard) queryWHOIS(parent context.Context, host, query string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, requestTimeout)
	defer cancel()
	conn, err := g.dialContext(ctx, "tcp", net.JoinHostPort(host, "43"))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return "", errUnavailable
	}
	if _, err = io.WriteString(conn, query); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", errUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(conn, maxResponse+1))
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", errUnavailable
	}
	if len(body) > maxResponse {
		return "", errLarge
	}
	return string(body), nil
}
func retryAfter(raw string, now time.Time) time.Time {
	if seconds, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 32); err == nil {
		return now.Add(time.Duration(seconds) * time.Second)
	}
	if parsed, err := http.ParseTime(raw); err == nil && parsed.After(now) {
		return parsed
	}
	return now.Add(time.Hour)
}
func (r *resolver) fetch(ctx context.Context, endpoint string) ([]byte, string, error) {
	client := *r.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	via := []*http.Request{}
	for {
		reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
		if err != nil {
			cancel()
			return nil, endpoint, errUnsafe
		}
		if len(via) > 0 {
			if err = r.checkRedirect(req, via); err != nil {
				cancel()
				return nil, endpoint, err
			}
		}
		req.Header.Set("Accept", "application/rdap+json, application/json")
		release, err := r.gate.acquire(reqCtx, req.URL.Host)
		if err != nil {
			cancel()
			return nil, endpoint, err
		}
		res, err := client.Do(req)
		if err != nil {
			release(time.Time{})
			cancel()
			if ctx.Err() != nil {
				return nil, endpoint, ctx.Err()
			}
			// A certificate authentication failure is not registry unavailability.
			// Never downgrade an unverified HTTPS response to plain WHOIS.
			var certificateError *tls.CertificateVerificationError
			if errors.Is(err, errUnsafe) || errors.As(err, &certificateError) {
				return nil, endpoint, errUnsafe
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, endpoint, context.DeadlineExceeded
			}
			return nil, endpoint, errUnavailable
		}
		if res.StatusCode == 429 {
			until := retryAfter(res.Header.Get("Retry-After"), time.Now())
			res.Body.Close()
			release(until)
			cancel()
			return nil, endpoint, &rateError{until}
		}
		if res.StatusCode == 301 || res.StatusCode == 302 || res.StatusCode == 303 || res.StatusCode == 307 || res.StatusCode == 308 {
			location, err := res.Location()
			res.Body.Close()
			release(time.Time{})
			cancel()
			if err != nil {
				return nil, endpoint, errUnsafe
			}
			via = append(via, req)
			endpoint = location.String()
			continue
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			release(time.Time{})
			cancel()
			if res.StatusCode == 404 || res.StatusCode == 501 || res.StatusCode >= 500 {
				return nil, endpoint, errUnavailable
			}
			return nil, endpoint, errInvalid
		}
		data, readErr := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
		res.Body.Close()
		release(time.Time{})
		cancel()
		if len(data) > maxResponse {
			return nil, endpoint, errLarge
		}
		if readErr != nil {
			if ctx.Err() != nil {
				return nil, endpoint, ctx.Err()
			}
			return nil, endpoint, errUnavailable
		}
		return data, endpoint, nil
	}
}
