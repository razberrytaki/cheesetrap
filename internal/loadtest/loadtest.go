// Package loadtest sends bounded synthetic traffic to isolated local engines.
// It never writes engine logs or database events and never equates inputs to events.
package loadtest

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"cheesetrap/internal/detection"
	"cheesetrap/internal/sensorinput"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	IsolatedTest               bool   `json:"isolated_test"`
	ExternalEnrichmentDisabled bool   `json:"external_enrichment_disabled"`
	CollectorLogDir            string `json:"collector_log_dir"`
	CollectorSourcesFile       string `json:"collector_sources_file"`
	SSHAddress                 string `json:"ssh_address"`
	SSHHostKeyFile             string `json:"ssh_host_key_file"`
	HTTPURL                    string `json:"http_url"`
	HTTPSURL                   string `json:"https_url"`
	TLSCAFile                  string `json:"tls_ca_file"`
	TLSServerName              string `json:"tls_server_name"`
	Concurrency                int    `json:"concurrency"`
	Timeout                    string `json:"timeout"`
}
type Scenario struct {
	WebWorkload         string  `json:"web_workload"`
	Name                string  `json:"name"`
	Duration            string  `json:"duration"`
	TargetNormalizedEPS float64 `json:"target_normalized_events_per_second"`
	SSHPerSecond        float64 `json:"ssh_auth_attempts_per_second"`
	HTTPPerSecond       float64 `json:"http_requests_per_second"`
	HTTPSPerSecond      float64 `json:"https_requests_per_second"`
}
type Stats struct {
	Scheduled          int     `json:"scheduled"`
	Attempted          int     `json:"attempted"`
	Succeeded          int     `json:"succeeded"`
	Failed             int     `json:"failed"`
	Dropped            int     `json:"dropped"`
	AttemptedPerSecond float64 `json:"attempted_per_second"`
	P95Milliseconds    float64 `json:"p95_milliseconds"`
	latencies          []float64
}
type Report struct {
	WebWorkload               string    `json:"web_workload"`
	WebPathCycle              []string  `json:"web_path_cycle"`
	Scenario                  string    `json:"scenario"`
	ScenarioSHA256            string    `json:"scenario_sha256"`
	StartedAt                 time.Time `json:"started_at"`
	EndedAt                   time.Time `json:"ended_at"`
	ElapsedSeconds            float64   `json:"elapsed_seconds"`
	Cancelled                 bool      `json:"cancelled"`
	TargetNormalizedEPS       float64   `json:"target_normalized_events_per_second"`
	NormalizedEventsPerSecond *float64  `json:"measured_normalized_events_per_second"`
	SSH                       Stats     `json:"ssh_auth_inputs"`
	HTTP                      Stats     `json:"http_inputs"`
	HTTPS                     Stats     `json:"https_inputs"`
}

func loopback(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" || port == "0" {
		return false
	}
	a, err := netip.ParseAddr(host)
	if err != nil || !a.IsLoopback() || a.Zone() != "" {
		return false
	}
	_, err = netip.ParseAddrPort(address)
	return err == nil
}
func safeURL(raw, scheme string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == scheme && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Path == "" || u.Path == "/") && loopback(u.Host)
}
func (c Config) Validate(s Scenario) error {
	if s.WebWorkload != "" && s.WebWorkload != "normal" && s.WebWorkload != "detection-mix-v1" {
		return errors.New("web_workload_invalid")
	}
	if !c.IsolatedTest || !c.ExternalEnrichmentDisabled {
		return errors.New("isolated_test_and_disabled_external_services_required")
	}
	d, e := time.ParseDuration(s.Duration)
	if e != nil || d <= 0 || d > time.Hour {
		return errors.New("duration_out_of_bounds")
	}
	timeout, e := time.ParseDuration(c.Timeout)
	if e != nil || timeout <= 0 || timeout > 30*time.Second || c.Concurrency < 1 || c.Concurrency > 128 {
		return errors.New("concurrency_or_timeout_out_of_bounds")
	}
	if math.IsNaN(s.TargetNormalizedEPS) || math.IsInf(s.TargetNormalizedEPS, 0) || s.TargetNormalizedEPS < 0 {
		return errors.New("target_normalized_rate_invalid")
	}
	total := s.SSHPerSecond + s.HTTPPerSecond + s.HTTPSPerSecond
	for _, rate := range []float64{s.SSHPerSecond, s.HTTPPerSecond, s.HTTPSPerSecond} {
		if math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0 || rate > 1000 {
			return errors.New("rate_out_of_bounds")
		}
	}
	if total <= 0 || total > 1000 || total*d.Seconds() > 1000000 {
		return errors.New("total_input_limit")
	}
	if s.SSHPerSecond > 0 && (!loopback(c.SSHAddress) || c.SSHHostKeyFile == "") {
		return errors.New("verified_loopback_ssh_required")
	}
	if s.HTTPPerSecond > 0 && !safeURL(c.HTTPURL, "http") {
		return errors.New("loopback_http_required")
	}
	if s.HTTPSPerSecond > 0 && (!safeURL(c.HTTPSURL, "https") || c.TLSCAFile == "" || c.TLSServerName == "") {
		return errors.New("verified_loopback_https_required")
	}
	return nil
}

type driver struct {
	c       Config
	client  *http.Client
	key     ssh.PublicKey
	timeout time.Duration
}

func newDriver(c Config, s Scenario) (*driver, error) {
	d := &driver{c: c}
	d.timeout, _ = time.ParseDuration(c.Timeout)
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	if s.HTTPSPerSecond > 0 {
		b, e := os.ReadFile(c.TLSCAFile)
		if e != nil {
			return nil, errors.New("tls_ca_unreadable")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(b) {
			return nil, errors.New("tls_ca_invalid")
		}
		tr.TLSClientConfig.RootCAs = roots
		tr.TLSClientConfig.ServerName = c.TLSServerName
	}
	d.client = &http.Client{Transport: tr, Timeout: d.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if s.SSHPerSecond > 0 {
		b, e := os.ReadFile(c.SSHHostKeyFile)
		if e != nil {
			return nil, errors.New("ssh_key_unreadable")
		}
		d.key, _, _, _, e = ssh.ParseAuthorizedKey(b)
		if e != nil {
			return nil, errors.New("ssh_key_invalid")
		}
	}
	return d, nil
}
func (d *driver) send(ctx context.Context, kind int, path string) error {
	if kind != 0 {
		base := d.c.HTTPURL
		if kind == 2 {
			base = d.c.HTTPSURL
		}
		req, e := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(base, "/")+path, nil)
		if e != nil {
			return e
		}
		req.Header.Set("User-Agent", "cheesetrap-synthetic")
		res, e := d.client.Do(req)
		if e != nil {
			return e
		}
		defer res.Body.Close()
		_, e = io.Copy(io.Discard, io.LimitReader(res.Body, 65537))
		return e
	}
	conn, e := (&net.Dialer{Timeout: d.timeout}).DialContext(ctx, "tcp", d.c.SSHAddress)
	if e != nil {
		return e
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	conn.SetDeadline(time.Now().Add(d.timeout))
	input := sensorinput.InvalidSSHCredentials()
	cfg := &ssh.ClientConfig{User: input.Username, Auth: []ssh.AuthMethod{ssh.Password(input.Password)}, HostKeyCallback: ssh.FixedHostKey(d.key), HostKeyAlgorithms: []string{d.key.Type()}, ClientVersion: "SSH-2.0-cheesetrap-loadtest", Timeout: d.timeout}
	client, _, _, e := ssh.NewClientConn(conn, d.c.SSHAddress, cfg)
	if client != nil {
		client.Close()
		return errors.New("synthetic_invalid_auth_accepted")
	}
	if e != nil && strings.Contains(e.Error(), "unable to authenticate") {
		return nil
	}
	return e
}

// Run schedules open-loop inputs. A saturated worker pool drops inputs instead
// of accumulating an unbounded backlog or bursting later to catch up.
func Run(ctx context.Context, c Config, s Scenario) (Report, error) {
	var r Report
	if e := c.Validate(s); e != nil {
		return r, e
	}
	d, e := newDriver(c, s)
	if e != nil {
		return r, e
	}
	defer d.client.CloseIdleConnections()
	b, _ := json.Marshal(s)
	sum := sha256.Sum256(b)
	r.ScenarioSHA256 = hex.EncodeToString(sum[:])
	r.Scenario = s.Name
	r.WebWorkload = s.WebWorkload
	if r.WebWorkload == "" {
		r.WebWorkload = "normal"
	}
	r.WebPathCycle = []string{"/synthetic"}
	if r.WebWorkload == "detection-mix-v1" {
		r.WebPathCycle = append(r.WebPathCycle, detection.SuspiciousPaths()...)
	}
	r.TargetNormalizedEPS = s.TargetNormalizedEPS
	r.StartedAt = time.Now().UTC()
	duration, _ := time.ParseDuration(s.Duration)
	finish := r.StartedAt.Add(duration)
	var mu sync.Mutex
	var workers, schedulers sync.WaitGroup
	slots := make(chan struct{}, c.Concurrency)
	stats := []*Stats{&r.SSH, &r.HTTP, &r.HTTPS}
	for kind, rate := range []float64{s.SSHPerSecond, s.HTTPPerSecond, s.HTTPSPerSecond} {
		if rate == 0 {
			continue
		}
		schedulers.Add(1)
		go func(kind int, rate float64) {
			defer schedulers.Done()
			st := stats[kind]
			// Cap the lateness allowance before integer conversion. Extremely
			// small positive rates may produce an infinite floating period.
			period := time.Duration(min(float64(duration), float64(time.Second)/rate))
			for n := 0; ; n++ {
				offsetSeconds := float64(n) / rate
				// Compare in floating point before converting to Duration;
				// out-of-range conversions differ across CPU architectures.
				if offsetSeconds >= duration.Seconds() {
					return
				}
				at := r.StartedAt.Add(time.Duration(offsetSeconds * float64(time.Second)))
				if !at.Before(finish) {
					return
				}
				timer := time.NewTimer(max(0, time.Until(at)))
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				mu.Lock()
				st.Scheduled++
				mu.Unlock()
				// Late scheduler slots are dropped, never replayed as a burst.
				if time.Since(at) > period {
					mu.Lock()
					st.Dropped++
					mu.Unlock()
					continue
				}
				select {
				case slots <- struct{}{}:
					workers.Add(1)
					path := r.WebPathCycle[n%len(r.WebPathCycle)]
					go func() {
						defer workers.Done()
						defer func() { <-slots }()
						start := time.Now()
						err := d.send(ctx, kind, path)
						mu.Lock()
						defer mu.Unlock()
						st.Attempted++
						if err == nil {
							st.Succeeded++
						} else {
							st.Failed++
						}
						st.latencies = append(st.latencies, float64(time.Since(start))/float64(time.Millisecond))
					}()
				default:
					mu.Lock()
					st.Dropped++
					mu.Unlock()
				}
			}
		}(kind, rate)
	}
	schedulers.Wait()
	// Preserve the full observation interval even when the last input precedes it.
	remaining := time.NewTimer(max(0, time.Until(finish)))
	select {
	case <-ctx.Done():
		remaining.Stop()
	case <-remaining.C:
	}
	workers.Wait()
	r.EndedAt = time.Now().UTC()
	r.ElapsedSeconds = r.EndedAt.Sub(r.StartedAt).Seconds()
	r.Cancelled = ctx.Err() != nil
	for _, st := range stats {
		st.AttemptedPerSecond = float64(st.Attempted) / r.ElapsedSeconds
		sort.Float64s(st.latencies)
		if len(st.latencies) > 0 {
			st.P95Milliseconds = st.latencies[(95*len(st.latencies)+99)/100-1]
		}
		st.latencies = nil
	}
	return r, nil
}

// Decode rejects unknown configuration fields and trailing JSON.
func Decode(data []byte, out any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if e := dec.Decode(out); e != nil {
		return errors.New("invalid_json")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return fmt.Errorf("trailing_json")
	}
	return nil
}
