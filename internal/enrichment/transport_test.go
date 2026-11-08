package enrichment

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type observedRemoteConn struct {
	net.Conn
	remote net.Addr
}

func (c observedRemoteConn) RemoteAddr() net.Addr { return c.remote }

func TestLookupNetworkGuard(t *testing.T) {
	public := netip.MustParseAddr("8.8.8.8")
	for _, tc := range []struct {
		name   string
		ips    []netip.Addr
		remote string
	}{
		{"private_answer", []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ""},
		{"mixed_public_private", []netip.Addr{public, netip.MustParseAddr("10.0.0.1")}, ""},
		{"special_answer", []netip.Addr{netip.MustParseAddr("192.31.196.1")}, ""},
		{"empty_answer", nil, ""},
		{"actual_peer_mismatch", []netip.Addr{public}, "8.8.4.4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dials := 0
			g := &networkGuard{resolve: func(context.Context, string, string) ([]netip.Addr, error) { return tc.ips, nil }, dial: func(context.Context, string, string) (net.Conn, error) {
				dials++
				a, b := net.Pipe()
				b.Close()
				return observedRemoteConn{a, &net.TCPAddr{IP: net.ParseIP(tc.remote), Port: 443}}, nil
			}}
			if conn, err := g.dialContext(context.Background(), "tcp", "rdap.db.ripe.net:443"); !errors.Is(err, errUnsafe) {
				if conn != nil {
					conn.Close()
				}
				t.Fatalf("unsafe DNS/peer accepted: %v", err)
			}
			if tc.remote == "" && dials != 0 {
				t.Fatal("dialed before validating every DNS answer")
			}
		})
	}
	t.Run("validated_address_fallback_within_budget", func(t *testing.T) {
		v6 := netip.MustParseAddr("2606:4700:4700::1111")
		var targets []string
		g := &networkGuard{resolve: func(context.Context, string, string) ([]netip.Addr, error) { return []netip.Addr{v6, public}, nil }, dial: func(c context.Context, network, target string) (net.Conn, error) {
			targets = append(targets, target)
			deadline, ok := c.Deadline()
			if !ok || time.Until(deadline) > requestTimeout {
				t.Error("unbounded address attempt")
			}
			if len(targets) == 1 {
				return nil, errors.New("IPv6 unreachable")
			}
			a, b := net.Pipe()
			b.Close()
			return observedRemoteConn{a, &net.TCPAddr{IP: net.ParseIP(public.String()), Port: 443}}, nil
		}}
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel()
		conn, err := g.dialContext(ctx, "tcp", "rdap.db.ripe.net:443")
		if err != nil {
			t.Fatalf("validated IPv4 fallback failed: %v", err)
		}
		defer conn.Close()
		if len(targets) != 2 || targets[0] != "[2606:4700:4700::1111]:443" || targets[1] != "8.8.8.8:443" {
			t.Fatalf("DNS not pinned: %v", targets)
		}
	})
	t.Run("target_allowlist", func(t *testing.T) {
		g := &networkGuard{resolve: func(context.Context, string, string) ([]netip.Addr, error) {
			t.Error("unsafe host reached DNS")
			return nil, nil
		}}
		for _, target := range []string{"evil.test:443", "rdap.db.ripe.net:80", "rdap.db.ripe.net:43", "whois.ripe.net:443", "127.0.0.1:443", "data.iana.org:43"} {
			if _, err := g.dialContext(context.Background(), "tcp", target); !errors.Is(err, errUnsafe) {
				t.Fatalf("unsafe endpoint allowed %s: %v", target, err)
			}
		}
	})
}

// Only injected package-private dial hooks route validated public targets to
// this local fixture. Production transport has no loopback/allowlist override.
func TestLookupRealHTTPTransport(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, DNSNames: []string{"rdap.db.ripe.net", "rdap.arin.net"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	var mu sync.Mutex
	var names []string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		names = append(names, req.TLS.ServerName)
		mu.Unlock()
		if req.Host == "rdap.db.ripe.net" {
			http.Redirect(w, req, "https://rdap.arin.net/registry/ip/8.8.8.8", 302)
			return
		}
		io.WriteString(w, document(registryCase{Start: "8.8.8.0", End: "8.8.8.255", Version: "v4", Emails: []string{"abuse@example.net"}, Roles: []string{"abuse"}}))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	var targets, hosts []string
	g := &networkGuard{resolve: func(_ context.Context, network, host string) ([]netip.Addr, error) {
		hosts = append(hosts, host)
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}, dial: func(c context.Context, network, target string) (net.Conn, error) {
		targets = append(targets, target)
		d := net.Dialer{}
		conn, err := d.DialContext(c, network, server.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return observedRemoteConn{conn, &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 443}}, nil
	}}
	transport := g.transport()
	defer transport.CloseIdleConnections()
	transport.TLSClientConfig.RootCAs = roots
	if transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("production transport weakens TLS or honors environment proxy")
	}
	r := newResolver()
	r.gate = newHostGate(0)
	r.client = &http.Client{Transport: transport}
	r.bootstraps[true] = bootstrapCache{[]bootstrapEntry{{netip.MustParsePrefix("8.8.8.0/24"), "https://rdap.db.ripe.net/"}}, time.Now().Add(time.Hour)}
	got, err := r.lookup(context.Background(), "8.8.8.8")
	if err != nil || got.HeldReason != "" || got.SourceURL != "https://rdap.arin.net/registry/ip/8.8.8.8" {
		t.Fatalf("real guarded HTTPS failed: %+v %v", got, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(hosts, ",") != "rdap.db.ripe.net,rdap.arin.net" || strings.Join(names, ",") != "rdap.db.ripe.net,rdap.arin.net" || strings.Join(targets, ",") != "8.8.8.8:443,8.8.8.8:443" {
		t.Fatalf("redirect DNS/dial/SNI validation failed: hosts=%v targets=%v names=%v", hosts, targets, names)
	}
}

func TestLookupRealWHOISTransport(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       error
	}{
		{"bounded", "inetnum: 8.8.8.0 - 8.8.8.255\nabuse-mailbox: abuse@example.net\n", nil},
		{"oversize", strings.Repeat("x", maxResponse+1), errLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			query := make(chan string, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				buf := make([]byte, len("-b 8.8.8.8\r\n"))
				_, err = io.ReadFull(conn, buf)
				if err != nil {
					return
				}
				query <- string(buf)
				io.WriteString(conn, tc.body)
			}()
			g := &networkGuard{resolve: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			}, dial: func(c context.Context, network, target string) (net.Conn, error) {
				if target != "8.8.8.8:43" {
					t.Error("WHOIS dial was not pinned")
				}
				d := net.Dialer{}
				conn, err := d.DialContext(c, network, listener.Addr().String())
				if err != nil {
					return nil, err
				}
				return observedRemoteConn{conn, &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 43}}, nil
			}}
			body, err := g.queryWHOIS(context.Background(), "whois.ripe.net", "-b 8.8.8.8\r\n")
			if !errors.Is(err, tc.want) || (tc.want == nil && body != tc.body) {
				t.Fatalf("WHOIS bounds: bytes=%d err=%v", len(body), err)
			}
			select {
			case actual := <-query:
				if actual != "-b 8.8.8.8\r\n" {
					t.Fatal("wrong WHOIS command")
				}
			case <-time.After(time.Second):
				t.Fatal("WHOIS fixture did not receive query")
			}
		})
	}
}

func TestLookupTLSAuthenticationCannotFallBack(t *testing.T) {
	for _, name := range []string{"hostname_mismatch", "unknown_ca", "expired", "availability_fallback"} {
		t.Run(name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"rdap.db.ripe.net"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
			if name == "hostname_mismatch" {
				template.DNSNames = []string{"other.example.net"}
			}
			if name == "expired" {
				template.NotBefore = time.Now().Add(-2 * time.Hour)
				template.NotAfter = time.Now().Add(-time.Hour)
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if name != "unknown_ca" {
				roots.AddCert(cert)
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if name != "availability_fallback" {
					t.Error("unverified TLS certificate reached HTTP handler")
				}
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
			server.StartTLS()
			defer server.Close()
			g := &networkGuard{resolve: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			}, dial: func(c context.Context, network, target string) (net.Conn, error) {
				d := net.Dialer{}
				conn, err := d.DialContext(c, network, server.Listener.Addr().String())
				if err != nil {
					return nil, err
				}
				return observedRemoteConn{conn, &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 443}}, nil
			}}
			transport := g.transport()
			defer transport.CloseIdleConnections()
			transport.TLSClientConfig.RootCAs = roots
			r := newResolver()
			r.gate = newHostGate(0)
			r.client = &http.Client{Transport: transport}
			r.bootstraps[true] = bootstrapCache{[]bootstrapEntry{{netip.MustParsePrefix("8.8.8.0/24"), "https://rdap.db.ripe.net/"}}, time.Now().Add(time.Hour)}
			whoisCalls := 0
			r.whoisQuery = func(context.Context, string, string) (string, error) {
				whoisCalls++
				return "inetnum: 8.8.8.0 - 8.8.8.255\nabuse-mailbox: fallback@example.net\n", nil
			}
			got, err := r.lookup(context.Background(), "8.8.8.8")
			if name == "availability_fallback" {
				if err != nil || got.HeldReason != "" || !got.LookupSucceeded || whoisCalls != 1 || got.Method != "whois" {
					t.Fatalf("availability fallback was blocked: %+v %v calls=%d", got, err, whoisCalls)
				}
			} else if err != nil || got.HeldReason != "unsafe_endpoint" || got.LookupSucceeded || len(got.Candidates) != 0 || whoisCalls != 0 {
				t.Fatalf("TLS authentication bypassed: %+v %v calls=%d", got, err, whoisCalls)
			}
		})
	}
}
