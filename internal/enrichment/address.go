// Package enrichment resolves registry-published abuse contacts for public IPs.
// A contact is evidence for later operator/report gates, never delivery approval.
package enrichment

import "net/netip"

// Conservative policy, checked 2026-10-19 against the IANA IPv4 and IPv6
// Special-Purpose Address Registries. Even globally reachable special-purpose
// space is excluded. IPv6 also requires the current global-unicast 2000::/3.
// https://www.iana.org/assignments/iana-ipv4-special-registry/
// https://www.iana.org/assignments/iana-ipv6-special-registry/
var specialPrefixes = func() []netip.Prefix {
	raw := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "2620:4f:8000::/48", "3fff::/20", "3ffe::/16"}
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()
var globalV6 = netip.MustParsePrefix("2000::/3")

func publicAddress(raw string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || (!ip.Is4() && !globalV6.Contains(ip)) {
		return ip, false
	}
	for _, prefix := range specialPrefixes {
		if prefix.Contains(ip) {
			return ip, false
		}
	}
	return ip, true
}
func networkRange(start, end, version string, ip netip.Addr) (netip.Addr, netip.Addr, bool) {
	a, e1 := netip.ParseAddr(start)
	b, e2 := netip.ParseAddr(end)
	if e1 != nil || e2 != nil || a.Zone() != "" || b.Zone() != "" || a.Is4In6() || b.Is4In6() || a.Is4() != ip.Is4() || b.Is4() != ip.Is4() || a.Compare(b) > 0 || a.Compare(ip) > 0 || b.Compare(ip) < 0 {
		return a, b, false
	}
	if (ip.Is4() && version != "v4") || (!ip.Is4() && version != "v6") {
		return a, b, false
	}
	return a, b, true
}

// PublicAddress applies the same conservative address policy to report targets.
func PublicAddress(raw string) (netip.Addr, bool) { return publicAddress(raw) }
