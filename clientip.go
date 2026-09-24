package auth

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

// clientIP is the address the brute-force limiter counts against.
//
// Before v0.9.2 it took the leftmost X-Forwarded-For entry from any request.
// That header is client-controlled, so an attacker could send a fresh value
// with every attempt and never be limited. Forwarding headers are now honoured
// only when the request arrives from a trusted proxy (TRUSTED_PROXIES, CIDRs or
// addresses, comma-separated; default loopback only):
//
//   - CLIENT_IP_HEADER (for example CF-Connecting-IP behind Cloudflare, or
//     X-Real-IP) is used when set and present;
//   - otherwise X-Forwarded-For is read from the right, skipping trusted
//     proxies, and the first untrusted hop is the client.
func clientIP(r *http.Request) string {
	remote := remoteHost(r.RemoteAddr)
	proxies := trustedProxies()
	if !proxies.contains(remote) {
		return remote
	}
	if name := strings.TrimSpace(os.Getenv("CLIENT_IP_HEADER")); name != "" {
		if v := strings.TrimSpace(r.Header.Get(name)); v != "" && net.ParseIP(v) != nil {
			return v
		}
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" || net.ParseIP(hop) == nil {
			continue
		}
		if !proxies.contains(hop) {
			return hop
		}
		remote = hop // every hop so far is a proxy; keep the outermost
	}
	return remote
}

func remoteHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

type proxySet []*net.IPNet

func (p proxySet) contains(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range p {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

var (
	proxiesMu  sync.Mutex
	proxiesRaw = "\x00"
	proxiesSet proxySet
)

// trustedProxies parses TRUSTED_PROXIES, re-reading it only when it changes.
func trustedProxies() proxySet {
	raw, ok := os.LookupEnv("TRUSTED_PROXIES")
	if !ok {
		raw = "127.0.0.0/8,::1/128"
	}
	proxiesMu.Lock()
	defer proxiesMu.Unlock()
	if raw == proxiesRaw {
		return proxiesSet
	}
	var set proxySet
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			if ip := net.ParseIP(part); ip != nil && ip.To4() != nil {
				part += "/32"
			} else {
				part += "/128"
			}
		}
		if _, n, err := net.ParseCIDR(part); err == nil {
			set = append(set, n)
		}
	}
	proxiesRaw, proxiesSet = raw, set
	return set
}
