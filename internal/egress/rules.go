package egress

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// domainSet matches exact names and "*.suffix" patterns (subdomains only).
type domainSet struct {
	exact  map[string]struct{}
	suffix map[string]struct{}
}

func newDomainSet(l []string) domainSet {
	s := domainSet{exact: map[string]struct{}{}, suffix: map[string]struct{}{}}
	for _, d := range l {
		if p, ok := strings.CutPrefix(d, "*."); ok {
			s.suffix[p] = struct{}{}
		} else {
			s.exact[d] = struct{}{}
		}
	}
	return s
}

// match reports whether host (lowercase, no trailing dot) is in the set.
func (s domainSet) match(host string) bool {
	if _, ok := s.exact[host]; ok {
		return true
	}
	for i := 0; i < len(host); i++ {
		if host[i] != '.' {
			continue
		}
		if _, ok := s.suffix[host[i+1:]]; ok {
			return true
		}
	}
	return false
}

// prefixSet is a list of CIDRs.
// ponytail: linear scan. A country list is a few thousand prefixes, which is
// microseconds per dial. Switch to a sorted slice or radix tree if lists grow
// to hundreds of thousands.
type prefixSet []netip.Prefix

func parsePrefixes(l []string) (prefixSet, error) {
	out := make(prefixSet, 0, len(l))
	for _, s := range l {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func (s prefixSet) contains(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// loadPrefixFile reads one CIDR or bare IP per line; "#" starts a comment.
func loadPrefixFile(path string) (prefixSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out prefixSet
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if p, err := netip.ParsePrefix(line); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %q is not a CIDR or IP", path, n, line)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, sc.Err()
}

// proxySafeHost reports whether a hostname may be handed to an upstream proxy.
// A sidecar on this machine resolves names itself, so "localhost", single-label
// names and numeric forms like "2130706433" or "0x7f.1" would reach loopback
// or the LAN from the proxy's side, past the node's address guard.
func proxySafeHost(h string) bool {
	i := strings.LastIndexByte(h, '.')
	if i < 0 {
		return false
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return false
	}
	_, err := strconv.ParseUint(h[i+1:], 0, 64)
	return err != nil
}
