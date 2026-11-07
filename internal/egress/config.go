package egress

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Reserved exit names usable in default, rules and udp.
const (
	ExitDirect = "direct"
	ExitBlock  = "block"
)

// Config is the node.egress section. The zero value dials every destination
// directly from the server, with the SSRF guard on.
type Config struct {
	// IPFamily limits direct dialing: auto (default, Happy Eyeballs), v4, v6.
	IPFamily string `yaml:"ip_family"`
	// Default is the exit for destinations no rule matches (default direct).
	Default string `yaml:"default"`
	// Exits are named upstreams: type warp, socks5 or http.
	Exits map[string]Exit `yaml:"exits"`
	// Block refuses destinations before any exit is tried.
	Block Block `yaml:"block"`
	// Rules map destinations to an exit; the first match wins.
	Rules []Rule `yaml:"rules"`
	// UDP is the exit for UDP flows: direct (default), block or a warp exit.
	UDP string `yaml:"udp"`
}

// Exit is one upstream path out of the node.
type Exit struct {
	Type string `yaml:"type"`
	// Addr is the sidecar host:port for socks5 and http exits.
	Addr string `yaml:"addr"`
	// License is an optional WARP+ or Zero Trust key for warp exits. Empty
	// uses the free account.
	License string `yaml:"license"`
}

// Block lists destinations that must never be reached.
type Block struct {
	// Domains are exact names or "*.suffix" (subdomains only, not the apex).
	Domains []string `yaml:"domains"`
	CIDRs   []string `yaml:"cidrs"`
	// CIDRFiles maps a label (a country code, say) to a file with one CIDR or
	// IP per line; "#" starts a comment.
	CIDRFiles map[string]string `yaml:"cidr_files"`
}

// Rule sends matching destinations to an exit.
type Rule struct {
	Match Match  `yaml:"match"`
	Exit  string `yaml:"exit"`
	// Fallback is "direct" to dial straight from the server when the exit
	// fails. Empty fails closed.
	Fallback string `yaml:"fallback"`
	// UDP overrides Config.UDP for matching destinations.
	UDP string `yaml:"udp"`
}

// Match selects destinations. Domains apply to hostnames, CIDRs to IP
// literals; a rule matches when either does.
type Match struct {
	Domains []string `yaml:"domains"`
	CIDRs   []string `yaml:"cidrs"`
}

// Validate checks everything that can be checked without reading files.
func (c Config) Validate() error {
	switch c.IPFamily {
	case "", "auto", "v4", "v6":
	default:
		return fmt.Errorf("ip_family %q: want auto, v4 or v6", c.IPFamily)
	}
	for name, e := range c.Exits {
		if name == "" || name == ExitDirect || name == ExitBlock {
			return fmt.Errorf("exits: name %q is reserved or empty", name)
		}
		switch e.Type {
		case "warp":
		case "socks5", "http":
			if _, _, err := net.SplitHostPort(e.Addr); err != nil {
				return fmt.Errorf("exits.%s.addr: %w", name, err)
			}
		default:
			return fmt.Errorf("exits.%s.type %q: unsupported", name, e.Type)
		}
	}
	known := func(name string) bool {
		_, ok := c.Exits[name]
		return ok || name == ExitDirect || name == ExitBlock
	}
	if c.Default != "" && !known(c.Default) {
		return fmt.Errorf("default: unknown exit %q", c.Default)
	}
	udp := func(name string) error {
		if name == "" || name == ExitDirect || name == ExitBlock {
			return nil
		}
		if e, ok := c.Exits[name]; !ok || e.Type != "warp" {
			return fmt.Errorf("udp exit %q: must be direct, block or a warp exit", name)
		}
		return nil
	}
	if err := udp(c.UDP); err != nil {
		return err
	}
	for _, d := range c.Block.Domains {
		if err := checkDomain(d); err != nil {
			return fmt.Errorf("block.domains: %w", err)
		}
	}
	if err := checkCIDRs(c.Block.CIDRs); err != nil {
		return fmt.Errorf("block.cidrs: %w", err)
	}
	for label, p := range c.Block.CIDRFiles {
		if label == "" || p == "" {
			return fmt.Errorf("block.cidr_files: label and path required")
		}
	}
	for i, r := range c.Rules {
		if len(r.Match.Domains) == 0 && len(r.Match.CIDRs) == 0 {
			return fmt.Errorf("rules[%d]: match needs domains or cidrs", i)
		}
		for _, d := range r.Match.Domains {
			if err := checkDomain(d); err != nil {
				return fmt.Errorf("rules[%d].match.domains: %w", i, err)
			}
		}
		if err := checkCIDRs(r.Match.CIDRs); err != nil {
			return fmt.Errorf("rules[%d].match.cidrs: %w", i, err)
		}
		if !known(r.Exit) {
			return fmt.Errorf("rules[%d]: unknown exit %q", i, r.Exit)
		}
		if r.Fallback != "" && r.Fallback != ExitDirect {
			return fmt.Errorf("rules[%d].fallback %q: want direct or empty", i, r.Fallback)
		}
		if err := udp(r.UDP); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return nil
}

func checkDomain(d string) error {
	p := strings.TrimPrefix(d, "*.")
	if p == "" || p != strings.ToLower(p) || strings.ContainsAny(p, "*/ :") || strings.HasPrefix(p, ".") {
		return fmt.Errorf("%q: want a lowercase name or *.suffix", d)
	}
	return nil
}

func checkCIDRs(l []string) error {
	for _, s := range l {
		if _, err := netip.ParsePrefix(s); err != nil {
			return err
		}
	}
	return nil
}
