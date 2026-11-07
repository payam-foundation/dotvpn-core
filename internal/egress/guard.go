package egress

import (
	"fmt"
	"net/netip"
	"syscall"
)

// DenyError is returned for a destination refused by the SSRF guard or the
// blocklist. Callers map it to a forbidden response, not a gateway error.
type DenyError struct{ Addr string }

func (d *DenyError) Error() string { return fmt.Sprintf("egress to %s denied", d.Addr) }

// guardControl runs after DNS resolution on the exact address being dialled,
// so a hostname that resolves to (or rebinds to) a private address is refused.
func guardControl(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || forbiddenAddr(ap.Addr()) {
		return &DenyError{address}
	}
	return nil
}

var extraBlocked = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64
	netip.MustParsePrefix("fec0::/10"),     // site-local
}

func forbiddenAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range extraBlocked {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
