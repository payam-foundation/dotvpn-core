package egress

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// direct dials from the server's own address. The OS dialer does the
// resolving and Happy Eyeballs; ip_family narrows it to one family.
type direct struct {
	d      net.Dialer
	family string // "", "4" or "6"
}

func newDirect(family string, allowPrivate bool, block prefixSet) *direct {
	d := &direct{d: net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}}
	switch family {
	case "v4":
		d.family = "4"
	case "v6":
		d.family = "6"
	}
	// Control runs on every resolved address just before connect, so the
	// guard and the country blocklist see what is actually dialled.
	d.d.Control = func(network, address string, c syscall.RawConn) error {
		if !allowPrivate {
			if err := guardControl(network, address, c); err != nil {
				return err
			}
		}
		if len(block) > 0 {
			if ap, err := netip.ParseAddrPort(address); err == nil && block.contains(ap.Addr()) {
				return &DenyError{address}
			}
		}
		return nil
	}
	return d
}

func (d *direct) dial(ctx context.Context, network, host, port string) (net.Conn, error) {
	return d.d.DialContext(ctx, network+d.family, net.JoinHostPort(host, port))
}
