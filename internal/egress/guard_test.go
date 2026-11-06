package egress

import (
	"net/netip"
	"testing"
)

func TestForbiddenAddr(t *testing.T) {
	for a, want := range map[string]bool{
		"127.0.0.1": true, "10.1.2.3": true, "172.16.0.1": true, "192.168.1.1": true,
		"169.254.169.254": true, "100.64.0.1": true, "0.0.0.0": true, "::1": true,
		"fe80::1": true, "fd00::1": true, "::ffff:10.0.0.1": true, "fd00:ec2::254": true,
		"8.8.8.8": false, "2606:4700::1111": false,
	} {
		if got := forbiddenAddr(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: got %v want %v", a, got, want)
		}
	}
	if err := guardControl("tcp", "10.0.0.1:80", nil); err == nil {
		t.Error("private dial allowed")
	}
}
