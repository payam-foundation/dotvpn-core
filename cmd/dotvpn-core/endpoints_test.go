package main

import (
	"testing"

	"github.com/payam-foundation/dotvpn-core/internal/config"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

func TestExtraEndpointsCDNHost(t *testing.T) {
	var c config.Config
	c.Node.Transports.CDNWSPath, c.Node.Transports.CDNHost = "/ws", "cdn.example.com"
	base := transport.Endpoint{Kind: transport.KindH2, Addr: "1.2.3.4:443", Host: "d.example.com", Pin: "pin"}
	got := extraEndpoints(&c, base)
	if len(got) != 1 {
		t.Fatalf("got %d endpoints", len(got))
	}
	e := got[0]
	if e.Kind != transport.KindCDNWS || e.Addr != "cdn.example.com:443" || e.Host != "cdn.example.com" || e.Pin != "" || e.Path != "/ws" {
		t.Fatalf("bad cdnws endpoint: %+v", e)
	}
	c.Node.Transports.CDNHost = ""
	if e := extraEndpoints(&c, base)[0]; e.Addr != base.Addr || e.Pin != "pin" {
		t.Fatalf("default must reuse node address: %+v", e)
	}
}
