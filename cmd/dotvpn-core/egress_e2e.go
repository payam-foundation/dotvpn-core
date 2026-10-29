//go:build e2e

package main

// allowPrivateEgress lets the dotvpn-lab harness use loopback origin servers.
// The tag is named "e2e" for historical reasons: it was introduced by the
// black-box test module that is now dotvpn-lab. It is a core-side switch, so
// it keeps its name. Binaries built with it are for tests only and are never
// released; the lab also builds an untagged binary to assert that the
// production SSRF guard rejects loopback, RFC1918 and metadata addresses.
const allowPrivateEgress = true
