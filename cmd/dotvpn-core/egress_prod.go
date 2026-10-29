//go:build !e2e

package main

// allowPrivateEgress keeps the SSRF guard on: release binaries never reach
// loopback, RFC1918 or metadata addresses.
const allowPrivateEgress = false
