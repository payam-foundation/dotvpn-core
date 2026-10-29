package node

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const decoyPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Welcome</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#222}</style>
</head><body><h1>Welcome</h1><p>This site is under construction. Please check back soon.</p></body></html>
`

// NewDecoy is newDecoy for carriers mounted outside the node package.
func NewDecoy(spec string) (http.Handler, error) { return newDecoy(spec) }

// newDecoy builds what ordinary visitors and active probes see:
// "" built-in page, "dir:/path" static files, "https://host" reverse proxy.
func newDecoy(spec string) (http.Handler, error) {
	switch {
	case spec == "":
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if r.URL.Path != "/" && r.URL.Path != "/index.html" {
				w.WriteHeader(http.StatusNotFound)
			}
			fmt.Fprint(w, decoyPage)
		}), nil
	case strings.HasPrefix(spec, "dir:"):
		return http.FileServer(http.Dir(strings.TrimPrefix(spec, "dir:"))), nil
	case strings.HasPrefix(spec, "http://"), strings.HasPrefix(spec, "https://"):
		u, err := url.Parse(spec)
		if err != nil {
			return nil, err
		}
		// Rewrite (not the deprecated Director) so no X-Forwarded-* header
		// is added: the decoy origin never learns the visitor's address.
		return &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(u) // also sets the outbound Host to the origin's
			r.Out.Header.Del("Proxy-Authorization")
		}}, nil
	}
	return nil, fmt.Errorf("node: invalid decoy %q", spec)
}
