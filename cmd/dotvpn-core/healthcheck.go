package main

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func init() {
	register("healthcheck", cmdHealthcheck)
}

// cmdHealthcheck is for container HEALTHCHECK, where the distroless image has
// no shell or curl. It queries the loopback admin listener.
func cmdHealthcheck(ctx context.Context, args []string) error {
	fs, _, _ := flagSet("healthcheck")
	addr := fs.String("addr", "127.0.0.1:9100", "node admin address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+*addr+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: %s", resp.Status)
	}
	return nil
}
