package server

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ash2k/iam4kube"

	"github.com/pkg/errors"
)

func parseIp(ipPort string) (iam4kube.IP, error) {
	pos := strings.IndexByte(ipPort, ':')
	if pos <= 6 {
		// Not found or shorter than `1.1.1.1`
		return "", errors.Errorf("failed to parse the ip %q", ipPort)
	}
	return iam4kube.IP(ipPort[:pos]), nil
}

func startStopServer(ctx context.Context, srv *http.Server, shutdownTimeout time.Duration) error {
	var wg sync.WaitGroup
	defer wg.Wait() // wait for goroutine to shutdown active connections
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if srv.Shutdown(c) != nil {
			srv.Close()
		}
	}()

	err := srv.ListenAndServe()
	if err != http.ErrServerClosed {
		// Failed to start or dirty shutdown
		return err
	}
	// Clean shutdown
	return nil
}
