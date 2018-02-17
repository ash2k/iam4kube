package meta

import (
	"context"
	"net/http"
	"sync"
	"time"
)

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
