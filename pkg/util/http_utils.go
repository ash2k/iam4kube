package util

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ash2k/iam4kube/pkg/util/logz"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

func StartStopServer(ctx context.Context, srv *http.Server, shutdownTimeout time.Duration) error {
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

func SetServerHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "iam4kube")
		next.ServeHTTP(w, r)
	})
}

func PerRequestContextLogger(logger *zap.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ctx := logz.ContextWithLogger(req.Context(), logger)
			req = req.WithContext(ctx)
			next.ServeHTTP(w, req)
		})
	}
}

func PageNotFound(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func WriteJson(w http.ResponseWriter, data interface{}) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(data)
	if err != nil {
		return err
	}
	response := buf.Bytes()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(response))) // To ensure we don't send a chunked response
	w.Write(response)
	return nil
}

func ErrorRenderer(errorCounter prometheus.Counter, f func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := logz.LoggerFromContext(r.Context())
		err := f(w, r)
		if err == nil {
			// Everything is awesome
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		cause := errors.Cause(err)
		causedByContext := cause == context.Canceled || cause == context.DeadlineExceeded
		if !causedByContext {
			select {
			case <-r.Context().Done():
				// The error was most likely caused by the context
				causedByContext = true
			default:
			}
		}
		if causedByContext {
			logger.Debug("Internal error caused by context", zap.Error(err))
		} else {
			errorCounter.Inc()
			logger.Error("Internal error", zap.Error(err))
		}
	}
}
