package util

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/iam4kube/pkg/util/logz"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type ipContextKeyType int

const ipContextKey ipContextKeyType = 43

func ContextWithIp(ctx context.Context, ip iam4kube.IP) context.Context {
	return context.WithValue(ctx, ipContextKey, ip)
}

func IpFromContext(ctx context.Context) iam4kube.IP {
	if ip, ok := ctx.Value(ipContextKey).(iam4kube.IP); ok {
		return ip
	}

	panic(errors.New("context did not contain ip, please call ContextWithIp"))
}

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

func Iam4kubeServerHeader() func(http.Handler) http.Handler {
	return SetServerHeader("iam4kube")
}

func SetServerHeader(server string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", server)
			next.ServeHTTP(w, r)
		})
	}
}

func PerRequestContextLogger(logger *zap.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := logz.ContextWithLogger(r.Context(), logger)
			r = r.WithContext(ctx)
			next.ServeHTTP(w, r)
		})
	}
}

func AddIpToContextAndLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := logz.LoggerFromContext(ctx)
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			logger.With(zap.Error(err)).Sugar().Errorf("Failed to parse remote address %q", r.RemoteAddr)
			return
		}
		logger = logger.With(logz.RemoteIp(ip))
		ctx = logz.ContextWithLogger(ctx, logger)
		ctx = ContextWithIp(ctx, iam4kube.IP(ip))
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
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
			if errorCounter != nil {
				errorCounter.Inc()
			}
			logger.Error("Internal error", zap.Error(err))
		}
	}
}
