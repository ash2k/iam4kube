package app

import (
	"context"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/ash2k/iam4kube/pkg/util"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

const (
	defaultMaxRequestDuration = 15 * time.Second
	shutdownTimeout           = defaultMaxRequestDuration
	readTimeout               = 1 * time.Second
	writeTimeout              = defaultMaxRequestDuration
	idleTimeout               = 1 * time.Minute
)

type AuxServer struct {
	Logger   *zap.Logger
	Addr     string // TCP address to listen on, ":http" if empty
	Gatherer prometheus.Gatherer
	Debug    bool
}

func (a *AuxServer) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:         a.Addr,
		Handler:      a.constructHandler(),
		WriteTimeout: writeTimeout,
		ReadTimeout:  readTimeout,
		IdleTimeout:  idleTimeout,
	}
	return util.StartStopServer(ctx, srv, shutdownTimeout)
}

func (a *AuxServer) constructHandler() *chi.Mux {
	router := chi.NewRouter()
	router.Use(middleware.Timeout(defaultMaxRequestDuration), util.SetServerHeader("ip2service"))
	router.NotFound(util.PageNotFound)

	router.Method(http.MethodGet, "/metrics", promhttp.HandlerFor(a.Gatherer, promhttp.HandlerOpts{}))
	router.Get("/healthz/ping", func(_ http.ResponseWriter, _ *http.Request) {})

	if a.Debug {
		// Enable debug endpoints
		router.HandleFunc("/debug/pprof/", pprof.Index)
		router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		router.HandleFunc("/debug/pprof/profile", pprof.Profile)
		router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		router.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	return router
}
