package app

import (
	"context"
	"net/http"
	"net/http/pprof"
	"os"
	"time"

	"github.com/ash2k/iam4kube/pkg/util"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	defaultMaxRequestDuration = 15 * time.Second
	shutdownTimeout           = defaultMaxRequestDuration
	readTimeout               = 1 * time.Second
	writeTimeout              = defaultMaxRequestDuration
	idleTimeout               = 1 * time.Minute
)

type Registry interface {
	prometheus.Gatherer
	prometheus.Registerer
}

type AuxServer struct {
	addr        string // TCP address to listen on, ":http" if empty
	gatherer    prometheus.Gatherer
	enablePprof bool
}

func NewAuxServer(addr string, registry Registry, enablePprof bool) (*AuxServer, error) {
	err := registry.Register(prometheus.NewProcessCollector(os.Getpid(), ""))
	if err != nil {
		return nil, err
	}
	err = registry.Register(prometheus.NewGoCollector())
	if err != nil {
		return nil, err
	}
	return &AuxServer{
		addr:        addr,
		gatherer:    registry,
		enablePprof: enablePprof,
	}, nil
}

func (a *AuxServer) Run(ctx context.Context) error {
	srv := http.Server{
		Addr:         a.addr,
		Handler:      a.constructHandler(),
		WriteTimeout: writeTimeout,
		ReadTimeout:  readTimeout,
		IdleTimeout:  idleTimeout,
	}
	return util.StartStopServer(ctx, &srv, shutdownTimeout)
}

func (a *AuxServer) constructHandler() *chi.Mux {
	router := chi.NewRouter()
	router.Use(middleware.Timeout(defaultMaxRequestDuration), util.SetServerHeader)
	router.NotFound(util.PageNotFound)

	router.Method(http.MethodGet, "/metrics", promhttp.HandlerFor(a.gatherer, promhttp.HandlerOpts{}))
	router.Get("/healthz/ping", func(_ http.ResponseWriter, _ *http.Request) {})

	if a.enablePprof {
		router.HandleFunc("/debug/pprof/", pprof.Index)
		router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		router.HandleFunc("/debug/pprof/profile", pprof.Profile)
		router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		router.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	return router
}
