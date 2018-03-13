package app

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/ash2k/iam4kube/pkg/util"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	defaultMaxRequestDuration = 5 * time.Second
	shutdownTimeout           = defaultMaxRequestDuration
	readTimeout               = 1 * time.Second
	writeTimeout              = 1 * time.Second
	idleTimeout               = 1 * time.Minute
)

type Registry interface {
	prometheus.Gatherer
	prometheus.Registerer
}

type Metrics struct {
	addr     string // TCP address to listen on, ":http" if empty
	gatherer prometheus.Gatherer
}

func NewMetrics(addr string, registry Registry) (*Metrics, error) {
	err := registry.Register(prometheus.NewProcessCollector(os.Getpid(), ""))
	if err != nil {
		return nil, err
	}
	err = registry.Register(prometheus.NewGoCollector())
	if err != nil {
		return nil, err
	}
	return &Metrics{
		addr:     addr,
		gatherer: registry,
	}, nil
}

func (s *Metrics) Run(ctx context.Context) error {
	srv := http.Server{
		Addr:         s.addr,
		Handler:      s.constructHandler(),
		WriteTimeout: writeTimeout,
		ReadTimeout:  readTimeout,
		IdleTimeout:  idleTimeout,
	}
	return util.StartStopServer(ctx, &srv, shutdownTimeout)
}

func (s *Metrics) constructHandler() *chi.Mux {
	router := chi.NewRouter()
	router.Use(middleware.Timeout(defaultMaxRequestDuration), util.SetServerHeader)
	router.NotFound(util.PageNotFound)

	router.Method(http.MethodGet, "/metrics", promhttp.HandlerFor(s.gatherer, promhttp.HandlerOpts{}))

	return router
}
