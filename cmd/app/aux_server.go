package app

import (
	"context"
	"net/http"
	"net/http/pprof"
	"os"
	"sync"
	"time"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/iam4kube/pkg/core"
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

type Prefetcher interface {
	Inspect(func(map[core.IamRoleKey]core.CacheEntry))
}

type AuxServer struct {
	addr       string // TCP address to listen on, ":http" if empty
	gatherer   prometheus.Gatherer
	prefetcher Prefetcher
}

func NewAuxServer(addr string, registry Registry, prefetcher Prefetcher) (*AuxServer, error) {
	err := registry.Register(prometheus.NewProcessCollector(os.Getpid(), ""))
	if err != nil {
		return nil, err
	}
	err = registry.Register(prometheus.NewGoCollector())
	if err != nil {
		return nil, err
	}
	return &AuxServer{
		addr:       addr,
		gatherer:   registry,
		prefetcher: prefetcher,
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

	if a.prefetcher != nil {
		// Enable debug endpoints
		router.HandleFunc("/debug/pprof/", pprof.Index)
		router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		router.HandleFunc("/debug/pprof/profile", pprof.Profile)
		router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		router.HandleFunc("/debug/pprof/trace", pprof.Trace)
		router.Get("/prefetcher/dump", a.prefetcherDump)
	}

	return router
}

type dumpCredentials struct {
	LastUpdated time.Time
	Expiration  time.Time
}

type dumpEntry struct {
	Role               iam4kube.IamRole
	Creds              dumpCredentials
	TimesAddedCounter  int
	Awaiting           int
	HasCreds           bool
	EnqueuedForRefresh bool
}

func (a *AuxServer) prefetcherDump(w http.ResponseWriter, r *http.Request) {
	var result map[string]dumpEntry
	var wg sync.WaitGroup
	wg.Add(1)
	a.prefetcher.Inspect(func(cache map[core.IamRoleKey]core.CacheEntry) {
		defer wg.Done()
		result = make(map[string]dumpEntry, len(cache))
		for key, entry := range cache {
			result[key.String()] = dumpEntry{
				Role: entry.Role,
				Creds: dumpCredentials{
					LastUpdated: entry.Creds.LastUpdated,
					Expiration:  entry.Creds.Expiration,
				},
				TimesAddedCounter:  entry.TimesAddedCounter,
				Awaiting:           len(entry.Awaiting),
				HasCreds:           entry.HasCreds,
				EnqueuedForRefresh: entry.EnqueuedForRefresh,
			}
		}
	})
	wg.Wait()
	// Write output from request goroutine, not from prefetcher main goroutine to avoid blocking it
	util.WriteJson(w, result)
}
