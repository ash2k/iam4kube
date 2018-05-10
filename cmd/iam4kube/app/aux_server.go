package app

import (
	"context"
	"net/http"
	"net/http/pprof"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/iam4kube/pkg/core"
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

type Registry interface {
	prometheus.Gatherer
	prometheus.Registerer
}

type Prefetcher interface {
	Inspect(func(map[core.IamRoleKey]core.CacheEntry))
}

type AuxServer struct {
	Logger         *zap.Logger
	Addr           string // TCP address to listen on, ":http" if empty
	Gatherer       prometheus.Gatherer
	Prefetcher     Prefetcher
	IsReady        func() bool
	Debug          bool
	readyTriggered int32 // atomic access only, 1 if IsReady() has returned true
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
	router.Use(middleware.Timeout(defaultMaxRequestDuration), util.Iam4kubeServerHeader())
	router.NotFound(util.PageNotFound)

	router.Method(http.MethodGet, "/metrics", promhttp.HandlerFor(a.Gatherer, promhttp.HandlerOpts{}))
	router.Get("/healthz/ping", func(_ http.ResponseWriter, _ *http.Request) {})
	router.Get("/healthz/ready", a.readiness)

	if a.Debug {
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

func (a *AuxServer) readiness(w http.ResponseWriter, r *http.Request) {
	readyTriggered := atomic.LoadInt32(&a.readyTriggered)
	if readyTriggered != 0 {
		// Always return ready after signaling ready for the first time
		return
	}
	if !a.IsReady() {
		// Coffee is not ready yet
		a.Logger.Debug("Readiness - not ready yet")
		w.WriteHeader(http.StatusTeapot)
		return
	}
	// Ready!
	a.Logger.Debug("Readiness - ready")
	atomic.StoreInt32(&a.readyTriggered, 1)
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
	a.Prefetcher.Inspect(func(cache map[core.IamRoleKey]core.CacheEntry) {
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
