package app

import (
	"context"
	"crypto/tls"
	"flag"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ash2k/iam4kube/pkg/amazon"
	"github.com/ash2k/iam4kube/pkg/core"
	"github.com/ash2k/iam4kube/pkg/kube"
	"github.com/ash2k/iam4kube/pkg/meta"
	"github.com/ash2k/iam4kube/pkg/util/logz"
	"github.com/ash2k/stager"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	core_v1inf "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	defaultResyncPeriod      = 20 * time.Minute
	defaultStsRateLimit      = 10
	defaultStsBurstRateLimit = 20
)

type App struct {
	Logger          *zap.Logger
	RestConfig      *rest.Config
	ResyncPeriod    time.Duration
	StsRateLimit    float64
	StsRateBurst    int
	ListenOn        string
	MetricsListenOn string
}

func (a *App) Run(ctx context.Context) (retErr error) {
	defer a.Logger.Sync()

	// Clients
	clientset, err := kubernetes.NewForConfig(a.RestConfig)
	if err != nil {
		return err
	}

	// Metrics
	registry := prometheus.NewPedanticRegistry()
	metricsSrv, err := NewMetrics(a.MetricsListenOn, registry)
	if err != nil {
		return err
	}

	// Informers
	svcAccInf := core_v1inf.NewServiceAccountInformer(clientset, meta_v1.NamespaceAll, a.ResyncPeriod, cache.Indexers{})
	podsInf := core_v1inf.NewPodInformer(clientset, meta_v1.NamespaceAll, a.ResyncPeriod, cache.Indexers{})

	// Kroler
	kroler, err := kube.NewKroler(a.Logger, podsInf, svcAccInf)
	if err != nil {
		return err
	}

	// Kloud
	stsClient, err := stsService()
	if err != nil {
		return err
	}
	kloud := &amazon.Kloud{
		Assumer: stsClient,
	}

	// Prefetcher
	prefetcher, err := core.NewCredentialsPrefetcher(a.Logger, kloud, registry,
		rate.NewLimiter(rate.Limit(a.StsRateLimit), a.StsRateBurst), int(a.StsRateLimit))
	if err != nil {
		return err
	}
	core.NotifyPrefetcher(a.Logger, prefetcher, svcAccInf)

	// Kernel
	kernel := &core.Kernel{
		Kloud:  prefetcher,
		Kroler: kroler,
	}

	// Meta server
	metaSrv, err := meta.NewServer(a.Logger, a.ListenOn, kernel, registry)
	if err != nil {
		return err
	}

	// ==== Lets start it all ====

	var metricsErr error
	defer func() {
		if retErr == nil {
			retErr = metricsErr
		}
	}()

	// Stager will perform ordered, graceful shutdown. Stage by stage in reverse startup order.
	stgr := stager.New()
	defer stgr.Shutdown()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stage := stgr.NextStage()
	stage.StartWithContext(prefetcher.Run) // prefetcher starts first, then informers. Shutdown is in reverse order.
	stage.StartWithContext(func(metricsCtx context.Context) {
		defer cancel() // if metricsSrv fails to start it signals the whole program that it should shut down
		metricsErr = metricsSrv.Run(metricsCtx)
	})

	stage = stgr.NextStage()
	stage.StartWithChannel(svcAccInf.Run)
	stage.StartWithChannel(podsInf.Run)

	a.Logger.Debug("Waiting for informers to sync")
	if !cache.WaitForCacheSync(ctx.Done(), svcAccInf.HasSynced, podsInf.HasSynced) {
		return nil
	}
	a.Logger.Debug("Informers synced")

	return metaSrv.Run(ctx)
}

// CancelOnInterrupt calls f when os.Interrupt or SIGTERM is received.
// It ignores subsequent interrupts on purpose - program should exit correctly after the first signal.
func CancelOnInterrupt(ctx context.Context, f context.CancelFunc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-ctx.Done():
		case <-c:
			f()
		}
	}()
}

func NewFromFlags(flagset *flag.FlagSet, arguments []string) (*App, error) {
	a := App{}
	flagset.DurationVar(&a.ResyncPeriod, "resync-period", defaultResyncPeriod, "Resync period for informers.")
	pprofAddr := flagset.String("pprof-listen-on", "", "Address for pprof to listen on.")
	flagset.StringVar(&a.ListenOn, "listen-on", ":8080", "Address for metadata proxy to listen on.")
	flagset.StringVar(&a.MetricsListenOn, "metrics-listen-on", ":9090", "Address for Prometheus metrics server to listen on.")
	flagset.Float64Var(&a.StsRateLimit, "sts-rate-limit", defaultStsRateLimit, "Rate limit for STS AssumeRole calls. N per second.")
	flagset.IntVar(&a.StsRateBurst, "sts-rate-burst", defaultStsBurstRateLimit, "Rate burst for STS AssumeRole calls. N per second.")
	logEncoding := flagset.String("log-encoding", "json", `Sets the logger's encoding. Valid values are "json" and "console".`)
	loggingLevel := flagset.String("log-level", "info", `Sets the logger's output level.`)

	err := flagset.Parse(arguments)
	if err != nil {
		return nil, err
	}

	a.RestConfig, err = rest.InClusterConfig()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	a.RestConfig.UserAgent = "iam4kube"

	a.Logger = logz.Logger(*loggingLevel, *logEncoding, os.Stderr)

	if *pprofAddr != "" {
		go func() {
			err := http.ListenAndServe(*pprofAddr, nil)
			a.Logger.Fatal("pprof server failed", zap.Error(err))
		}()
	}
	return &a, nil
}

func stsService() (*sts.STS, error) {
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSHandshakeTimeout: 3 * time.Second,
		TLSClientConfig: &tls.Config{
			// Can't use SSLv3 because of POODLE and BEAST
			// Can't use TLSv1.0 because of POODLE and BEAST using CBC cipher
			// Can't use TLSv1.1 because of RC4 cipher usage
			MinVersion: tls.VersionTLS12,
		},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:    50,
		IdleConnTimeout: 1 * time.Minute,
	}
	sharedConfig := aws.NewConfig().
		WithHTTPClient(&http.Client{
			Transport: transport,
			Timeout:   50 * time.Second,
		})
	metadataSession, err := session.NewSession(sharedConfig)
	if err != nil {
		return nil, errors.Wrap(err, "error creating Metadata session")
	}
	metadata := ec2metadata.New(metadataSession)
	region, err := metadata.Region()
	if err != nil {
		return nil, errors.Wrap(err, "error getting AWS region")
	}
	stsConfig := sharedConfig.Copy().
		// Use region-local STS endpoint to reduce latency
		// https://docs.aws.amazon.com/general/latest/gr/rande.html#sts_region
		// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html
		WithRegion(region)
	stsSession, err := session.NewSession(stsConfig)
	if err != nil {
		return nil, errors.Wrap(err, "error creating STS session")
	}
	return sts.New(stsSession), nil
}
