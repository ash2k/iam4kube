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
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	core_v1inf "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	core_v1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
)

const (
	defaultResyncPeriod      = 20 * time.Minute
	defaultStsRateLimit      = 10
	defaultStsBurstRateLimit = 20
)

type App struct {
	Logger       *zap.Logger
	RestConfig   *rest.Config
	ResyncPeriod time.Duration
	StsRateLimit float64
	StsRateBurst int
	ListenOn     string
	AuxListenOn  string
	EnableDebug  bool
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

	// Informers
	svcAccInf := core_v1inf.NewServiceAccountInformer(clientset, meta_v1.NamespaceAll, a.ResyncPeriod, cache.Indexers{})
	podsInf := core_v1inf.NewPodInformer(clientset, meta_v1.NamespaceAll, a.ResyncPeriod, cache.Indexers{})

	// Kroler
	kroler, err := kube.NewKroler(a.Logger, podsInf, svcAccInf)
	if err != nil {
		return err
	}

	// Kloud
	awsConfig, az, err := initAws()
	if err != nil {
		return errors.Wrap(err, "failed to init AWS config")
	}
	stsSession, err := session.NewSession(awsConfig)
	if err != nil {
		return errors.Wrap(err, "error creating STS session")
	}
	kloud := &amazon.Kloud{
		Assumer: sts.New(stsSession),
	}

	// Prefetcher
	prefetcher, err := core.NewCredentialsPrefetcher(a.Logger, kloud, registry,
		rate.NewLimiter(rate.Limit(a.StsRateLimit), a.StsRateBurst), int(a.StsRateLimit))
	if err != nil {
		return err
	}
	svcAccInf.AddEventHandler(&core.PrefetcherNotifier{
		Logger:     a.Logger,
		Prefetcher: prefetcher,
	})

	// Auxiliary server
	var prefetcherDebug Prefetcher
	if a.EnableDebug {
		prefetcherDebug = prefetcher
	}
	auxSrv, err := NewAuxServer(a.AuxListenOn, registry, prefetcherDebug)
	if err != nil {
		return err
	}

	// Kernel
	kernel := &core.Kernel{
		Kloud:  prefetcher,
		Kroler: kroler,
	}

	// Events
	scheme := runtime.NewScheme()
	err = core_v1.SchemeBuilder.AddToScheme(scheme)
	if err != nil {
		return errors.WithStack(err)
	}

	eventBroadcaster := record.NewBroadcaster()
	loggingWatch := eventBroadcaster.StartLogging(a.Logger.Sugar().Debugf)
	defer loggingWatch.Stop()
	recordingWatch := eventBroadcaster.StartRecordingToSink(&core_v1client.EventSinkImpl{Interface: clientset.CoreV1().Events("")})
	defer recordingWatch.Stop()
	recorder := eventBroadcaster.NewRecorder(scheme, core_v1.EventSource{Component: "iam4kube"})

	// Meta server
	metaSrv, err := meta.NewServer(a.Logger, a.ListenOn, az, kernel, registry, recorder)
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
	stage.StartWithContext(kroler.Run)     // Kroler must start before informers and stop after they are stopped
	stage.StartWithContext(prefetcher.Run) // prefetcher starts first, then informers. Shutdown is in reverse order.
	stage.StartWithContext(func(metricsCtx context.Context) {
		defer cancel() // if auxSrv fails to start it signals the whole program that it should shut down
		metricsErr = auxSrv.Run(metricsCtx)
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
	flagset.BoolVar(&a.EnableDebug, "debug", false, "Enables pprof and prefetcher dump endpoints.")
	flagset.StringVar(&a.ListenOn, "listen-on", ":8080", "Address for metadata proxy to listen on.")
	flagset.StringVar(&a.AuxListenOn, "aux-listen-on", ":9090", "Auxiliary address to listen on. Used for Prometheus metrics server, pprof and prefetcher dump endpoints.")
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

	return &a, nil
}

func initAws() (*aws.Config, string, error) {
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
		return nil, "", errors.Wrap(err, "error creating Metadata session")
	}
	metadata := ec2metadata.New(metadataSession)
	az, err := metadata.GetMetadata("placement/availability-zone")
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to get availability zone")
	}
	// Use region-local STS endpoint to reduce latency
	// https://docs.aws.amazon.com/general/latest/gr/rande.html#sts_region
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html
	sharedConfig = sharedConfig.WithRegion(az[:len(az)-1])
	return sharedConfig, az, nil
}
