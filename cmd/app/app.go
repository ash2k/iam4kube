package app

import (
	"context"
	"flag"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ash2k/iam4kube/pkg/server"

	"github.com/ash2k/stager"
	"go.uber.org/zap"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	core_v1inf "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	defaultResyncPeriod = 20 * time.Minute
)

type App struct {
	Logger       *zap.Logger
	RestConfig   *rest.Config
	ResyncPeriod time.Duration
	MetadataURL  url.URL // URL of the metadata api endpoint
}

func (a *App) Run(ctx context.Context) error {
	defer a.Logger.Sync()

	// Clients
	clientset, err := kubernetes.NewForConfig(a.RestConfig)
	if err != nil {
		return err
	}

	// Informers
	svcAccInf := core_v1inf.NewServiceAccountInformer(clientset, meta_v1.NamespaceAll, defaultResyncPeriod, cache.Indexers{})
	podsInf := core_v1inf.NewPodInformer(clientset, meta_v1.NamespaceAll, defaultResyncPeriod, cache.Indexers{})

	// Controller

	// Stager will perform ordered, graceful shutdown
	stgr := stager.New()
	defer stgr.Shutdown()

	stage := stgr.NextStage()
	stage.StartWithChannel(svcAccInf.Run)
	stage.StartWithChannel(podsInf.Run)

	a.Logger.Debug("Waiting for informers to sync")
	if !cache.WaitForCacheSync(ctx.Done(), svcAccInf.HasSynced, podsInf.HasSynced) {
		return ctx.Err()
	}

	s := server.Server{}
	return s.Run(ctx)
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
	zapConfig := zap.NewProductionConfig()
	flagset.DurationVar(&a.ResyncPeriod, "resync-period", defaultResyncPeriod, "Resync period for informers.")
	pprofAddr := flagset.String("pprof-address", "", "Address for pprof to listen on.")
	metadataUrl := flagset.String("metadata-url", "http://169.254.169.254", "URL of the metadata service endpoint.")

	flagset.StringVar(&zapConfig.Encoding, "log-encoding", "json", `Sets the logger's encoding. Valid values are "json" and "console".`)
	flagset.BoolVar(&zapConfig.DisableCaller, "log-disable-caller", true, `Stops annotating logs with the calling function's file name and line number.`)
	flagset.BoolVar(&zapConfig.DisableStacktrace, "log-disable-stacktrace", true, `Completely disables automatic stacktrace capturing. `+
		`Stacktraces are captured for ErrorLevel and above if set to false.`)

	err := flagset.Parse(arguments)
	if err != nil {
		return nil, err
	}

	metaUrl, err := url.Parse(*metadataUrl)
	if err != nil {
		return nil, err
	}
	a.MetadataURL = *metaUrl

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	config.UserAgent = "iam4kube"
	a.RestConfig = config

	a.Logger, err = zapConfig.Build()
	if err != nil {
		return nil, err
	}

	if *pprofAddr != "" {
		go func() {
			err := http.ListenAndServe(*pprofAddr, nil)
			a.Logger.Fatal("pprof server failed", zap.Error(err))
		}()
	}
	return &a, nil
}
