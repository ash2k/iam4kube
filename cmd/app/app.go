package app

import (
	"context"
	"crypto/tls"
	"flag"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ash2k/iam4kube/pkg/amazon"
	"github.com/ash2k/iam4kube/pkg/core"
	"github.com/ash2k/iam4kube/pkg/kube"
	"github.com/ash2k/iam4kube/pkg/meta"

	"github.com/ash2k/stager"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
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
	ListenOn     string
}

func (a *App) Run(ctx context.Context) error {
	defer a.Logger.Sync()

	// Clients
	clientset, err := kubernetes.NewForConfig(a.RestConfig)
	if err != nil {
		return err
	}

	// Informers
	svcAccInf := core_v1inf.NewServiceAccountInformer(clientset, meta_v1.NamespaceAll, a.ResyncPeriod, cache.Indexers{})
	podsInf := core_v1inf.NewPodInformer(clientset, meta_v1.NamespaceAll, a.ResyncPeriod, cache.Indexers{})

	// Kroler
	kroler, err := kube.NewKroler(podsInf, svcAccInf)
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

	// Kernel
	kernel := &core.Kernel{
		Kloud:  kloud,
		Kroler: kroler,
	}

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

	s := meta.Server{
		Logger:      a.Logger,
		Addr:        a.ListenOn,
		MetadataURL: a.MetadataURL,
		Kernel:      kernel,
	}
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
	pprofAddr := flagset.String("pprof-listen-on", "", "Address for pprof to listen on.")
	flagset.StringVar(&a.ListenOn, "listen-on", ":8080", "Address for metadata proxy to listen on.")
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
		return nil, errors.WithStack(err)
	}
	a.MetadataURL = *metaUrl

	a.RestConfig, err = rest.InClusterConfig()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	a.RestConfig.UserAgent = "iam4kube"

	a.Logger, err = zapConfig.Build()
	if err != nil {
		return nil, errors.WithStack(err)
	}

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
		WithCredentials(credentials.NewChainCredentials(
			[]credentials.Provider{
				&credentials.EnvProvider{},
				&ec2rolecreds.EC2RoleProvider{
					Client:       metadata,
					ExpiryWindow: 10 * time.Minute,
				},
				&credentials.SharedCredentialsProvider{},
			})).
		WithRegion(region)
	stsSession, err := session.NewSession(stsConfig)
	if err != nil {
		return nil, errors.Wrap(err, "error creating STS session")
	}
	return sts.New(stsSession), nil
}
