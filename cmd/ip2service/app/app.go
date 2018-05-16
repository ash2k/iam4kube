package app

import (
	"context"
	"flag"
	"math"
	"net"
	"os"
	"time"

	"github.com/ash2k/iam4kube/pkg/ip2service"
	"github.com/ash2k/iam4kube/pkg/util/logz"
	"github.com/ash2k/stager"
	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	core_v1inf "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	defaultResyncPeriod = 20 * time.Minute
	ipTablesChainPrefix = "IP2SVC"
)

type PrometheusRegistry interface {
	prometheus.Registerer
	prometheus.Gatherer
}

type App struct {
	Logger             *zap.Logger
	RestConfig         *rest.Config
	PrometheusRegistry PrometheusRegistry
	ServiceNamespace   string
	ServiceName        string
	ServiceTargetPort  int32
	InterceptIP        string
	InterceptPort      int32
	ResyncPeriod       time.Duration
	AuxListenOn        string
	Debug              bool
}

func (a *App) Run(ctx context.Context) error {
	defer a.Logger.Sync()

	ipt, err := iptables.New()
	if err != nil {
		return err
	}

	// Clients
	mainClient, err := kubernetes.NewForConfig(a.RestConfig)
	if err != nil {
		return err
	}

	// Informers
	endpointsInf := core_v1inf.NewEndpointsInformer(mainClient, a.ServiceNamespace, a.ResyncPeriod, cache.Indexers{})
	endpointsInf.AddEventHandler(&ip2service.EndpointsEventHandler{
		Logger:            a.Logger,
		ServiceName:       a.ServiceName,
		ServiceTargetPort: a.ServiceTargetPort,
		Router: &ip2service.Router{
			Logger:        a.Logger,
			Prefix:        ipTablesChainPrefix,
			InterceptIP:   a.InterceptIP,
			InterceptPort: a.InterceptPort,
			IPTables:      ipt,
		},
	})

	// Auxiliary server
	auxSrv := &AuxServer{
		Logger:   a.Logger,
		Addr:     a.AuxListenOn,
		Gatherer: a.PrometheusRegistry,
		Debug:    a.Debug,
	}

	// ==== Lets start it all ====

	// Stager will perform ordered, graceful shutdown. Stage by stage in reverse startup order.
	stgr := stager.New()
	defer stgr.Shutdown()

	stage := stgr.NextStage()
	stage.StartWithChannel(endpointsInf.Run)

	return auxSrv.Run(ctx)
}

func NewFromFlags(flagset *flag.FlagSet, arguments []string) (*App, error) {
	a := App{}
	flagset.DurationVar(&a.ResyncPeriod, "resync-period", defaultResyncPeriod, "Resync period for informers.")
	flagset.BoolVar(&a.Debug, "debug", false, "Enables pprof endpoint.")
	flagset.StringVar(&a.AuxListenOn, "aux-listen-on", ":9090", "Auxiliary address to listen on. Used for Prometheus metrics server and pprof endpoints.")

	flagset.StringVar(&a.ServiceNamespace, "service-namespace", meta_v1.NamespaceDefault, "Namespace of the Service object to route traffic to.")
	flagset.StringVar(&a.ServiceName, "service-name", "iam4kube", "Name of the Service object to route traffic to.")
	serviceTargetPort := flagset.Int("service-target-port", 8080, "Target port of the Service object to route traffic to.")
	flagset.StringVar(&a.InterceptIP, "intercept-ip", "19", "IP address to intercept traffic for.")
	interceptPort := flagset.Int("intercept-port", 80, "Port on the IP to intercept traffic for.")

	logEncoding := flagset.String("log-encoding", "json", `Sets the logger's encoding. Valid values are "json" and "console".`)
	loggingLevel := flagset.String("log-level", "info", `Sets the logger's output level.`)

	err := flagset.Parse(arguments)
	if err != nil {
		return nil, err
	}

	if a.ServiceNamespace == "" {
		return nil, errors.New("Service namespace must be specified")
	}
	if a.ServiceName == "" {
		return nil, errors.New("Service name must be specified")
	}
	if !isValidPort(*serviceTargetPort) {
		return nil, errors.New("Service target port is invalid")
	}
	a.ServiceTargetPort = int32(*serviceTargetPort)

	if !isValidIP(a.InterceptIP) {
		return nil, errors.New("Intercept ip is invalid")
	}
	if !isValidPort(*interceptPort) {
		return nil, errors.New("Intercept port is invalid")
	}
	a.InterceptPort = int32(*interceptPort)

	a.RestConfig, err = rest.InClusterConfig()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	a.RestConfig.UserAgent = "ip2service"

	a.Logger = logz.Logger(*loggingLevel, *logEncoding, os.Stderr)

	// Metrics
	a.PrometheusRegistry = prometheus.NewPedanticRegistry()
	err = a.PrometheusRegistry.Register(prometheus.NewProcessCollector(os.Getpid(), ""))
	if err != nil {
		return nil, err
	}
	err = a.PrometheusRegistry.Register(prometheus.NewGoCollector())
	if err != nil {
		return nil, err
	}

	return &a, nil
}

func isValidPort(port int) bool {
	return port > 0 && port <= math.MaxUint16
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}
