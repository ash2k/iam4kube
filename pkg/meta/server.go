package meta

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/iam4kube/pkg/util"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
)

const (
	defaultMaxRequestDuration = 15 * time.Second
	shutdownTimeout           = defaultMaxRequestDuration
	readTimeout               = 1 * time.Second
	writeTimeout              = defaultMaxRequestDuration
	idleTimeout               = 1 * time.Minute

	iso8601Format = "2006-01-02T15:04:05Z"

	eventReasonInvalidRole      = "InvalidRole"
	eventReasonNoRole           = "NoRole"
	eventReasonRoleFound        = "RoleFound"
	eventReasonNoCredentials    = "NoCredentials"
	eventReasonCredentialsFound = "CredentialsFound"
)

type Kernel interface {
	// RoleForIp fetches the IAM role that is supposed to be used by a Pod with the provided IP.
	// Returns nil if no IAM role is assigned.
	RoleForIp(context.Context, iam4kube.IP) (*core_v1.Pod, *iam4kube.IamRole, error)
	// CredentialsForIp fetches credentials for the IAM role that is assigned to a Pod with the provided IP.
	// Returns nil if no IAM role is assigned.
	CredentialsForIp(context.Context, iam4kube.IP, string /*role*/) (*core_v1.Pod, *iam4kube.Credentials, error)
}

// Example https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials
// Struct is mimicking ec2RoleCredRespBody struct from github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds/ec2_role_provider.go
type jsonCreds struct {
	// Success State
	LastUpdated     string
	Type            string
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string
	SessionToken    string `json:"Token"`
	Expiration      string

	// Error state
	Code    string
	Message string `json:"Message,omitempty"`
}

type Server struct {
	logger               *zap.Logger
	addr                 string // TCP address to listen on, ":http" if empty
	availabilityZone     string
	kernel               Kernel
	recorder             record.EventRecorder
	getRoleCount         prometheus.Counter
	getRoleSuccessCount  prometheus.Counter
	getRoleErrorCount    prometheus.Counter
	getRoleLatency       prometheus.Histogram
	getCredsCount        prometheus.Counter
	getCredsSuccessCount prometheus.Counter
	getCredsErrorCount   prometheus.Counter
	getCredsLatency      prometheus.Histogram
}

func NewServer(logger *zap.Logger, addr, availabilityZone string, kernel Kernel, registry prometheus.Registerer,
	recorder record.EventRecorder) (*Server, error) {
	getRoleCount := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "iam4kube",
		Subsystem: "meta",
		Name:      "get_role_count",
		Help:      "Number of times available role name was requested",
	})
	getRoleSuccessCount := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "iam4kube",
		Subsystem: "meta",
		Name:      "get_role_success_count",
		Help:      "Number of times available role name was successfully returned",
	})
	getRoleErrorCount := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "iam4kube",
		Subsystem: "meta",
		Name:      "get_role_error_count",
		Help:      "Number of times available role name lookup failed",
	})
	getRoleLatency := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "iam4kube",
		Subsystem: "meta",
		Name:      "get_role_seconds",
		Help:      "Histogram measuring the time it took to process a get role request",
	})
	getCredsCount := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "iam4kube",
		Subsystem: "meta",
		Name:      "get_creds_count",
		Help:      "Number of times credentials were requested",
	})
	getCredsSuccessCount := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "iam4kube",
		Subsystem: "meta",
		Name:      "get_creds_success_count",
		Help:      "Number of times credentials were successfully returned",
	})
	getCredsErrorCount := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "iam4kube",
		Subsystem: "meta",
		Name:      "get_creds_error_count",
		Help:      "Number of times credentials lookup failed",
	})
	getCredsLatency := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "iam4kube",
		Subsystem: "meta",
		Name:      "get_creds_seconds",
		Help:      "Histogram measuring the time it took to process a get credentials request",
	})

	allMetrics := []prometheus.Collector{
		getRoleCount, getRoleSuccessCount, getRoleErrorCount, getRoleLatency,
		getCredsCount, getCredsSuccessCount, getCredsErrorCount, getCredsLatency,
	}
	if err := util.RegisterAll(registry, allMetrics...); err != nil {
		return nil, errors.WithStack(err)
	}
	return &Server{
		logger:               logger,
		addr:                 addr,
		availabilityZone:     availabilityZone,
		kernel:               kernel,
		recorder:             recorder,
		getRoleCount:         getRoleCount,
		getRoleSuccessCount:  getRoleSuccessCount,
		getRoleErrorCount:    getRoleErrorCount,
		getRoleLatency:       getRoleLatency,
		getCredsCount:        getCredsCount,
		getCredsSuccessCount: getCredsSuccessCount,
		getCredsErrorCount:   getCredsErrorCount,
		getCredsLatency:      getCredsLatency,
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:         s.addr,
		Handler:      s.constructHandler(),
		WriteTimeout: writeTimeout,
		ReadTimeout:  readTimeout,
		IdleTimeout:  idleTimeout,
	}
	return util.StartStopServer(ctx, srv, shutdownTimeout)
}

func (s *Server) constructHandler() *chi.Mux {
	router := chi.NewRouter()
	router.Use(
		middleware.Timeout(defaultMaxRequestDuration),
		util.Iam4kubeServerHeader(),
		util.PerRequestContextLogger(s.logger),
		util.AddIpToContextAndLogger,
	)

	router.NotFound(util.PageNotFound)

	// === Support for IAM credentials ===
	getRoleHandler := util.TimeRequest(s.getRoleLatency, util.ErrorRenderer(s.getRoleErrorCount, s.getRole))
	getCredsHandler := util.TimeRequest(s.getCredsLatency, util.ErrorRenderer(s.getCredsErrorCount, s.getCredentials))
	// Trailing slash support https://github.com/jtblin/kube2iam/pull/119
	router.Get("/{version}/meta-data/iam/security-credentials", getRoleHandler)
	router.Get("/{version}/meta-data/iam/security-credentials/", getRoleHandler)
	router.Get("/{version}/meta-data/iam/security-credentials/{role:.+}", getCredsHandler)

	// === Support fetching AZ/region using metadata service ===
	// Note that actual AZ may be a different AZ - host making the request does not necessarily reside in the same
	// AZ as this instance of iam4kube
	router.Get("/{version}/meta-data/placement/availability-zone", s.getAz)

	// Everything else will get a 404 and this is by design. Tomorrow AWS might add an endpoint that exposes some
	// sensitive information and that would create a security hole. Also there is plenty of information
	// that would most likely be incorrect for the container because it might be running on a different host.
	// E.g. ami id, host id, instance profile, instance type and so on.

	// If you are reading this and have a valid use case - create an issue please.

	return router
}

func (s *Server) getRole(w http.ResponseWriter, r *http.Request) error {
	s.getRoleCount.Inc()
	ip := util.IpFromContext(r.Context())
	pod, role, err := s.kernel.RoleForIp(r.Context(), ip)
	if err != nil {
		return errors.Wrap(err, "failed to get IAM role for ip")
	}
	var response []byte
	if role == nil {
		s.recorder.Event(pod, core_v1.EventTypeWarning, eventReasonNoRole, "No IAM role defined for ServiceAccount used by this Pod")
	} else {
		roleName, err := util.RoleNameFromRoleArn(role.Arn)
		if err != nil {
			err = errors.Wrapf(err, "failed to extract IAM role name from ARN %q", role.Arn)
			s.recorder.Event(pod, core_v1.EventTypeWarning, eventReasonInvalidRole, err.Error())
			return err
		}
		response = []byte(roleName)
		s.getRoleSuccessCount.Inc()
		s.recorder.Event(pod, core_v1.EventTypeNormal, eventReasonRoleFound, "IAM role found")
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", strconv.Itoa(len(response))) // To ensure we don't send a chunked response
	w.Write(response)
	return nil
}

func (s *Server) getCredentials(w http.ResponseWriter, r *http.Request) error {
	s.getCredsCount.Inc()
	ip := util.IpFromContext(r.Context())
	role := chi.URLParam(r, "role")
	pod, creds, err := s.kernel.CredentialsForIp(r.Context(), ip, role)
	if err != nil {
		err = errors.Wrap(err, "failed to get credentials for ip")
		if pod != nil {
			s.recorder.Event(pod, core_v1.EventTypeWarning, eventReasonNoCredentials, err.Error())
		}
		return err
	}
	if creds == nil {
		s.recorder.Event(pod, core_v1.EventTypeWarning, eventReasonNoCredentials, "No IAM credentials")
		w.WriteHeader(http.StatusNotFound)
		return nil
	}
	s.recorder.Event(pod, core_v1.EventTypeNormal, eventReasonCredentialsFound, "IAM credentials found")
	return util.WriteJson(w, &jsonCreds{
		Code:            "Success",
		LastUpdated:     creds.LastUpdated.Format(iso8601Format),
		Type:            "AWS-HMAC",
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      creds.Expiration.Format(iso8601Format),
	})
}

func (s *Server) getAz(w http.ResponseWriter, r *http.Request) {
	az := []byte(s.availabilityZone)
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", strconv.Itoa(len(az))) // To ensure we don't send a chunked response
	w.Write(az)
}
