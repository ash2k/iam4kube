package meta

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
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
)

const (
	defaultMaxRequestDuration = 15 * time.Second
	shutdownTimeout           = defaultMaxRequestDuration
	readTimeout               = 1 * time.Second
	writeTimeout              = defaultMaxRequestDuration
	idleTimeout               = 1 * time.Minute

	iso8601Format = "2006-01-02T15:04:05Z"
)

type Kernel interface {
	// RoleForIp fetches the IAM role that is supposed to be used by a Pod with the provided IP.
	// Returns nil if no IAM role is assigned.
	RoleForIp(context.Context, iam4kube.IP) (*iam4kube.IamRole, error)
	// CredentialsForIp fetches credentials for the IAM role that is assigned to a Pod with the provided IP.
	// Returns nil if no IAM role is assigned.
	CredentialsForIp(context.Context, iam4kube.IP, string /*role*/) (*iam4kube.Credentials, error)
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
	kernel               Kernel
	getRoleCount         prometheus.Counter
	getRoleSuccessCount  prometheus.Counter
	getRoleErrorCount    prometheus.Counter
	getCredsCount        prometheus.Counter
	getCredsSuccessCount prometheus.Counter
	getCredsErrorCount   prometheus.Counter
}

func NewServer(logger *zap.Logger, addr string, kernel Kernel, registry prometheus.Registerer) (*Server, error) {
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
	allMetrics := []prometheus.Collector{
		getRoleCount, getRoleSuccessCount, getRoleErrorCount,
		getCredsCount, getCredsSuccessCount, getCredsErrorCount,
	}
	for _, metric := range allMetrics {
		if err := registry.Register(metric); err != nil {
			return nil, errors.WithStack(err)
		}
	}
	return &Server{
		logger:               logger,
		addr:                 addr,
		kernel:               kernel,
		getRoleCount:         getRoleCount,
		getRoleSuccessCount:  getRoleSuccessCount,
		getRoleErrorCount:    getRoleErrorCount,
		getCredsCount:        getCredsCount,
		getCredsSuccessCount: getCredsSuccessCount,
		getCredsErrorCount:   getCredsErrorCount,
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	srv := http.Server{
		Addr:         s.addr,
		Handler:      s.constructHandler(),
		WriteTimeout: writeTimeout,
		ReadTimeout:  readTimeout,
		IdleTimeout:  idleTimeout,
	}
	return util.StartStopServer(ctx, &srv, shutdownTimeout)
}

func (s *Server) constructHandler() *chi.Mux {
	router := chi.NewRouter()
	router.Use(middleware.Timeout(defaultMaxRequestDuration), util.SetServerHeader)
	router.NotFound(util.PageNotFound)

	// Trailing slash support https://github.com/jtblin/kube2iam/pull/119
	router.Get("/{version}/meta-data/iam/security-credentials", s.errorRenderer(s.getRoleErrorCount, s.getRole))
	router.Get("/{version}/meta-data/iam/security-credentials/", s.errorRenderer(s.getRoleErrorCount, s.getRole))
	router.Get("/{version}/meta-data/iam/security-credentials/{role:.+}", s.errorRenderer(s.getCredsErrorCount, s.getCredentials))

	// Everything else will get a 404 and this is by design. Tomorrow AWS might add an endpoint that exposes some
	// sensitive information and that would create a security hole. Also there is plenty of information
	// that would most likely be incorrect for the container because it might be running on a different host.
	// E.g. ami id, host id, instance profile, instance type and so on.

	// If you are reading this and have a valid use case - create an issue please.

	return router
}

func (s *Server) getRole(w http.ResponseWriter, r *http.Request) error {
	s.getRoleCount.Inc()
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return err
	}
	role, err := s.kernel.RoleForIp(r.Context(), iam4kube.IP(ip))
	if err != nil {
		return errors.Wrap(err, "failed to get IAM role for ip")
	}
	var response []byte
	if role != nil {
		roleName, err := util.RoleNameFromRoleArn(role.Arn)
		if err != nil {
			return errors.Wrapf(err, "failed to extract IAM role name from ARN %q", role.Arn)
		}
		response = []byte(roleName)
		s.getRoleSuccessCount.Inc()
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", strconv.Itoa(len(response))) // To ensure we don't send a chunked response
	w.Write(response)
	return nil
}

func (s *Server) getCredentials(w http.ResponseWriter, r *http.Request) error {
	s.getCredsCount.Inc()
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return err
	}
	role := chi.URLParam(r, "role")
	creds, err := s.kernel.CredentialsForIp(r.Context(), iam4kube.IP(ip), role)
	if err != nil {
		return errors.Wrap(err, "failed to get credentials for ip")
	}
	if creds == nil {
		w.WriteHeader(http.StatusNotFound)
		return nil
	}
	return s.writeJson(w, &jsonCreds{
		Code:            "Success",
		LastUpdated:     creds.LastUpdated.Format(iso8601Format),
		Type:            "AWS-HMAC",
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      creds.Expiration.Format(iso8601Format),
	})
}

func (s *Server) writeJson(w http.ResponseWriter, data interface{}) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(data)
	if err != nil {
		return err
	}
	response := buf.Bytes()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(response))) // To ensure we don't send a chunked response
	w.Write(response)
	return nil
}

func (s *Server) errorRenderer(errorCounter prometheus.Counter, f func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := f(w, r)
		if err == nil {
			// Everything is awesome
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		cause := errors.Cause(err)
		causedByContext := cause == context.Canceled || cause == context.DeadlineExceeded
		if !causedByContext {
			select {
			case <-r.Context().Done():
				// The error was most likely caused by the context
				causedByContext = true
			default:
			}
		}
		if causedByContext {
			s.logger.Debug("Internal error caused by context", zap.Error(err))
		} else {
			errorCounter.Inc()
			s.logger.Error("Internal error", zap.Error(err))
		}
	}
}
