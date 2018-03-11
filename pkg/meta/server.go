package meta

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/iam4kube/pkg/util"

	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	defaultMaxRequestDuration = 15 * time.Second
	shutdownTimeout           = defaultMaxRequestDuration
	readTimeout               = 1 * time.Second
	writeTimeout              = 1 * time.Second
	idleTimeout               = 1 * time.Minute

	iso8601Format = "2006-01-02T15:04:05Z"
)

type Kernel interface {
	RoleForIp(context.Context, iam4kube.IP) (*iam4kube.IamRole, error)
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
	Logger      *zap.Logger
	Addr        string  // TCP address to listen on, ":http" if empty
	MetadataURL url.URL // URL of the metadata api endpoint
	Kernel      Kernel
}

func (s *Server) Run(ctx context.Context) error {
	srv := http.Server{
		Addr:         s.Addr,
		Handler:      s.handler(),
		WriteTimeout: writeTimeout,
		ReadTimeout:  readTimeout,
		IdleTimeout:  idleTimeout,
	}
	return startStopServer(ctx, &srv, shutdownTimeout)
}

func (s *Server) handler() *mux.Router {
	router := mux.NewRouter()
	router.Handle("/{version}/meta-data/iam/info", http.HandlerFunc(s.getInfo))

	// Trailing slash support https://github.com/jtblin/kube2iam/pull/119
	router.Handle("/{version}/meta-data/iam/security-credentials{slash:/?}", http.HandlerFunc(s.getRole))
	router.Handle("/{version}/meta-data/iam/security-credentials/{role:.+}", http.HandlerFunc(s.getCredentials))

	router.Handle("/{path:.*}", httputil.NewSingleHostReverseProxy(&s.MetadataURL))

	return router
}

func (s *Server) getRole(w http.ResponseWriter, r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		s.writeInternalError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultMaxRequestDuration)
	defer cancel()
	role, err := s.Kernel.RoleForIp(ctx, iam4kube.IP(ip))
	if err != nil {
		s.writeInternalError(w, errors.Wrap(err, "failed to get IAM role for ip"))
		return
	}
	roleName, err := util.RolePathAndNameFromRoleArn(role.Arn)
	if err != nil {
		s.writeInternalError(w, errors.Wrapf(err, "failed to extract IAM role name from ARN %q", role.Arn))
		return
	}
	response := []byte(roleName)
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", strconv.Itoa(len(response))) // To ensure we don't send a chunked response
	w.Header().Set("Server", "iam4kube")
	w.Write(response)
}

func (s *Server) getInfo(w http.ResponseWriter, r *http.Request) {
	// TODO
}

func (s *Server) getCredentials(w http.ResponseWriter, r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		s.writeInternalError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultMaxRequestDuration)
	defer cancel()
	role := mux.Vars(r)["role"]
	creds, err := s.Kernel.CredentialsForIp(ctx, iam4kube.IP(ip), role)
	if err != nil {
		s.writeInternalError(w, err)
		return
	}
	s.writeJson(w, &jsonCreds{
		Code:            "Success",
		LastUpdated:     creds.LastUpdated.Format(iso8601Format),
		Type:            "AWS-HMAC",
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      creds.Expiration.Format(iso8601Format),
	})
}

func (s *Server) writeInternalError(w http.ResponseWriter, err error) {
	w.Header().Set("Server", "iam4kube")
	w.WriteHeader(http.StatusInternalServerError)
	s.Logger.Error("Internal error", zap.Error(err))
}

func (s *Server) writeJson(w http.ResponseWriter, data interface{}) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(data)
	if err != nil {
		s.writeInternalError(w, err)
		return
	}
	response := buf.Bytes()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(response))) // To ensure we don't send a chunked response
	w.Header().Set("Server", "iam4kube")
	w.Write(response)
}
