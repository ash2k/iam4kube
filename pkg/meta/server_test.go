package meta

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ash2k/iam4kube"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	accessKeyId     = "keyId"
	secretAccessKey = "secret"
	sessionToken    = "token"
)

func TestServer(t *testing.T) {
	t.Parallel()
	metaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("%s should not be invoked", r.URL)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer metaServer.Close()

	metaUrl, err := url.Parse(metaServer.URL)
	require.NoError(t, err)

	server := Server{
		//Logger:
		MetadataURL: *metaUrl,
		Kernel:      &kernelFake{},
	}

	srv := httptest.NewServer(server.handler())
	defer srv.Close()

	metadataSession, err := session.NewSession(aws.NewConfig().
		WithEndpoint(srv.URL))
	require.NoError(t, err)
	metadata := ec2metadata.New(metadataSession)

	t.Run("credentials", func(t *testing.T) {
		provider := ec2rolecreds.EC2RoleProvider{
			Client: metadata,
		}
		creds, err := provider.Retrieve()
		require.NoError(t, err)
		assert.Equal(t, accessKeyId, creds.AccessKeyID)
		assert.Equal(t, secretAccessKey, creds.SecretAccessKey)
		assert.Equal(t, sessionToken, creds.SessionToken)
	})
}

type kernelFake struct {
}

func (k *kernelFake) RoleForIp(ctx context.Context, ip iam4kube.IP) (*iam4kube.IamRole, error) {
	a, err := arn.Parse("arn:aws:iam::123456789012:role/this/is/a/path/roleName")
	if err != nil {
		return nil, err
	}
	return &iam4kube.IamRole{
		Arn: a,
	}, nil
}

func (k *kernelFake) CredentialsForIp(ctx context.Context, ip iam4kube.IP, role string) (*iam4kube.Credentials, error) {
	return &iam4kube.Credentials{
		LastUpdated:     time.Now(),
		AccessKeyId:     "keyId",
		SecretAccessKey: "secret",
		SessionToken:    "token",
		Expiration:      time.Now().Add(10 * time.Minute),
	}, nil
}
