package meta

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/iam4kube/pkg/util/logz"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	accessKeyID     = "keyId"
	secretAccessKey = "secret"
	sessionToken    = "token"
)

func TestServer(t *testing.T) {
	bootstrap(t, &kernelFake{}, func(t *testing.T, url string) {
		metadataSession, err := session.NewSession(aws.NewConfig().
			WithEndpoint(url + "/latest"))
		require.NoError(t, err)
		metadata := ec2metadata.New(metadataSession)

		t.Run("credentials", func(t *testing.T) {
			provider := ec2rolecreds.EC2RoleProvider{
				Client: metadata,
			}
			creds, err := provider.Retrieve()
			require.NoError(t, err)
			assert.Equal(t, accessKeyID, creds.AccessKeyID)
			assert.Equal(t, secretAccessKey, creds.SecretAccessKey)
			assert.Equal(t, sessionToken, creds.SessionToken)
		})
	})
}

func TestServerRoleFoundButThenCredentialsNotFound(t *testing.T) {
	bootstrap(t, &kernelFake{credentialsNotFound: true}, func(t *testing.T, url string) {
		metadataSession, err := session.NewSession(aws.NewConfig().
			WithEndpoint(url + "/latest"))
		require.NoError(t, err)
		metadata := ec2metadata.New(metadataSession)

		t.Run("credentials", func(t *testing.T) {
			provider := ec2rolecreds.EC2RoleProvider{
				Client: metadata,
			}
			_, err := provider.Retrieve()
			assert.EqualError(t, err, `EC2RoleRequestError: failed to get this/is/a/path/roleName EC2 instance role credentials
caused by: EC2MetadataError: failed to make EC2Metadata request
caused by: `)
		})
	})
}

func TestServerRoleNotFound(t *testing.T) {
	bootstrap(t, &kernelFake{roleNotFound: true, credentialsNotFound: true}, func(t *testing.T, url string) {
		metadataSession, err := session.NewSession(aws.NewConfig().
			WithEndpoint(url + "/latest"))
		require.NoError(t, err)
		metadata := ec2metadata.New(metadataSession)

		t.Run("credentials", func(t *testing.T) {
			provider := ec2rolecreds.EC2RoleProvider{
				Client: metadata,
			}
			_, err := provider.Retrieve()
			assert.EqualError(t, err, `EmptyEC2RoleList: empty EC2 Role list`)
		})
	})
}

func bootstrap(t *testing.T, kernel Kernel, test func(t *testing.T, url string)) {
	t.Parallel()
	metaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("%s should not be invoked", r.URL)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer metaServer.Close()

	metaUrl, err := url.Parse(metaServer.URL)
	require.NoError(t, err)

	server := Server{
		Logger:      logz.DevelopmentLogger(),
		MetadataURL: *metaUrl,
		Kernel:      kernel,
	}

	srv := httptest.NewServer(server.handler())
	defer srv.Close()
	test(t, srv.URL)
}

type kernelFake struct {
	credentialsNotFound bool
	roleNotFound        bool
}

func (k *kernelFake) RoleForIp(ctx context.Context, ip iam4kube.IP) (*iam4kube.IamRole, error) {
	if k.roleNotFound {
		return nil, nil
	}
	a, err := arn.Parse("arn:aws:iam::123456789012:role/this/is/a/path/roleName")
	if err != nil {
		return nil, err
	}
	return &iam4kube.IamRole{
		Arn: a,
	}, nil
}

func (k *kernelFake) CredentialsForIp(ctx context.Context, ip iam4kube.IP, role string) (*iam4kube.Credentials, error) {
	if k.credentialsNotFound {
		return nil, nil
	}
	return &iam4kube.Credentials{
		LastUpdated:     time.Now(),
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		Expiration:      time.Now().Add(1 * time.Hour),
	}, nil
}
