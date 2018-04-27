package meta

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ash2k/iam4kube"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
)

const (
	accessKeyID     = "keyId"
	secretAccessKey = "secret"
	sessionToken    = "token"
	regionSydney    = "ap-southeast-2"
	azSydneyA       = regionSydney + "a"

	namespace  = "Foo"
	svcAccName = "svcAccName"
	podName1   = "podName1"
	ipAddr     = "127.0.0.1"
	testArn    = "arn:aws:iam::123456789012:role/test_role"
)

func TestServerDirectNoRoleWithoutSlash(t *testing.T) {
	bootstrap(t, &kernelFake{credentialsNotFound: true, roleNotFound: true}, func(t *testing.T, url string) {
		r, err := http.Get(url + "/latest/meta-data/iam/security-credentials")
		require.NoError(t, err)
		defer r.Body.Close()
		assert.Equal(t, http.StatusOK, r.StatusCode)
		data, err := ioutil.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, []byte{}, data)
	})
}

func TestServerDirectNoRoleWithSlash(t *testing.T) {
	bootstrap(t, &kernelFake{credentialsNotFound: true, roleNotFound: true}, func(t *testing.T, url string) {
		r, err := http.Get(url + "/latest/meta-data/iam/security-credentials/")
		require.NoError(t, err)
		defer r.Body.Close()
		assert.Equal(t, http.StatusOK, r.StatusCode)
		data, err := ioutil.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, []byte{}, data)
	})
}

func TestServerDirectInexistentRole(t *testing.T) {
	bootstrap(t, &kernelFake{credentialsNotFound: true, roleNotFound: true}, func(t *testing.T, url string) {
		r, err := http.Get(url + "/latest/meta-data/iam/security-credentials/i-do-not-exist")
		require.NoError(t, err)
		defer r.Body.Close()
		assert.Equal(t, http.StatusNotFound, r.StatusCode)
	})
}

func TestServerDirectAvailabilityZone(t *testing.T) {
	bootstrap(t, &kernelFake{}, func(t *testing.T, url string) {
		r, err := http.Get(url + "/latest/meta-data/placement/availability-zone")
		require.NoError(t, err)
		defer r.Body.Close()
		assert.Equal(t, http.StatusOK, r.StatusCode)
		body, err := ioutil.ReadAll(r.Body)
		require.NoError(t, err)
		assert.Equal(t, azSydneyA, string(body))
	})
}

func TestServerSdk(t *testing.T) {
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
		t.Run("region", func(t *testing.T) {
			region, err := metadata.Region()
			require.NoError(t, err)
			assert.Equal(t, regionSydney, region)
		})
		// TODO test other methods
	})
}

func TestServerSdkRoleFoundButThenCredentialsNotFound(t *testing.T) {
	bootstrap(t, &kernelFake{credentialsNotFound: true}, func(t *testing.T, url string) {
		metadataSession, err := session.NewSession(aws.NewConfig().
			WithEndpoint(url + "/latest"))
		require.NoError(t, err)
		metadata := ec2metadata.New(metadataSession)

		provider := ec2rolecreds.EC2RoleProvider{
			Client: metadata,
		}
		_, err = provider.Retrieve()
		assertAwsError(t, err, `EC2RoleRequestError`)
	})
}

func TestServerSdkNoRoleAssigned(t *testing.T) {
	bootstrap(t, &kernelFake{roleNotFound: true, credentialsNotFound: true}, func(t *testing.T, url string) {
		metadataSession, err := session.NewSession(aws.NewConfig().
			WithEndpoint(url + "/latest"))
		require.NoError(t, err)
		metadata := ec2metadata.New(metadataSession)
		provider := ec2rolecreds.EC2RoleProvider{
			Client: metadata,
		}
		_, err = provider.Retrieve()
		assertAwsError(t, err, `EmptyEC2RoleList`)
	})
}

func assertAwsError(t *testing.T, err error, code string) bool {
	if !assert.Error(t, err) {
		return false
	}
	if !assert.Implements(t, (*awserr.Error)(nil), err) {
		return false
	}
	return assert.Equal(t, err.(awserr.Error).Code(), code)
}

func bootstrap(t *testing.T, kernel Kernel, test func(t *testing.T, url string)) {
	t.Parallel()

	server, err := NewServer(
		zaptest.NewLogger(t),
		":http",
		azSydneyA,
		kernel,
		prometheus.NewPedanticRegistry(),
		&record.FakeRecorder{},
	)
	require.NoError(t, err)

	srv := httptest.NewServer(server.constructHandler())
	defer srv.Close()
	test(t, srv.URL)
}

type kernelFake struct {
	credentialsNotFound bool
	roleNotFound        bool
}

func (k *kernelFake) RoleForIp(ctx context.Context, ip iam4kube.IP) (*core_v1.Pod, *iam4kube.IamRole, error) {
	if k.roleNotFound {
		return pod(), nil, nil
	}
	a, err := arn.Parse(testArn)
	if err != nil {
		return nil, nil, err
	}
	return pod(), &iam4kube.IamRole{
		Arn: a,
	}, nil
}

func (k *kernelFake) CredentialsForIp(ctx context.Context, ip iam4kube.IP, role string) (*core_v1.Pod, *iam4kube.Credentials, error) {
	if k.credentialsNotFound {
		return nil, nil, nil
	}
	now := time.Now().UTC()
	return pod(), &iam4kube.Credentials{
		LastUpdated:     now,
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		Expiration:      now.Add(1 * time.Hour),
	}, nil
}

func pod() *core_v1.Pod {
	return &core_v1.Pod{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      podName1,
			Namespace: namespace,
		},
		Spec: core_v1.PodSpec{
			ServiceAccountName: svcAccName,
		},
		Status: core_v1.PodStatus{
			PodIP: ipAddr,
		},
	}
}
