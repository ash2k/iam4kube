package kube

import (
	"context"
	"testing"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/iam4kube/pkg/util/logz"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	core_v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func newKroler() Kroler {
	store := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
		podByIpIndex: podByIpIndexFunc,
	})
	store2 := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})

	kroler := Kroler{
		logger:    logz.DevelopmentLogger(),
		podIdx:    store,
		svcAccIdx: store2,
	}
	return kroler
}

func TestRoleForIpNotFound(t *testing.T) {
	t.Parallel()

	kroler := newKroler()
	_, err := kroler.RoleForIp(context.Background(), "127.0.0.1")
	assert.Equal(t, err, ErrPodForIpNotFound)
}

func TestRoleForIp(t *testing.T) {
	t.Parallel()

	namespace := "Foo"
	name := "Bar"
	ipAddr := "127.0.0.1"
	testArn := "arn:aws:iam::123456789012:role/test_role"

	kroler := newKroler()

	pod := core_v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
		},
		Spec: core_v1.PodSpec{
			ServiceAccountName: name,
		},
		Status: core_v1.PodStatus{
			PodIP: ipAddr,
		},
	}
	kroler.podIdx.Add(&pod)

	svcAccount := core_v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				iam4kube.IamRoleArnAnnotation: testArn,
			},
		},
	}
	kroler.svcAccIdx.Add(&svcAccount)

	expectedRole := &iam4kube.IamRole{}
	expectedRole.Arn = arn.ARN{"aws", "iam", "", "123456789012", "role/test_role"}
	expectedRole.SessionName = namespace + "/" + name

	role, err := kroler.RoleForIp(context.Background(), iam4kube.IP(ipAddr))
	require.NoError(t, err)
	assert.Equal(t, expectedRole, role)
}
