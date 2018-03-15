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

const (
	namespace  = "Foo"
	svcAccName = "svcAccName"
	podName1   = "podName1"
	podName2   = "podName2"
	ipAddr     = "127.0.0.1"
	testArn    = "arn:aws:iam::123456789012:role/test_role"
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
	t1 := metav1.Now()
	cases := []struct {
		name string
		pods []core_v1.Pod
	}{
		{
			name: "no Pods",
		},
		{
			name: "succeeded Pod",
			pods: []core_v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podName1,
						Namespace: namespace,
					},
					Spec: core_v1.PodSpec{
						ServiceAccountName: svcAccName,
					},
					Status: core_v1.PodStatus{
						Phase: core_v1.PodSucceeded,
						PodIP: ipAddr,
					},
				},
			},
		},
		{
			name: "succeeded, failed and deleted Pods",
			pods: []core_v1.Pod{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podName1,
						Namespace: namespace,
					},
					Spec: core_v1.PodSpec{
						ServiceAccountName: svcAccName,
					},
					Status: core_v1.PodStatus{
						Phase: core_v1.PodFailed,
						PodIP: ipAddr,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      podName2,
						Namespace: namespace,
					},
					Spec: core_v1.PodSpec{
						ServiceAccountName: svcAccName,
					},
					Status: core_v1.PodStatus{
						Phase: core_v1.PodSucceeded,
						PodIP: ipAddr,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:              podName1,
						Namespace:         namespace,
						DeletionTimestamp: &t1,
					},
					Spec: core_v1.PodSpec{
						ServiceAccountName: svcAccName,
					},
					Status: core_v1.PodStatus{
						PodIP: ipAddr,
					},
				},
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			kroler := newKroler()
			for _, pod := range tc.pods {
				pod := pod
				err := kroler.podIdx.Add(&pod)
				require.NoError(t, err)
			}

			_, err := kroler.RoleForIp(context.Background(), ipAddr)
			assert.Equal(t, err, ErrPodForIpNotFound)
		})
	}
}

func TestRoleForIp(t *testing.T) {
	t.Parallel()

	kroler := newKroler()

	pod := core_v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
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
	err := kroler.podIdx.Add(&pod)
	require.NoError(t, err)

	svcAccount := core_v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcAccName,
			Namespace: namespace,
			Annotations: map[string]string{
				iam4kube.IamRoleArnAnnotation: testArn,
			},
		},
	}
	err = kroler.svcAccIdx.Add(&svcAccount)
	require.NoError(t, err)

	expectedRole := &iam4kube.IamRole{
		Arn:         arn.ARN{"aws", "iam", "", "123456789012", "role/test_role"},
		SessionName: namespace + "/" + svcAccName,
	}

	role, err := kroler.RoleForIp(context.Background(), ipAddr)
	require.NoError(t, err)
	assert.Equal(t, expectedRole, role)
}
