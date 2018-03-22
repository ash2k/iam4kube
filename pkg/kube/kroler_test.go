package kube

import (
	"context"
	"testing"
	"time"

	"github.com/ash2k/iam4kube"
	i4k_testing "github.com/ash2k/iam4kube/pkg/util/testing"
	"github.com/ash2k/stager"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	core_v1inf "k8s.io/client-go/informers/core/v1"
	mainFake "k8s.io/client-go/kubernetes/fake"
	kube_testing "k8s.io/client-go/testing"
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

type testStuff struct {
	fakeClient  *mainFake.Clientset
	kroler      *Kroler
	podsWatch   *watch.FakeWatcher
	svcAccWatch *watch.FakeWatcher
}

func bootstrap(t *testing.T, test func(*testing.T, *testStuff)) {
	t.Parallel()

	fakeClient := mainFake.NewSimpleClientset()
	podsWatch := watch.NewFake()
	svcAccWatch := watch.NewFake()
	fakeClient.PrependWatchReactor("pods", kube_testing.DefaultWatchReactor(podsWatch, nil))
	fakeClient.PrependWatchReactor("serviceaccounts", kube_testing.DefaultWatchReactor(svcAccWatch, nil))

	svcAccInf := core_v1inf.NewServiceAccountInformer(fakeClient, meta_v1.NamespaceAll, 0, cache.Indexers{})
	podsInf := core_v1inf.NewPodInformer(fakeClient, meta_v1.NamespaceAll, 0, cache.Indexers{})

	logger := i4k_testing.DevelopmentLogger(t)
	defer logger.Sync()
	kroler, err := NewKroler(logger, podsInf, svcAccInf)
	require.NoError(t, err)

	stgr := stager.New()
	defer stgr.Shutdown()

	stage := stgr.NextStage()
	stage.StartWithContext(kroler.Run) // Kroler must start before informers and stop after they are stopped
	stage = stgr.NextStage()
	stage.StartWithChannel(svcAccInf.Run)
	stage.StartWithChannel(podsInf.Run)

	test(t, &testStuff{
		fakeClient:  fakeClient,
		kroler:      kroler,
		podsWatch:   podsWatch,
		svcAccWatch: svcAccWatch,
	})
}

func TestRoleForIpNotFound(t *testing.T) {
	t.Parallel()
	t1 := meta_v1.Now()
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
					ObjectMeta: meta_v1.ObjectMeta{
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
					ObjectMeta: meta_v1.ObjectMeta{
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
					ObjectMeta: meta_v1.ObjectMeta{
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
					ObjectMeta: meta_v1.ObjectMeta{
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
			bootstrap(t, func(t *testing.T, stuff *testStuff) {
				for _, pod := range tc.pods {
					stuff.podsWatch.Add(pod.DeepCopy())
				}

				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancel()
				pod, _, err := stuff.kroler.RoleForIp(ctx, ipAddr)
				assert.Equal(t, context.DeadlineExceeded, errors.Cause(err))
				assert.Nil(t, pod)
			})
		})
	}
}

func TestRoleForIp(t *testing.T) {
	bootstrap(t, func(t *testing.T, stuff *testStuff) {
		stuff.podsWatch.Add(pod())
		stuff.svcAccWatch.Add(svcAcc())
		expectedRole := &iam4kube.IamRole{
			Arn:         arn.ARN{"aws", "iam", "", "123456789012", "role/test_role"},
			SessionName: namespace + "@" + svcAccName,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		pod, role, err := stuff.kroler.RoleForIp(ctx, ipAddr)
		require.NoError(t, err)
		assert.Equal(t, expectedRole, role)
		assert.NotNil(t, pod)
	})
}

func TestSlowRoleForIp(t *testing.T) {
	bootstrap(t, func(t *testing.T, stuff *testStuff) {
		go func() {
			time.Sleep(30 * time.Millisecond)
			stuff.podsWatch.Add(pod())
		}()
		go func() {
			time.Sleep(60 * time.Millisecond)
			stuff.svcAccWatch.Add(svcAcc())
		}()
		expectedRole := &iam4kube.IamRole{
			Arn:         arn.ARN{"aws", "iam", "", "123456789012", "role/test_role"},
			SessionName: namespace + "@" + svcAccName,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		pod, role, err := stuff.kroler.RoleForIp(ctx, ipAddr)
		require.NoError(t, err)
		assert.Equal(t, expectedRole, role)
		assert.NotNil(t, pod)
	})
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

func svcAcc() *core_v1.ServiceAccount {
	return &core_v1.ServiceAccount{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      svcAccName,
			Namespace: namespace,
			Annotations: map[string]string{
				iam4kube.IamRoleArnAnnotation: testArn,
			},
		},
	}
}
