package kube

import (
	"context"

	"github.com/ash2k/iam4kube"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	podByIpIndex = "podByIpIndex"
)

var (
	ErrPodForIpNotFound = errors.New("Pod for ip not found")
)

type Kroler struct {
	logger    *zap.Logger
	podIdx    cache.Indexer
	svcAccIdx cache.Indexer
}

func NewKroler(logger *zap.Logger, podsInf, svcAccInf cache.SharedIndexInformer) (*Kroler, error) {
	err := podsInf.AddIndexers(cache.Indexers{
		podByIpIndex: podByIpIndexFunc,
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &Kroler{
		logger:    logger,
		podIdx:    podsInf.GetIndexer(),
		svcAccIdx: svcAccInf.GetIndexer(),
	}, nil
}

// RoleForIp fetches the IAM role that is supposed to be used by a Pod with the provided IP.
// Returns nil if no IAM role is assigned.
func (k *Kroler) RoleForIp(ctx context.Context, ip iam4kube.IP) (*iam4kube.IamRole, error) {
	pods, err := k.podIdx.ByIndex(podByIpIndex, string(ip))

	if err != nil {
		return nil, errors.Wrap(err, "failed to get Pod by its ip")
	}
	var pod *core_v1.Pod
	switch len(pods) {
	case 0:
		// TODO wait here until Pod is found or context is cancelled?
		return nil, ErrPodForIpNotFound
	case 1:
		pod = pods[0].(*core_v1.Pod)
	default:
		return nil, errors.Errorf("unexpected number of Pods found for ip: %d", len(pods))
	}
	if pod.Spec.ServiceAccountName == "" {
		return nil, nil
	}
	svcAccObj, exists, err := k.svcAccIdx.GetByKey(pod.Namespace + "/" + pod.Spec.ServiceAccountName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get ServiceAccount by its namespace %q and name %q", pod.Namespace, pod.Spec.ServiceAccountName)
	}
	if !exists {
		// Pod has a ServiceAccount name specified but it was not found.
		// Configuration error or informer is out of sync.
		// TODO wait here until ServiceAccount is found or context is cancelled?
		// TODO At least log for now
		return nil, nil
	}
	svcAcc := svcAccObj.(*core_v1.ServiceAccount)
	role, err := IamRoleFromServiceAccount(svcAcc)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get IAM role from ServiceAccount %q in namespace %q",
			svcAcc.Name, svcAcc.Namespace)
	}
	return role, nil
}

func IamRoleFromServiceAccount(svcAcc *core_v1.ServiceAccount) (*iam4kube.IamRole, error) {
	iamRoleArnStr, ok := svcAcc.Annotations[iam4kube.IamRoleArnAnnotation]
	if !ok {
		return nil, nil
	}
	var err error
	role := &iam4kube.IamRole{
		// TODO make SessionName configuration through a template.
		// must satisfy regular expression pattern: [\w+=,.@-]
		SessionName: svcAcc.Namespace + "@" + svcAcc.Name,
	}
	role.Arn, err = arn.Parse(iamRoleArnStr)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse %s annotation's value %q as ARN",
			iam4kube.IamRoleArnAnnotation, iamRoleArnStr)
	}
	iamRoleExternalId, ok := svcAcc.Annotations[iam4kube.IamRoleExternalIdAnnotation]
	if ok {
		role.ExternalID = &iamRoleExternalId
	}

	return role, nil
}

func podByIpIndexFunc(obj interface{}) ([]string, error) {
	pod := obj.(*core_v1.Pod)
	ip := pod.Status.PodIP
	if ip == "" ||
		pod.Status.Phase == core_v1.PodSucceeded ||
		pod.Status.Phase == core_v1.PodFailed ||
		pod.DeletionTimestamp != nil {
		// Do not index irrelevant Pods
		return nil, nil
	}
	return []string{ip}, nil
}
