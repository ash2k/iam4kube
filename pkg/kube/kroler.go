package kube

import (
	"context"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/iam4kube/pkg/util"
	"github.com/ash2k/stager/wait"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	core_v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

type Kroler struct {
	logger                *zap.Logger
	podByIp               *BlockingIndex
	svcAccByNamespaceName *BlockingIndex
}

func NewKroler(logger *zap.Logger, podsInf, svcAccInf cache.SharedIndexInformer) (*Kroler, error) {
	podByIp, err := NewBlockingGetByIndex(podsInf, podByIpIndexFunc)
	if err != nil {
		return nil, err
	}
	return &Kroler{
		logger:                logger,
		podByIp:               podByIp,
		svcAccByNamespaceName: NewBlockingGetByKey(svcAccInf),
	}, nil
}

func (k *Kroler) Run(ctx context.Context) {
	var wg wait.Group
	defer wg.Wait()
	wg.StartWithContext(ctx, k.podByIp.Run) // fork
	k.svcAccByNamespaceName.Run(ctx)        // execute inline
}

// RoleForIp fetches the IAM role that is supposed to be used by a Pod with the provided IP.
// Returns nil if no IAM role is assigned.
func (k *Kroler) RoleForIp(ctx context.Context, ip iam4kube.IP) (*iam4kube.IamRole, error) {
	pods, err := k.podByIp.Get(ctx, string(ip))
	if err != nil {
		return nil, errors.Wrap(err, "failed to get Pod by its ip")
	}
	if len(pods) != 1 {
		return nil, errors.Errorf("unexpected number of Pods found for ip: %d", len(pods))
	}
	pod := pods[0].(*core_v1.Pod)
	if pod.Spec.ServiceAccountName == "" {
		return nil, nil
	}
	svcAccs, err := k.svcAccByNamespaceName.Get(ctx, pod.Namespace+"/"+pod.Spec.ServiceAccountName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get ServiceAccount by its namespace %q and name %q",
			pod.Namespace, pod.Spec.ServiceAccountName)
	}
	if len(svcAccs) != 1 {
		return nil, errors.Errorf("unexpected number of ServiceAccounts found by namespace %q and name %q: %d",
			pod.Namespace, pod.Spec.ServiceAccountName, len(pods))
	}
	svcAcc := svcAccs[0].(*core_v1.ServiceAccount)
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
	roleArn, err := arn.Parse(iamRoleArnStr)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse %s annotation's value %q as ARN",
			iam4kube.IamRoleArnAnnotation, iamRoleArnStr)
	}
	err = util.ValidateIamRoleArn(roleArn)
	if err != nil {
		return nil, errors.Wrapf(err, "%s annotation's value %q is not a valid ARN",
			iam4kube.IamRoleArnAnnotation, iamRoleArnStr)
	}
	var roleExternalId *string
	iamRoleExternalId, ok := svcAcc.Annotations[iam4kube.IamRoleExternalIdAnnotation]
	if ok {
		roleExternalId = &iamRoleExternalId
	}

	return &iam4kube.IamRole{
		Arn: roleArn,
		// TODO make SessionName configuration through a template.
		// must satisfy regular expression pattern: [\w+=,.@-]
		SessionName: svcAcc.Namespace + "@" + svcAcc.Name,
		ExternalID:  roleExternalId,
	}, nil
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
