package kube

import (
	"context"
	"fmt"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/iam4kube/pkg/util"
	authz_v1 "k8s.io/api/authorization/v1"
	core_v1 "k8s.io/api/core/v1"
	authz_v1client "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

type KrolerInterface interface {
	// RoleForIp fetches the IAM role that is supposed to be used by a Pod with the provided IP.
	// Returns nil if no IAM role is assigned. May return non-nil pod even on error.
	RoleForIp(context.Context, iam4kube.IP) (*core_v1.Pod, *core_v1.ServiceAccount, *iam4kube.IamRole, error)
}

type AuthorizingKroler struct {
	kroler KrolerInterface
	sar    authz_v1client.SubjectAccessReviewInterface
}

func NewAuthorizingKroler(kroler KrolerInterface, sar authz_v1client.SubjectAccessReviewInterface) *AuthorizingKroler {
	return &AuthorizingKroler{
		kroler: kroler,
		sar:    sar,
	}
}

func (a *AuthorizingKroler) RoleForIp(ctx context.Context, ip iam4kube.IP) (*core_v1.Pod, *core_v1.ServiceAccount, *iam4kube.IamRole, error) {
	pod, svcAcc, iamRole, err := a.kroler.RoleForIp(ctx, ip)
	if err != nil {
		return pod, svcAcc, nil, err
	}
	roleName, err := util.RoleNameFromRoleArn(iamRole.Arn)
	if err != nil {
		// This should not happen
		return pod, svcAcc, nil, err
	}
	result, err := a.sar.Create(&authz_v1.SubjectAccessReview{
		Spec: authz_v1.SubjectAccessReviewSpec{
			ResourceAttributes: &authz_v1.ResourceAttributes{
				Namespace:   pod.Namespace,
				Verb:        iam4kube.RbacVerb,
				Group:       iam4kube.RbacGroup,
				Resource:    iamRole.Arn.AccountID,
				Subresource: roleName,
			},
			User: fmt.Sprintf("system:serviceaccount:%s:%s", svcAcc.Namespace, svcAcc.Name),
		},
	})
	if err != nil {

	}
	return pod, svcAcc, iamRole, err
}
