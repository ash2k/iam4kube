package core

import (
	"context"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/iam4kube/pkg/util"
	"github.com/pkg/errors"
	core_v1 "k8s.io/api/core/v1"
)

type Kloud interface {
	CredentialsForRole(context.Context, *iam4kube.IamRole) (*iam4kube.Credentials, error)
}

type Kroler interface {
	// RoleForIp fetches the IAM role that is supposed to be used by a Pod with the provided IP.
	// Returns nil if no IAM role is assigned. May return non-nil pod even on error.
	RoleForIp(context.Context, iam4kube.IP) (*core_v1.Pod, *core_v1.ServiceAccount, *iam4kube.IamRole, error)
}

type Kernel struct {
	Kloud  Kloud
	Kroler Kroler
}

// RoleForIp fetches the IAM role that is supposed to be used by a Pod with the provided IP.
// Returns nil if no IAM role is assigned. May return non-nil pod even on error.
func (k *Kernel) RoleForIp(ctx context.Context, ip iam4kube.IP) (*core_v1.Pod, *iam4kube.IamRole, error) {
	pod, _, iamRole, err := k.Kroler.RoleForIp(ctx, ip)
	return pod, iamRole, err
}

// CredentialsForIp fetches credentials for the IAM role that is assigned to a Pod with the provided IP.
// Returns nil if no IAM role is assigned. May return non-nil pod even on error.
func (k *Kernel) CredentialsForIp(ctx context.Context, ip iam4kube.IP, role string) (*core_v1.Pod, *iam4kube.Credentials, error) {
	pod, _, iamRole, err := k.Kroler.RoleForIp(ctx, ip)
	if err != nil {
		return pod, nil, errors.Wrap(err, "failed to get IAM role for ip")
	}
	if iamRole == nil {
		return pod, nil, nil
	}
	availableRole, err := util.RoleNameFromRoleArn(iamRole.Arn)
	if err != nil {
		return pod, nil, errors.Wrapf(err, "failed to extract IAM role name from ARN %q", iamRole.Arn)
	}
	if availableRole != role {
		return pod, nil, errors.Errorf("expected IAM role name %q is different from the requested role name %q", availableRole, role)
	}
	creds, err := k.Kloud.CredentialsForRole(ctx, iamRole)
	if err != nil {
		return pod, nil, errors.Wrapf(err, "failed to get credentials for IAM role %q", iamRole.Arn)
	}
	return pod, creds, nil
}
