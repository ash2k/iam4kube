package core

import (
	"context"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/iam4kube/pkg/util"

	"github.com/pkg/errors"
)

type Kloud interface {
	CredentialsForRole(context.Context, *iam4kube.IamRole) (*iam4kube.Credentials, error)
}

type Kroler interface {
	RoleForIp(context.Context, iam4kube.IP) (*iam4kube.IamRole, error)
}

type Kernel struct {
	Kloud  Kloud
	Kroler Kroler
}

func (k *Kernel) RoleForIp(ctx context.Context, ip iam4kube.IP) (*iam4kube.IamRole, error) {
	return k.Kroler.RoleForIp(ctx, ip)
}

func (k *Kernel) CredentialsForIp(ctx context.Context, ip iam4kube.IP, role string) (*iam4kube.Credentials, error) {
	iamRole, err := k.Kroler.RoleForIp(ctx, ip)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get IAM role for ip")
	}
	availableRole, err := util.RoleNameFromRoleArn(iamRole.Arn)
	if availableRole != role {
		return nil, errors.Errorf("expected IAM role name %q is different from the requested role name %q", availableRole, role)
	}
	return k.Kloud.CredentialsForRole(ctx, iamRole)
}
