package core

import (
	"context"

	"github.com/ash2k/iam4kube"
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
	// TODO
	return nil, nil
}

func (k *Kernel) CredentialsForIp(ctx context.Context, ip iam4kube.IP, role string) (*iam4kube.Credentials, error) {
	// TODO
	return nil, nil
}
