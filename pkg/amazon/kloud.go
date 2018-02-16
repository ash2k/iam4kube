package amazon

import (
	"context"
	"time"

	"github.com/ash2k/iam4kube"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
)

type Assumer interface {
	AssumeRoleWithContext(aws.Context, *sts.AssumeRoleInput, ...request.Option) (*sts.AssumeRoleOutput, error)
}

type Kloud struct {
	Assumer Assumer
}

func (k *Kloud) CredentialsForRole(ctx context.Context, role *iam4kube.IamRole) (*iam4kube.Credentials, error) {
	res, err := k.Assumer.AssumeRoleWithContext(ctx, &sts.AssumeRoleInput{
		ExternalId: role.ExternalID,
		RoleArn:    aws.String(role.Arn.String()),
		// RoleSessionName ?
	})
	if err != nil {
		return nil, errors.Wrap(err, "STS AssumeRole call failed")
	}
	return &iam4kube.Credentials{
		LastUpdated:     time.Now().UTC(),
		AccessKeyId:     aws.StringValue(res.Credentials.AccessKeyId),
		SecretAccessKey: aws.StringValue(res.Credentials.SecretAccessKey),
		SessionToken:    aws.StringValue(res.Credentials.SessionToken),
		Expiration:      aws.TimeValue(res.Credentials.Expiration),
	}, nil
}
