package amazon

import (
	"context"
	"time"

	"github.com/ash2k/iam4kube"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

type Assumer interface {
	AssumeRoleWithContext(aws.Context, *sts.AssumeRoleInput, ...request.Option) (*sts.AssumeRoleOutput, error)
}

type Kloud struct {
	Assumer    Assumer
	StsLatency prometheus.Histogram
}

func NewKloud(assumer Assumer, registry prometheus.Registerer) (*Kloud, error) {
	stsLatency := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "iam4kube",
		Name:      "assume_role_seconds",
		Help:      "Histogram measuring the time it took to perform successful STS AssumeRole call",
	})
	if err := registry.Register(stsLatency); err != nil {
		return nil, errors.WithStack(err)
	}
	return &Kloud{
		Assumer:    assumer,
		StsLatency: stsLatency,
	}, nil
}

func (k *Kloud) CredentialsForRole(ctx context.Context, role *iam4kube.IamRole) (*iam4kube.Credentials, error) {
	start := time.Now()
	res, err := k.Assumer.AssumeRoleWithContext(ctx, &sts.AssumeRoleInput{
		ExternalId:      role.ExternalID,
		RoleArn:         aws.String(role.Arn.String()),
		RoleSessionName: aws.String(role.SessionName),
	})
	if err != nil {
		return nil, errors.Wrap(err, "STS AssumeRole call failed")
	}
	k.StsLatency.Observe(time.Since(start).Seconds())
	return &iam4kube.Credentials{
		LastUpdated:     time.Now().UTC(),
		AccessKeyID:     aws.StringValue(res.Credentials.AccessKeyId),
		SecretAccessKey: aws.StringValue(res.Credentials.SecretAccessKey),
		SessionToken:    aws.StringValue(res.Credentials.SessionToken),
		Expiration:      aws.TimeValue(res.Credentials.Expiration),
	}, nil
}
