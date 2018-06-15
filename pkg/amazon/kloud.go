package amazon

import (
	"context"
	"time"

	"github.com/ash2k/iam4kube"
	"github.com/ash2k/iam4kube/pkg/util"
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
	assumer      Assumer
	latency      prometheus.Histogram
	successCount prometheus.Counter
	errorCount   prometheus.Counter
}

func NewKloud(assumer Assumer, registry prometheus.Registerer) (*Kloud, error) {
	latency := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "iam4kube",
		Name:      "assume_role_seconds",
		Help:      "Histogram measuring the time it took to perform successful STS AssumeRole call",
	})
	successCount := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "iam4kube",
		Name:      "assume_role_success_count",
		Help:      "Number of times credentials were successfully fetched from STS",
	})
	errorCount := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "iam4kube",
		Name:      "assume_role_error_count",
		Help:      "Number of times credentials prefetch failed",
	})
	if err := util.RegisterAll(registry, latency, successCount, errorCount); err != nil {
		return nil, err
	}
	return &Kloud{
		assumer:      assumer,
		latency:      latency,
		successCount: successCount,
		errorCount:   errorCount,
	}, nil
}

func (k *Kloud) CredentialsForRole(ctx context.Context, role *iam4kube.IamRole) (*iam4kube.Credentials, error) {
	start := time.Now()
	res, err := k.assumer.AssumeRoleWithContext(ctx, &sts.AssumeRoleInput{
		ExternalId:      role.ExternalID,
		RoleArn:         aws.String(role.Arn.String()),
		RoleSessionName: aws.String(role.SessionName),
	})
	if err != nil {
		k.errorCount.Inc()
		return nil, errors.Wrap(err, "STS AssumeRole call failed")
	}
	k.latency.Observe(time.Since(start).Seconds())
	k.successCount.Inc()
	return &iam4kube.Credentials{
		LastUpdated:     time.Now().UTC(),
		AccessKeyID:     aws.StringValue(res.Credentials.AccessKeyId),
		SecretAccessKey: aws.StringValue(res.Credentials.SecretAccessKey),
		SessionToken:    aws.StringValue(res.Credentials.SessionToken),
		Expiration:      aws.TimeValue(res.Credentials.Expiration),
	}, nil
}
