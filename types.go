package iam4kube

import (
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"
)

const (
	IamRoleArnAnnotation        = "iam.amazonaws.com/roleArn"
	IamRoleExternalIdAnnotation = "iam.amazonaws.com/roleExternalId"
)

type IP string

type IamRole struct {
	Arn         arn.ARN
	SessionName string
	ExternalID  *string // optional
}

func (r *IamRole) String() string {
	ext := "none"
	if r.ExternalID != nil {
		ext = *r.ExternalID
	}
	return fmt.Sprintf("%s<extId=%s>", r.Arn, ext)
}

type Credentials struct {
	LastUpdated     time.Time
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

func (c *Credentials) WillBeValidForAtLeast(duration time.Duration) bool {
	return c.Expiration.After(time.Now().Add(duration))
}
