package iam4kube

import (
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"
)

const (
	IamRoleArnAnnotation        = "iam.amazonaws.com/roleArn"
	IamRoleExternalIdAnnotation = "iam.amazonaws.com/roleExternalId"
)

type IP string

type IamRole struct {
	Arn        arn.ARN
	ExternalID *string // optional
}

type Credentials struct {
	LastUpdated     time.Time
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}
