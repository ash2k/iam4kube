package util

import (
	"regexp"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/pkg/errors"
)

var (
	// As per https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html
	resourceRegex = regexp.MustCompile(`^role/(?:[\x21-\x7F]+/)?([\w+=,.@-]+)$`)
)

func RoleNameFromRoleArn(roleArn arn.ARN) (string, error) {
	match := resourceRegex.FindStringSubmatch(roleArn.Resource)
	if match == nil {
		return "", errors.New("ARN resource part does not contain a valid role name")
	}
	return match[1], nil
}
