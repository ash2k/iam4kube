package util

import (
	"regexp"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/pkg/errors"
)

var (
	resourceRegex = regexp.MustCompile(`^role/(?:.+/)?([^/]+)$`)
)

func RoleNameFromRoleArn(roleArn arn.ARN) (string, error) {
	match := resourceRegex.FindStringSubmatch(roleArn.Resource)
	if match == nil {
		return "", errors.Errorf("failed to extract IAM role name from ARN resource part. ARN %q", roleArn)
	}
	return match[1], nil
}
