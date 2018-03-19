package util

import (
	"regexp"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/pkg/errors"
)

var (
	// As per https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html
	resourceRegex = regexp.MustCompile(`^role/(?:[\x21-\x7F]+/)?([\w+=,.@-]+)$`)
	// As per https://docs.aws.amazon.com/general/latest/gr/acct-identifiers.html
	accountRegex = regexp.MustCompile(`^\d{12}$`)
)

// RoleNameFromRoleArn returns the role name part of the ARN.
// It does not perform validation of the general ARN structure.
func RoleNameFromRoleArn(roleArn arn.ARN) (string, error) {
	match := resourceRegex.FindStringSubmatch(roleArn.Resource)
	if match == nil {
		return "", errors.New("ARN resource part does not contain a valid role name")
	}
	return match[1], nil
}

func ValidateIamRoleArn(roleArn arn.ARN) error {
	if roleArn.Service != "iam" {
		return errors.New("IAM role ARN should have `iam` as service")
	}
	if roleArn.Region != "" {
		return errors.New("IAM role ARN should not have region")
	}
	if !accountRegex.MatchString(roleArn.AccountID) {
		return errors.Errorf("IAM role ARN should have account identifier matching %s", accountRegex)
	}
	if !resourceRegex.MatchString(roleArn.Resource) {
		return errors.Errorf("IAM role ARN should have resource part matching %s", resourceRegex)
	}

	return nil
}
