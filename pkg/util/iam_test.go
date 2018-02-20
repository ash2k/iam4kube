package util

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoleNameFromRoleArn(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		arn              string
		expectedRoleName string
		expectedError    string
	}{
		"valid": {
			arn:              "arn:aws:iam::123456789012:role/this/is/a/path/roleName",
			expectedRoleName: "roleName",
		},
		"only path": {
			arn:           "arn:aws:iam::123456789012:role/this/is/a/path/",
			expectedError: `failed to extract IAM role name from ARN resource part. ARN "arn:aws:iam::123456789012:role/this/is/a/path/"`,
		},
		"no role no path no name": {
			arn:           "arn:aws:iam::123456789012:",
			expectedError: `failed to extract IAM role name from ARN resource part. ARN "arn:aws:iam::123456789012:"`,
		},
		"no path no name 1": {
			arn:           "arn:aws:iam::123456789012:role/",
			expectedError: `failed to extract IAM role name from ARN resource part. ARN "arn:aws:iam::123456789012:role/"`,
		},
		"no path no name 2": {
			arn:           "arn:aws:iam::123456789012:role",
			expectedError: `failed to extract IAM role name from ARN resource part. ARN "arn:aws:iam::123456789012:role"`,
		},
	}
	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			arnParsed, err := arn.Parse(tc.arn)
			require.NoError(t, err)

			actualRoleName, actualErr := RoleNameFromRoleArn(arnParsed)
			if tc.expectedRoleName != "" {
				assert.NoError(t, actualErr)
				assert.Equal(t, tc.expectedRoleName, actualRoleName)
			} else {
				assert.EqualError(t, actualErr, tc.expectedError)
			}
		})
	}
}
