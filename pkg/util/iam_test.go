package util

import (
	"testing"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRolePathAndNameFromRoleArn(t *testing.T) {
	t.Parallel()
	testCases := map[string]struct {
		arn              string
		expectedRoleName string
		expectedError    string
	}{
		"valid": {
			arn:              "arn:aws:iam::123456789012:role/this/is/a/path/roleName",
			expectedRoleName: "this/is/a/path/roleName",
		},
		"valid only role": {
			arn:              "arn:aws:iam::123456789012:role/roleName",
			expectedRoleName: "roleName",
		},
		"only path": {
			arn:           "arn:aws:iam::123456789012:role/this/is/a/path/",
			expectedError: `ARN resource part does not contain a valid role name`,
		},
		"no role no path no name": {
			arn:           "arn:aws:iam::123456789012:",
			expectedError: `ARN resource part does not contain a valid role name`,
		},
		"no path no name 1": {
			arn:           "arn:aws:iam::123456789012:role/",
			expectedError: `ARN resource part does not contain a valid role name`,
		},
		"no path no name 2": {
			arn:           "arn:aws:iam::123456789012:role",
			expectedError: `ARN resource part does not contain a valid role name`,
		},
	}
	for name, tc := range testCases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			arnParsed, err := arn.Parse(tc.arn)
			require.NoError(t, err)

			actualRoleName, actualErr := RolePathAndNameFromRoleArn(arnParsed)
			if tc.expectedRoleName != "" {
				assert.NoError(t, actualErr)
				assert.Equal(t, tc.expectedRoleName, actualRoleName)
			} else {
				assert.EqualError(t, actualErr, tc.expectedError)
			}
		})
	}
}
