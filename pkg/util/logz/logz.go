package logz

import (
	"github.com/aws/aws-sdk-go/aws/arn"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func RoleArn(roleArn arn.ARN) zapcore.Field {
	return zap.Stringer("role_arn", roleArn)
}
