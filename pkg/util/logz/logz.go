package logz

import (
	"os"

	"github.com/aws/aws-sdk-go/aws/arn"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func RoleArn(roleArn arn.ARN) zapcore.Field {
	return zap.Stringer("role_arn", roleArn)
}

func Logger(loggingLevel, logEncoding string) *zap.Logger {
	var levelEnabler zapcore.Level
	switch loggingLevel {
	case "debug":
		levelEnabler = zap.DebugLevel
	case "warn":
		levelEnabler = zap.WarnLevel
	case "error":
		levelEnabler = zap.ErrorLevel
	default:
		levelEnabler = zap.InfoLevel
	}
	var logEncoder func(zapcore.EncoderConfig) zapcore.Encoder
	if logEncoding == "console" {
		logEncoder = zapcore.NewConsoleEncoder
	} else {
		logEncoder = zapcore.NewJSONEncoder
	}
	return zap.New(
		zapcore.NewCore(
			logEncoder(zap.NewProductionEncoderConfig()),
			zapcore.Lock(zapcore.AddSync(os.Stderr)),
			levelEnabler,
		),
	)
}

func DevelopmentLogger() *zap.Logger {
	syncer := zapcore.AddSync(os.Stderr)
	return zap.New(
		zapcore.NewCore(
			zapcore.NewConsoleEncoder(zap.NewProductionEncoderConfig()),
			zapcore.Lock(syncer),
			zap.InfoLevel,
		),
		zap.Development(),
		zap.ErrorOutput(syncer),
	)
}
