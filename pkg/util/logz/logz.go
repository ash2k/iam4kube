package logz

import (
	"context"
	"errors"
	"io"

	"github.com/aws/aws-sdk-go/aws/arn"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func RoleArn(roleArn arn.ARN) zapcore.Field {
	return zap.Stringer("role_arn", roleArn)
}

func RoleSessionName(sessionName string) zapcore.Field {
	return zap.String("session_name", sessionName)
}

func RemoteIp(ip string) zapcore.Field {
	return zap.String("remote_ip", ip)
}

type loggerContextKeyType uint64

const loggerContextKey loggerContextKeyType = 9007367333159325040

func ContextWithLogger(ctx context.Context, log *zap.Logger) context.Context {
	return context.WithValue(ctx, loggerContextKey, log)
}

func LoggerFromContext(ctx context.Context) *zap.Logger {
	if log, ok := ctx.Value(loggerContextKey).(*zap.Logger); ok && log != nil {
		return log
	}

	panic(errors.New("context did not contain logger, please call ContextWithLogger"))
}

func Logger(loggingLevel, logEncoding string, output io.Writer) *zap.Logger {
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
	lockedSyncer := zapcore.Lock(zapcore.AddSync(output))
	return zap.New(
		zapcore.NewCore(
			logEncoder(zap.NewProductionEncoderConfig()),
			lockedSyncer,
			levelEnabler,
		),
		zap.ErrorOutput(lockedSyncer),
	)
}
