package testing

import (
	"bytes"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// TB is *testing.T or *testing.B
type TB interface {
	Log(args ...interface{})
}

func DevelopmentLogger(tb TB) *zap.Logger {
	cfg := zap.NewProductionEncoderConfig()
	cfg.EncodeTime = zapcore.ISO8601TimeEncoder
	syncer := zapcore.AddSync(&TBWriter{TB: tb})
	return zap.New(
		zapcore.NewCore(
			zapcore.NewConsoleEncoder(cfg),
			syncer,
			zap.DebugLevel,
		),
		zap.Development(),
		zap.ErrorOutput(syncer),
	)
}

type TBWriter struct {
	TB TB
}

func (tb *TBWriter) Write(p []byte) (int, error) {
	tb.TB.Log(string(bytes.TrimRight(p, "\r\n")))
	return len(p), nil
}
