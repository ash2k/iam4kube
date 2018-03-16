package logz

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestContextWithLogger(t *testing.T) {
	t.Parallel()

	type key string
	cKey := key("foo")
	cVal := "bar"
	ctx := context.WithValue(context.Background(), cKey, cVal)

	ctxLogger := ContextWithLogger(ctx, nil)

	assert.NotNil(t, ctxLogger.Value(cKey), "value was not inherited from parent correctly: did not exist")
	rVal, ok := ctxLogger.Value(cKey).(string)
	assert.True(t, ok, "value was not inherited from parent correctly: it was not a string")
	assert.Equal(t, cVal, rVal, "value was not inherited from parent correctly: different value")

}

func TestLoggerFromContex(t *testing.T) {
	t.Parallel()

	logger, _ := zap.NewProduction()
	ctxLogger := ContextWithLogger(context.Background(), logger)

	require.NotPanics(t, func() {
		LoggerFromContext(ctxLogger)
	})

	loggerFromContext := LoggerFromContext(ctxLogger)
	assert.Equal(t, loggerFromContext, logger, "The logger we gave the parent, was not the same in the child")
}

func TestGetLoggerPanicsOnBadContext(t *testing.T) {
	t.Parallel()

	ctxLogger := context.Background()

	assert.Panics(t, func() {
		LoggerFromContext(ctxLogger)
	})
}

type LoggerOutput struct {
	Level   string `json:"level"`
	Message string `json:"msg"`
}

// TestLogger just ensures that the output is working
func TestLogger(t *testing.T) {
	var out bytes.Buffer
	logger := Logger("info", "json", &out)

	logger.Info("Hello")

	data := LoggerOutput{}
	err := json.NewDecoder(
		bytes.NewReader(out.Bytes()),
	).Decode(&data)

	require.NoError(t, err)
	assert.Equal(t, "info", data.Level)
	assert.Equal(t, "Hello", data.Message)
}
