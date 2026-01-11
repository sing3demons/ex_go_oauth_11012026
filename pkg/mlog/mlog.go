package mlog

import (
	"context"

	"github.com/sing3demons/oauth/kp/pkg/logger"
)

func L(ctx context.Context) logger.ILogger {
	if ctx == nil {
		return logger.NewLogger("", "")
	}
	l, ok := ctx.Value(logger.LoggerKey).(logger.ILogger)
	if !ok || l == nil {
		return logger.NewLogger("", "")
	}

	return l
}
