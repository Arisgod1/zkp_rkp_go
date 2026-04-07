package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func LoggingMiddleware(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		latency := time.Since(start)
		reqID, _ := c.Get("requestId")
		username, _ := c.Get("username")

		log.Info("http_request",
			zap.String("requestId", toStr(reqID)),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.String("clientIP", c.ClientIP()),
			zap.String("username", toStr(username)),
			zap.Duration("latency", latency),
		)
	}
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
