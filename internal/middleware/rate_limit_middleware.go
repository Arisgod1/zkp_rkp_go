package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func RateLimitMiddleware(rdb *redis.Client, ctx context.Context, keyPrefix string, limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		key := keyPrefix + ":" + ip

		count, err := rdb.Incr(ctx, key).Result()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "rate limit backend error"})
			c.Abort()
			return
		}

		if count == 1 {
			_ = rdb.Expire(ctx, key, window).Err()
		}

		if count > int64(limit) {
			ttl, _ := rdb.TTL(ctx, key).Result()
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":        "too many requests",
				"retryAfterMs": ttl.Milliseconds(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
