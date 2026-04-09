package middleware

import (
	"context"
	"time"

	"github.com/Arisgod1/zkp_rkp_go/internal/ratelimit"
	"github.com/Arisgod1/zkp_rkp_go/pkg/errs"
	"github.com/Arisgod1/zkp_rkp_go/pkg/response"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func MultiLayerRateLimitMiddleware(
	rdb *redis.Client,
	keyPrefix string,
	bucketCapacity int,
	bucketRefillPerSecond float64,
	windowLimit int,
	window time.Duration,
) gin.HandlerFunc {
	bucket := ratelimit.NewTokenBucketLimiter(rdb, ratelimit.TokenBucketConfig{
		Capacity:        bucketCapacity,
		RefillPerSecond: bucketRefillPerSecond,
		KeyPrefix:       "tb:" + keyPrefix,
		TTL:             window,
	})
	windowLimiter := ratelimit.NewSlidingWindowLimiter(rdb, ratelimit.SlidingWindowConfig{
		Limit:     windowLimit,
		Window:    window,
		KeyPrefix: "sw:" + keyPrefix,
	})

	return ratelimit.NewMultiLayerLimiter(bucket, windowLimiter).Middleware()
}

func RateLimitMiddleware(rdb *redis.Client, ctx context.Context, keyPrefix string, limit int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		key := keyPrefix + ":" + ip

		count, err := rdb.Incr(ctx, key).Result()
		if err != nil {
			response.JSONError(c, errs.CommonInternalError.Status, errs.CommonInternalError.Code, "rate limit backend error")
			c.Abort()
			return
		}

		if count == 1 {
			_ = rdb.Expire(ctx, key, window).Err()
		}

		if count > int64(limit) {
			ttl, _ := rdb.TTL(ctx, key).Result()
			if ttl > 0 {
				c.Header("Retry-After", ttl.String())
			}
			response.JSONError(c, errs.CommonRateLimited.Status, errs.CommonRateLimited.Code, errs.CommonRateLimited.Message)
			c.Abort()
			return
		}

		c.Next()
	}
}
