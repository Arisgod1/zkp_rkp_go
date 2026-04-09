package ratelimit

import (
	"github.com/Arisgod1/zkp_rkp_go/pkg/errs"
	"github.com/Arisgod1/zkp_rkp_go/pkg/response"
	"github.com/gin-gonic/gin"
)

type MultiLayerLimiter struct {
	bucket *TokenBucketLimiter
	window *SlidingWindowLimiter
}

func NewMultiLayerLimiter(bucket *TokenBucketLimiter, window *SlidingWindowLimiter) *MultiLayerLimiter {
	return &MultiLayerLimiter{bucket: bucket, window: window}
}

func (m *MultiLayerLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		key := c.ClientIP()

		allowed, wait, err := m.bucket.Allow(ctx, key)
		if err != nil {
			response.JSONError(c, errs.CommonInternalError.Status, errs.CommonInternalError.Code, "rate limit backend error")
			c.Abort()
			return
		}
		if !allowed {
			c.Header("Retry-After", wait.String())
			response.JSONError(c, errs.CommonRateLimited.Status, errs.CommonRateLimited.Code, errs.CommonRateLimited.Message)
			c.Abort()
			return
		}

		allowed, wait, err = m.window.Allow(ctx, key)
		if err != nil {
			m.bucket.Rollback(ctx, key)
			response.JSONError(c, errs.CommonInternalError.Status, errs.CommonInternalError.Code, "rate limit backend error")
			c.Abort()
			return
		}
		if !allowed {
			m.bucket.Rollback(ctx, key)
			c.Header("Retry-After", wait.String())
			response.JSONError(c, errs.CommonRateLimited.Status, errs.CommonRateLimited.Code, errs.CommonRateLimited.Message)
			c.Abort()
			return
		}

		c.Next()
	}
}
