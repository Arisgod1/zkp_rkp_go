package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type TokenBucketConfig struct {
	Capacity        int
	RefillPerSecond float64
	KeyPrefix       string
	TTL             time.Duration
}

type TokenBucketLimiter struct {
	rdb             *redis.Client
	capacity        int
	refillPerSecond float64
	keyPrefix       string
	ttl             time.Duration
}

var tokenBucketScript = redis.NewScript(`
local key = KEYS[1]
local nowMs = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local refillPerSec = tonumber(ARGV[3])
local ttlSec = tonumber(ARGV[4])

local tokens = tonumber(redis.call('HGET', key, 'tokens'))
local lastMs = tonumber(redis.call('HGET', key, 'last_ms'))

if tokens == nil then tokens = capacity end
if lastMs == nil then lastMs = nowMs end

local elapsed = math.max(0, nowMs - lastMs) / 1000.0
tokens = math.min(capacity, tokens + elapsed * refillPerSec)

local allowed = 0
local waitMs = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  waitMs = math.ceil((1 - tokens) / refillPerSec * 1000)
end

redis.call('HSET', key, 'tokens', tokens, 'last_ms', nowMs)
redis.call('EXPIRE', key, ttlSec)

return {allowed, waitMs}
`)

func NewTokenBucketLimiter(rdb *redis.Client, cfg TokenBucketConfig) *TokenBucketLimiter {
	if cfg.Capacity <= 0 {
		cfg.Capacity = 10
	}
	if cfg.RefillPerSecond <= 0 {
		cfg.RefillPerSecond = 1
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "tb"
	}
	if cfg.TTL <= 0 {
		cfg.TTL = time.Minute
	}

	return &TokenBucketLimiter{
		rdb:             rdb,
		capacity:        cfg.Capacity,
		refillPerSecond: cfg.RefillPerSecond,
		keyPrefix:       cfg.KeyPrefix,
		ttl:             cfg.TTL,
	}
}

func (t *TokenBucketLimiter) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	bucketKey := fmt.Sprintf("%s:%s", t.keyPrefix, key)
	nowMs := time.Now().UnixMilli()
	ttlSec := int(t.ttl.Seconds())
	if ttlSec <= 0 {
		ttlSec = 1
	}

	res, err := tokenBucketScript.Run(ctx, t.rdb, []string{bucketKey}, nowMs, t.capacity, t.refillPerSecond, ttlSec).Result()
	if err != nil {
		return false, 0, err
	}

	arr, ok := res.([]interface{})
	if !ok || len(arr) != 2 {
		return false, 0, fmt.Errorf("invalid token bucket result")
	}

	allowed, ok := arr[0].(int64)
	if !ok {
		return false, 0, fmt.Errorf("invalid allowed type")
	}
	waitMs, ok := arr[1].(int64)
	if !ok {
		return false, 0, fmt.Errorf("invalid wait type")
	}

	return allowed == 1, time.Duration(waitMs) * time.Millisecond, nil
}

func (t *TokenBucketLimiter) Rollback(ctx context.Context, key string) {
	bucketKey := fmt.Sprintf("%s:%s", t.keyPrefix, key)
	_ = t.rdb.HIncrBy(ctx, bucketKey, "tokens", 1).Err()
}
