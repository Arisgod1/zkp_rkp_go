package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type SlidingWindowConfig struct {
	Limit     int
	Window    time.Duration
	KeyPrefix string
}

type SlidingWindowLimiter struct {
	rdb       *redis.Client
	limit     int
	window    time.Duration
	keyPrefix string
}

var slidingWindowScript = redis.NewScript(`
local key = KEYS[1]
local nowMs = tonumber(ARGV[1])
local windowMs = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local ttlSec = tonumber(ARGV[5])

redis.call('ZREMRANGEBYSCORE', key, 0, nowMs - windowMs)
local count = redis.call('ZCARD', key)

if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local waitMs = windowMs
  if oldest[2] then
    waitMs = math.max(1, math.floor(windowMs - (nowMs - tonumber(oldest[2]))))
  end
  return {0, waitMs}
end

redis.call('ZADD', key, nowMs, member)
redis.call('EXPIRE', key, ttlSec)
return {1, 0}
`)

func NewSlidingWindowLimiter(rdb *redis.Client, cfg SlidingWindowConfig) *SlidingWindowLimiter {
	if cfg.Limit <= 0 {
		cfg.Limit = 60
	}
	if cfg.Window <= 0 {
		cfg.Window = time.Minute
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "sw"
	}

	return &SlidingWindowLimiter{
		rdb:       rdb,
		limit:     cfg.Limit,
		window:    cfg.Window,
		keyPrefix: cfg.KeyPrefix,
	}
}

func (s *SlidingWindowLimiter) Allow(ctx context.Context, key string) (bool, time.Duration, error) {
	windowKey := fmt.Sprintf("%s:%s", s.keyPrefix, key)
	nowMs := time.Now().UnixMilli()
	ttlSec := int(s.window.Seconds())
	if ttlSec <= 0 {
		ttlSec = 1
	}

	member := fmt.Sprintf("%d-%s", nowMs, uuid.NewString())
	res, err := slidingWindowScript.Run(ctx, s.rdb, []string{windowKey}, nowMs, s.window.Milliseconds(), s.limit, member, ttlSec).Result()
	if err != nil {
		return false, 0, err
	}

	arr, ok := res.([]interface{})
	if !ok || len(arr) != 2 {
		return false, 0, fmt.Errorf("invalid sliding window result")
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
