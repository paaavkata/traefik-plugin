package traefik_gateway_plugin

import (
	"context"
	"fmt"
	"time"
)

// RateLimiter implements a fixed-window rate limiter backed by Redis.
type RateLimiter struct {
	client *respRedis
	prefix string
	log    *pluginLogger
}

func newRateLimiter(redisURL, password, prefix string, db int, log *pluginLogger) (*RateLimiter, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, err := dialRedis(ctx, redisURL, password, db, log)
	if err != nil {
		return nil, fmt.Errorf("redis dial failed: %w", err)
	}

	return &RateLimiter{
		client: client,
		prefix: prefix,
		log:    log,
	}, nil
}

// RateLimitResult contains the outcome of a rate limit check.
type RateLimitResult struct {
	Allowed   bool
	Remaining int
	Limit     int
	ResetAt   time.Time
}

// Check performs a fixed-window rate limit check.
func (rl *RateLimiter) Check(ctx context.Context, key, endpointUID string, limit, windowSeconds int) (*RateLimitResult, error) {
	if limit <= 0 {
		rl.log.debugf("rate limit skipped limit<=0 endpoint_uid=%s key=%s", endpointUID, key)
		return &RateLimitResult{Allowed: false, Limit: 0}, nil
	}

	checkStart := time.Now()
	window := time.Duration(windowSeconds) * time.Second
	now := time.Now()
	windowStart := now.Truncate(window)
	resetAt := windowStart.Add(window)

	redisKey := fmt.Sprintf("%s%s:%s:%d", rl.prefix, key, endpointUID, windowStart.Unix())

	count, err := rl.client.incr(ctx, redisKey)
	if err != nil {
		rl.log.debugf("rate limit redis INCR failed duration=%s endpoint_uid=%s error=%v", since(checkStart), endpointUID, err)
		return nil, fmt.Errorf("redis incr: %w", err)
	}

	if count == 1 {
		ttlSec := int((window + time.Second).Seconds())
		if ttlSec < 1 {
			ttlSec = 1
		}
		if err := rl.client.expire(ctx, redisKey, ttlSec); err != nil {
			rl.log.debugf("rate limit redis EXPIRE failed duration=%s endpoint_uid=%s error=%v", since(checkStart), endpointUID, err)
			return nil, fmt.Errorf("redis expire: %w", err)
		}
	}

	remaining := limit - int(count)
	if remaining < 0 {
		remaining = 0
	}

	res := &RateLimitResult{
		Allowed:   count <= int64(limit),
		Remaining: remaining,
		Limit:     limit,
		ResetAt:   resetAt,
	}
	rl.log.debugf("rate limit check endpoint_uid=%s plan_key=%s redis_key=%s duration=%s incr=%d allowed=%v remaining=%d limit=%d window=%ds reset_unix=%d",
		endpointUID, key, redisKey, since(checkStart), count, res.Allowed, res.Remaining, res.Limit, windowSeconds, res.ResetAt.Unix())
	return res, nil
}

func (rl *RateLimiter) Close() error {
	if rl.client != nil {
		return rl.client.Close()
	}
	return nil
}
