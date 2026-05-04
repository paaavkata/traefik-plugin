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
}

func newRateLimiter(redisURL, password, prefix string, db int) (*RateLimiter, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, err := dialRedis(ctx, redisURL, password, db)
	if err != nil {
		return nil, fmt.Errorf("redis dial failed: %w", err)
	}

	return &RateLimiter{
		client: client,
		prefix: prefix,
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
		return &RateLimitResult{Allowed: false, Limit: 0}, nil
	}

	window := time.Duration(windowSeconds) * time.Second
	now := time.Now()
	windowStart := now.Truncate(window)
	resetAt := windowStart.Add(window)

	redisKey := fmt.Sprintf("%s%s:%s:%d", rl.prefix, key, endpointUID, windowStart.Unix())

	count, err := rl.client.incr(ctx, redisKey)
	if err != nil {
		return nil, fmt.Errorf("redis incr: %w", err)
	}

	if count == 1 {
		ttlSec := int((window + time.Second).Seconds())
		if ttlSec < 1 {
			ttlSec = 1
		}
		if err := rl.client.expire(ctx, redisKey, ttlSec); err != nil {
			return nil, fmt.Errorf("redis expire: %w", err)
		}
	}

	remaining := limit - int(count)
	if remaining < 0 {
		remaining = 0
	}

	return &RateLimitResult{
		Allowed:   count <= int64(limit),
		Remaining: remaining,
		Limit:     limit,
		ResetAt:   resetAt,
	}, nil
}

func (rl *RateLimiter) Close() error {
	if rl.client != nil {
		return rl.client.Close()
	}
	return nil
}
