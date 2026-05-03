package traefik_gateway_plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter implements a sliding-window rate limiter backed by Redis.
type RateLimiter struct {
	client *redis.Client
	prefix string
}

func newRateLimiter(redisURL, password, prefix string, db int) (*RateLimiter, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		opts = &redis.Options{Addr: redisURL}
	}
	if password != "" {
		opts.Password = password
	}
	opts.DB = db

	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping failed: %w", err)
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
// key: the identity (user ID or session ID)
// endpointUID: the endpoint being accessed
// limit: max requests allowed
// windowSeconds: the window duration
func (rl *RateLimiter) Check(ctx context.Context, key, endpointUID string, limit, windowSeconds int) (*RateLimitResult, error) {
	if limit <= 0 {
		return &RateLimitResult{Allowed: false, Limit: 0}, nil
	}

	window := time.Duration(windowSeconds) * time.Second
	now := time.Now()
	windowStart := now.Truncate(window)
	resetAt := windowStart.Add(window)

	redisKey := fmt.Sprintf("%s%s:%s:%d", rl.prefix, key, endpointUID, windowStart.Unix())

	pipe := rl.client.Pipeline()
	incrCmd := pipe.Incr(ctx, redisKey)
	pipe.ExpireNX(ctx, redisKey, window+time.Second)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("redis pipeline: %w", err)
	}

	count := int(incrCmd.Val())
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	return &RateLimitResult{
		Allowed:   count <= limit,
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
