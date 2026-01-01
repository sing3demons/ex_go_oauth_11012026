package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sing3demons/oauth/kp/internal/config"
	"github.com/sing3demons/oauth/kp/pkg/logAction"
	"github.com/sing3demons/oauth/kp/pkg/logger"
	"github.com/sing3demons/oauth/kp/pkg/mlog"
)

type RedisClient struct {
	client *redis.Client
}

type IRedisClient interface {
	Close() error
	Ping() error
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value any, expiration time.Duration) error
	Del(ctx context.Context, keys ...string) error
}

func NewRedisConfig(cfg *config.RedisConfig) (IRedisClient, error) {
	// if cfg == nil || cfg.Addr == "" {
	// 	return nil, errors.New("redis config is nil")
	// }
	fmt.Println("connecting to redis:", cfg.Addr)

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password, // no password set
		DB:       cfg.DB,       // use default DB
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	fmt.Println("redis connected")

	return &RedisClient{client: rdb}, nil
}

func (c *RedisClient) GetClient() *redis.Client {
	return c.client
}

func (c *RedisClient) Close() error {
	return c.client.Close()
}

func (c *RedisClient) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.client.Ping(ctx).Err()
}

func (c *RedisClient) Get(ctx context.Context, key string) (string, error) {
	log := mlog.L(ctx)
	start := time.Now()

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: "redis",
	}).Debug(logAction.DB_REQUEST(logAction.DB_READ, "redis GET"), map[string]any{
		"key": key,
	})

	val, err := c.client.Get(ctx, key).Result()
	elapsedMs := time.Since(start).Milliseconds()

	result := map[string]any{}

	if err == redis.Nil {
		// return "", fmt.Errorf("key %s does not exist", key)
		result = map[string]any{
			"data": nil,
		}
		err = errors.New("not_found")
	} else if err != nil {
		result = map[string]any{
			"error": err.Error(),
		}
	} else {
		result = map[string]any{
			"data": val,
		}
	}
	maskingRules := []logger.MaskingRule{
		{
			Field: "data.PrivateKey", Type: logger.MaskingTypeFull,
		},
		{
			Field: "data.PublicKey", Type: logger.MaskingTypeFull,
		},
	}

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   "redis",
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_READ, "redis GET"), result, maskingRules...)
	return val, err
}

func (c *RedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	log := mlog.L(ctx)
	start := time.Now()

	maskingRules := []logger.MaskingRule{
		{
			Field: "value.PrivateKey", Type: logger.MaskingTypeFull,
		},
		{
			Field: "value.PublicKey", Type: logger.MaskingTypeFull,
		},
	}

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: "redis",
	}).Debug(logAction.DB_REQUEST(logAction.DB_CREATE, "redis SET"), map[string]any{
		"key":        key,
		"value":      value,
		"expiration": expiration,
	}, maskingRules...)

	err := c.client.Set(ctx, key, value, expiration).Err()
	elapsedMs := time.Since(start).Milliseconds()

	result := map[string]any{}
	if err != nil {
		result = map[string]any{
			"error": err.Error(),
		}
	} else {
		result = map[string]any{
			"data": "OK",
		}
	}

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   "redis",
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_CREATE, "redis SET"), result)

	return err
}

func (c *RedisClient) Del(ctx context.Context, keys ...string) error {
	log := mlog.L(ctx)
	start := time.Now()
	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency: "redis",
	}).Debug(logAction.DB_REQUEST(logAction.DB_CREATE, "redis SET"), map[string]any{
		"keys": keys,
	})

	err := c.client.Del(ctx, keys...).Err()
	elapsedMs := time.Since(start).Milliseconds()

	result := map[string]any{}
	if err != nil {
		result = map[string]any{
			"error": err.Error(),
		}
	} else {
		result = map[string]any{
			"data": "OK",
		}
	}

	log.SetDependencyMetadata(logger.DependencyMetadata{
		Dependency:   "redis",
		ResponseTime: elapsedMs,
	}).Debug(logAction.DB_RESPONSE(logAction.DB_DELETE, "redis DEL"), result)
	return err
}
