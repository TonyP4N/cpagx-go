package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// CacheService Redis缓存服务
type CacheService struct {
	client *redis.Client
}

// CacheConfig 缓存配置
type CacheConfig struct {
	Addr         string
	Password     string
	DB           int
	PoolSize     int
	MinIdleConns int
	MaxRetries   int
}

// NewCacheService 创建缓存服务
func NewCacheService(config *CacheConfig) *CacheService {
	client := redis.NewClient(&redis.Options{
		Addr:         config.Addr,
		Password:     config.Password,
		DB:           config.DB,
		PoolSize:     config.PoolSize,
		MinIdleConns: config.MinIdleConns,
		MaxRetries:   config.MaxRetries,
	})

	return &CacheService{
		client: client,
	}
}

// Set 设置缓存
func (cs *CacheService) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %v", err)
	}

	return cs.client.Set(ctx, key, data, expiration).Err()
}

// Get 获取缓存
func (cs *CacheService) Get(ctx context.Context, key string, dest interface{}) error {
	data, err := cs.client.Get(ctx, key).Bytes()
	if err != nil {
		return err
	}

	return json.Unmarshal(data, dest)
}

// SetNX 设置缓存（仅当键不存在时）
func (cs *CacheService) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return false, fmt.Errorf("failed to marshal value: %v", err)
	}

	return cs.client.SetNX(ctx, key, data, expiration).Result()
}

// Delete 删除缓存
func (cs *CacheService) Delete(ctx context.Context, keys ...string) error {
	return cs.client.Del(ctx, keys...).Err()
}

// Exists 检查键是否存在
func (cs *CacheService) Exists(ctx context.Context, keys ...string) (int64, error) {
	return cs.client.Exists(ctx, keys...).Result()
}

// Incr 递增计数器
func (cs *CacheService) Incr(ctx context.Context, key string) (int64, error) {
	return cs.client.Incr(ctx, key).Result()
}

// IncrBy 按指定值递增
func (cs *CacheService) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	return cs.client.IncrBy(ctx, key, value).Result()
}

// Expire 设置过期时间
func (cs *CacheService) Expire(ctx context.Context, key string, expiration time.Duration) error {
	return cs.client.Expire(ctx, key, expiration).Err()
}

// TTL 获取剩余生存时间
func (cs *CacheService) TTL(ctx context.Context, key string) (time.Duration, error) {
	return cs.client.TTL(ctx, key).Result()
}

// Close 关闭连接
func (cs *CacheService) Close() error {
	return cs.client.Close()
}

// HealthCheck 健康检查
func (cs *CacheService) HealthCheck(ctx context.Context) error {
	return cs.client.Ping(ctx).Err()
}

// GetStats 获取统计信息
func (cs *CacheService) GetStats(ctx context.Context) (*redis.PoolStats, error) {
	stats := cs.client.PoolStats()
	return stats, nil
}
