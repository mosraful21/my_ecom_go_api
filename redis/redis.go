package redis

import (
	"context"
	"github.com/redis/go-redis/v9"
	"my_ecom_api/config"
)

type Client struct {
	RDB *redis.Client
}

func New(cfg *config.Config) *Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	return &Client{
		RDB: rdb,
	}
}

func (r *Client) Ping(ctx context.Context) error {
	return r.RDB.Ping(ctx).Err()
}

func (r *Client) Close() error {
	return r.RDB.Close()
}
