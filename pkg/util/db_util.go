package util

import (
	"context"
	"fmt"
	"net/url"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresDatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
	SSLMode  string `yaml:"sslmode"`
	PoolSize int    `yaml:"pool"`
}

func NewPostgresDBPool(config PostgresDatabaseConfig) (*pgxpool.Pool, error) {
	connString := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s&pool_max_conns=%d",
		url.PathEscape(config.User),
		url.PathEscape(config.Password),
		url.PathEscape(config.Host),
		config.Port,
		url.PathEscape(config.Database),
		url.QueryEscape(config.SSLMode),
		config.PoolSize,
	)

	dbPool, err := pgxpool.New(
		context.Background(),
		connString,
	)

	if err != nil {
		return nil, fmt.Errorf("open connection to database: %w", err)
	}

	err = dbPool.Ping(context.Background())
	if err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return dbPool, nil
}
