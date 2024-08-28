package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openebl/openebl/pkg/util"
	"github.com/stretchr/testify/suite"
)

type BaseStorageTestSuite struct {
	suite.Suite
	ctx    context.Context
	pgPool *pgxpool.Pool
}

func (s *BaseStorageTestSuite) SetupSuite() {
	s.ctx = context.Background()
	dbHost := os.Getenv("DATABASE_HOST")
	dbPort, err := strconv.Atoi(os.Getenv("DATABASE_PORT"))
	if err != nil {
		dbPort = 5432
	}
	dbName := os.Getenv("DATABASE_NAME")
	userName := os.Getenv("DATABASE_USER")
	password := os.Getenv("DATABASE_PASSWORD")

	config := util.PostgresDatabaseConfig{
		Host:     dbHost,
		Port:     dbPort,
		Database: dbName,
		User:     userName,
		Password: password,
		SSLMode:  "disable",
		PoolSize: 5,
	}

	pool, err := util.NewPostgresDBPool(config)
	s.Require().NoError(err)
	s.pgPool = pool

	tableNames := []string{
		"event",
		"offset",
		"root_cert",
		"cert_revocation_list",
	}
	for _, tableName := range tableNames {
		_, err := pool.Exec(context.Background(), fmt.Sprintf(`TRUNCATE TABLE %q`, tableName))
		s.Require().NoError(err)
	}
}

func (s *BaseStorageTestSuite) TearDownSuite() {
	s.pgPool.Close()
}
