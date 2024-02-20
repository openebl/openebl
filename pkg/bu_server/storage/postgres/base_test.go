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

type BaseTestSuite struct {
	suite.Suite
	ctx    context.Context
	pgPool *pgxpool.Pool
}

func (s *BaseTestSuite) SetupTest() {
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
		"trade_document",
		"certificate",
		"certificate_history",
		"business_unit",
		"business_unit_history",
		"business_unit_authentication",
		"business_unit_authentication_history",
		"api_key",
		"api_key_history",
		"application",
		"application_history",
	}
	for _, tableName := range tableNames {
		_, err := pool.Exec(context.Background(), fmt.Sprintf(`DELETE FROM %q`, tableName))
		s.Require().NoError(err)
	}
}

func (s *BaseTestSuite) TearDownTest() {
	s.pgPool.Close()
}
