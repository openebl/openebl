package postgres_test

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/go-testfixtures/testfixtures/v3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/openebl/openebl/pkg/relay/server/storage"
	"github.com/openebl/openebl/pkg/relay/server/storage/postgres"
	"github.com/stretchr/testify/suite"
)

type EventStorageTestSuite struct {
	suite.Suite
	storage storage.RelayServerDataStore
	pgPool  *pgxpool.Pool
}

func TestEventStorage(t *testing.T) {
	suite.Run(t, new(EventStorageTestSuite))
}

func (s *EventStorageTestSuite) SetupSuite() {
	dbHost := os.Getenv("DATABASE_HOST")
	dbPort, err := strconv.Atoi(os.Getenv("DATABASE_PORT"))
	if err != nil {
		dbPort = 5432
	}
	dbName := os.Getenv("DATABASE_NAME")
	userName := os.Getenv("DATABASE_USER")
	password := os.Getenv("DATABASE_PASSWORD")

	config := postgres.DatabaseConfig{
		Host:     dbHost,
		Port:     dbPort,
		Database: dbName,
		User:     userName,
		Password: password,
		SSLMode:  "disable",
		PoolSize: 5,
	}

	pool, err := postgres.NewDBPool(config)
	s.Require().NoError(err)
	s.storage = postgres.NewEventStorage(pool)
	s.pgPool = pool

	tableNames := []string{
		"event",
	}
	for _, tableName := range tableNames {
		_, err := pool.Exec(context.Background(), "TRUNCATE TABLE "+tableName)
		s.Require().NoError(err)
	}
}

func (s *EventStorageTestSuite) TearDownSuite() {
	s.pgPool.Close()
}

func (s *EventStorageTestSuite) TestStoreEvent() {
	ctx := context.Background()
	ts := time.Now().Unix()
	eventID := "test_event_id"
	eventType := 1001
	event := []byte("test_event")

	offset, err := s.storage.StoreEvent(ctx, ts, eventID, eventType, event)
	s.Require().NoError(err)
	s.Require().NotZero(offset)
}

func (s *EventStorageTestSuite) TestListEvents() {
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(s.pgPool)
	fixtures, err := testfixtures.New(
		testfixtures.Database(db),
		testfixtures.Dialect("postgres"),
		testfixtures.Directory("testdata/list_event"),
	)
	s.Require().NoError(err)
	s.Require().NoError(fixtures.Load())

	// Unfiltered and unlimited query
	request := storage.ListEventRequest{
		Offset:    0,
		EventType: 0,
		Limit:     10,
	}
	result, err := s.storage.ListEvents(ctx, request)
	s.Require().NoError(err)
	s.Require().Equal(4, len(result.Events))
	s.Assert().Equal(int64(103), result.MaxOffset)
	s.Assert().Equal("event1 content", string(result.Events[0]))
	s.Assert().Equal("cert1 content", string(result.Events[1]))
	s.Assert().Equal("event2 content", string(result.Events[2]))
	s.Assert().Equal("cert2 content", string(result.Events[3]))
	// End of Unfiltered and unlimited query

	// Limited query
	request = storage.ListEventRequest{
		Offset:    0,
		EventType: 0,
		Limit:     2,
	}
	result, err = s.storage.ListEvents(ctx, request)
	s.Require().NoError(err)
	s.Require().Equal(2, len(result.Events))
	s.Assert().Equal(int64(101), result.MaxOffset)
	s.Assert().Equal("event1 content", string(result.Events[0]))
	s.Assert().Equal("cert1 content", string(result.Events[1]))
	// End of Limited query

	// Filtered by EventType
	request = storage.ListEventRequest{
		Offset:    0,
		EventType: 1001,
		Limit:     10,
	}
	result, err = s.storage.ListEvents(ctx, request)
	s.Require().NoError(err)
	s.Require().Equal(2, len(result.Events))
	s.Assert().Equal(int64(102), result.MaxOffset)
	s.Assert().Equal("event1 content", string(result.Events[0]))
	s.Assert().Equal("event2 content", string(result.Events[1]))
	// End of Filtered by EventType

	// Filtered by Offset
	request = storage.ListEventRequest{
		Offset:    102,
		EventType: 0,
		Limit:     10,
	}
	result, err = s.storage.ListEvents(ctx, request)
	s.Require().NoError(err)
	s.Require().Equal(1, len(result.Events))
	s.Assert().Equal(int64(103), result.MaxOffset)
	s.Assert().Equal("cert2 content", string(result.Events[0]))
	// End of Filtered by Offset
}
