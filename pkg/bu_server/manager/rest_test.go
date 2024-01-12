package manager_test

import (
	"testing"

	"github.com/openebl/openebl/pkg/bu_server/manager"
	"github.com/openebl/openebl/pkg/util"
)

func TestRest(t *testing.T) {
	dbConfig := util.PostgresDatabaseConfig{
		Host:     "localhost",
		Port:     5432,
		User:     "xdlai",
		Database: "bu_server_test",
		SSLMode:  "disable",
		PoolSize: 5,
	}

	restConfig := manager.ManagerAPIConfig{
		Database:     dbConfig,
		LocalAddress: "localhost:9100",
	}

	rest, err := manager.NewManagerAPI(restConfig)
	if err != nil {
		t.Fatal(err)
	}
	_ = rest
}
