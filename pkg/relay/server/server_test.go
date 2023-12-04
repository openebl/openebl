package server_test

import (
	"sync"
	"testing"

	"github.com/openebl/openebl/pkg/relay/server"
	"github.com/openebl/openebl/pkg/relay/server/storage/postgres"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	t.Skip()
	serverCfg := server.ServerConfig{
		DbConfig: postgres.DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "xdlai",
			Database: "relay_server_test",
			SSLMode:  "disable",
			PoolSize: 5,
		},
		LocalAddress: "localhost:9001",
		OtherPeers: []string{
			"ws://localhost:9002",
		},
	}

	serverCfg2 := server.ServerConfig{
		DbConfig: postgres.DatabaseConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "xdlai",
			Database: "relay_server_test2",
			SSLMode:  "disable",
			PoolSize: 5,
		},
		LocalAddress: "localhost:9002",
		OtherPeers: []string{
			"ws://localhost:9001",
		},
	}

	srv1, err := server.NewServer(serverCfg)
	require.NoError(t, err)

	srv2, err := server.NewServer(serverCfg2)
	require.NoError(t, err)

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		srv1.Run()
	}()
	go func() {
		defer wg.Done()
		srv2.Run()
	}()
	wg.Wait()
}
