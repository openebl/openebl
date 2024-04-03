package server

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
	formatter "github.com/bluexlab/logrus-formatter"
	otlp_util "github.com/bluexlab/otlp-util-go"
	"github.com/gobuffalo/pop"
	"github.com/gobuffalo/pop/logging"
	"github.com/openebl/openebl/pkg/config"
	"github.com/openebl/openebl/pkg/relay/server/storage/postgres"
	"github.com/openebl/openebl/pkg/util"
	"github.com/sirupsen/logrus"
)

const appName string = "relay-server"

type RelayServerApp struct{}

type RelayServerCli struct {
	Server  struct{} `cmd:"" help:"Run relay server."`
	Migrate struct {
		Migrations string `short:"p" long:"path" type:"existingdir" help:"Path to the migration files" default:"migrations"`
	} `cmd:"" help:"Migrate database."`
	Config string `short:"c" long:"config" type:"existingfile" help:"Path to the configuration file" default:"config.yaml"`
}

type RelayServerConfig struct {
	Database     util.PostgresDatabaseConfig `yaml:"database"`
	LocalAddress string                      `yaml:"local_address"`
	OtherPeers   []string                    `yaml:"other_peers"`
	OTLPEndpoint string                      `yaml:"otlp_endpoint"`
}

func (r *RelayServerApp) Run() error {
	formatter.InitLogger()

	var cli RelayServerCli
	kctx := kong.Parse(&cli)
	switch kctx.Command() {
	case "server":
		return r.runServer(cli)
	case "migrate":
		return r.runMigrate(cli)
	}

	return nil
}

func (r *RelayServerApp) runServer(cli RelayServerCli) error {
	cfg := RelayServerConfig{}
	if err := config.FromFile(cli.Config, &cfg); err != nil {
		logrus.Errorf("failed to load config: %v", err)
		os.Exit(1)
	}

	eventStorage, err := postgres.NewEventStorageWithConfig(cfg.Database)
	if err != nil {
		logrus.Errorf("failed to create event storage: %v", err)
		os.Exit(1)
	}

	if otlpEndpoint := cfg.OTLPEndpoint; otlpEndpoint != "" {
		otlp_util.InitGlobalTracer(
			otlp_util.WithEndPoint(otlpEndpoint),
			otlp_util.WithServiceName(appName),
			otlp_util.WithInSecure(),
			otlp_util.WithErrorHandler(func(err error) {
				logrus.Warnf("OTLP error: %v", err)
			}),
		)
	}

	relayServer, err := NewServer(
		WithLocalAddress(cfg.LocalAddress),
		WithPeers(cfg.OtherPeers),
		WithStorage(eventStorage),
	)
	if err != nil {
		logrus.Errorf("failed to create relay server: %v", err)
		os.Exit(1)
	}

	logrus.Info("starting relay server.")
	go func() {
		if err := relayServer.Run(); err != nil {
			logrus.Errorf("failed to start relay server: %v", err)
			os.Exit(1)
		}
	}()

	r.waitForInterrupt()
	relayServer.Close()
	return nil
}

func (r *RelayServerApp) runMigrate(cli RelayServerCli) error {
	pop.SetLogger(popLogger)
	cfg := RelayServerConfig{}
	if err := config.FromFile(cli.Config, &cfg); err != nil {
		logrus.Errorf("failed to load config: %v", err)
		os.Exit(1)
	}

	cd := pop.ConnectionDetails{
		Dialect:  "postgres",
		Database: cfg.Database.Database,
		Host:     cfg.Database.Host,
		Port:     fmt.Sprintf("%d", cfg.Database.Port),
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
	}
	conn, err := pop.NewConnection(&cd)
	if err != nil {
		logrus.Errorf("failed to create connection: %v", err)
		os.Exit(1)
	}

	if err := conn.Dialect.CreateDB(); err != nil {
		logrus.Warnf("failed to create database: %v", err)
	}

	migrator, err := pop.NewFileMigrator(cli.Migrate.Migrations, conn)
	if err != nil {
		logrus.Errorf("failed to create migrator: %v", err)
		os.Exit(1)
	}
	// Remove SchemaPath to prevent migrator try to dump schema.
	migrator.SchemaPath = ""

	if err := migrator.Up(); err != nil {
		logrus.Errorf("failed to migrate: %v", err)
		os.Exit(1)
	}

	return nil
}

func (r *RelayServerApp) waitForInterrupt() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logrus.Info("Shutting down server......")
}

func popLogger(lvl logging.Level, s string, args ...interface{}) {
	switch lvl {
	case logging.Debug:
		logrus.Debugf(s, args...)
	case logging.Info:
		logrus.Infof(s, args...)
	case logging.Warn:
		logrus.Warnf(s, args...)
	case logging.Error:
		logrus.Errorf(s, args...)
	case logging.SQL:
		// Do nothing because we don't want to log SQL queries.
	}
}
