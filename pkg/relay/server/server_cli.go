package server

import (
	"context"
	"crypto/tls"
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
	"github.com/openebl/openebl/pkg/relay/server/cert"
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
	MTLS         MTLSConfig                  `yaml:"mtls"`
}

type MTLSConfig struct {
	Cert           config.MultilineString `yaml:"cert"`
	CertPrivateKey config.MultilineString `yaml:"cert_private_key"`
	CertServer     string                 `yaml:"cert_server"`
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
	ctx := context.Background()
	cfg := RelayServerConfig{}
	if err := config.FromFile(cli.Config, &cfg); err != nil {
		logrus.Errorf("failed to load config: %v", err)
		os.Exit(1)
	}

	dataStorage, err := postgres.NewEventStorageWithConfig(cfg.Database)
	if err != nil {
		logrus.Errorf("failed to create event storage: %v", err)
		os.Exit(1)
	}

	var certMgr cert.CertManager
	var tlsConfig *tls.Config
	if cfg.MTLS.Cert != "" && cfg.MTLS.CertPrivateKey != "" && cfg.MTLS.CertServer != "" {
		logrus.Info("mTLS is enabled.")
		_certMgr := cert.NewCertManager(
			cert.WithCertServerURL(cfg.MTLS.CertServer),
			cert.WithCertStore(dataStorage),
		)
		_tlsConfig, err := cert.NewTLSConfig([]byte(cfg.MTLS.Cert), []byte(cfg.MTLS.CertPrivateKey), _certMgr)
		if err != nil {
			logrus.Errorf("failed to create TLS config: %v", err)
			os.Exit(1)
		}
		certMgr = _certMgr
		tlsConfig = _tlsConfig
	} else {
		logrus.Info("mTLS is not enabled.")
	}

	if endpoint := cfg.OTLPEndpoint; endpoint != "" {
		exporter, err := otlp_util.InitExporter(
			otlp_util.WithContext(ctx),
			otlp_util.WithEndPoint(endpoint),
			otlp_util.WithServiceName(appName),
			otlp_util.WithInSecure(),
			otlp_util.WithErrorHandler(func(err error) {
				logrus.Warnf("OTLP error: %v", err)
			}),
		)
		if err != nil {
			logrus.Errorf("failed to init OTLP exporter: %v", err)
			os.Exit(1)
		}
		defer func() { _ = exporter.Shutdown(ctx) }()
	}

	relayServer, err := NewServer(
		WithLocalAddress(cfg.LocalAddress),
		WithPeers(cfg.OtherPeers),
		WithStorage(dataStorage),
		WithCertManager(certMgr),
		WithTLSConfig(tlsConfig),
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
