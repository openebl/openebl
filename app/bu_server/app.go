package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	formatter "github.com/bluexlab/logrus-formatter"
	otlp_util "github.com/bluexlab/otlp-util-go"
	"github.com/gobuffalo/pop"
	"github.com/gobuffalo/pop/logging"
	"github.com/openebl/openebl/pkg/bu_server/api"
	"github.com/openebl/openebl/pkg/bu_server/broker"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/cert"
	"github.com/openebl/openebl/pkg/bu_server/manager"
	"github.com/openebl/openebl/pkg/bu_server/storage/postgres"
	"github.com/openebl/openebl/pkg/bu_server/webhook"
	"github.com/openebl/openebl/pkg/config"
	"github.com/openebl/openebl/pkg/util"
	"github.com/sirupsen/logrus"
)

const appName string = "bu-server"

type CLI struct {
	Server struct {
	} `cmd:"" help:"Run the server"`
	Migrate struct {
		Path string `short:"p" long:"path" help:"Path to the migration files" type:"existingdir" default:"migrations"`
	} `cmd:"" help:"Migrate the database"`
	Broker struct {
	} `cmd:"" help:"Run the broker to send/receive messages with the relay server"`
	Config string `short:"c" long:"config" help:"Path to the configuration file" type:"existingfile" default:"config.yaml"`
}

type Config struct {
	Database util.PostgresDatabaseConfig `yaml:"database"`
	Server   struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"server"`
	Manager struct {
		Host string `yaml:"host"`
		Port int    `yaml:"port"`
	} `yaml:"manager"`
	Broker struct {
		RelayServer   string `yaml:"relay_server"`
		CheckInterval int    `yaml:"check_interval"`
		BatchSize     int    `yaml:"batch_size"`
		CertServer    string `yaml:"cert_server"`
	} `yaml:"broker"`
	Webhook struct {
		CheckInterval int `yaml:"check_interval"`
		BatchSize     int `yaml:"batch_size"`
		Timeout       int `yaml:"timeout"`
		MaxRetry      int `yaml:"max_retry"`
	} `yaml:"webhook"`
	OTLPEndpoint string `yaml:"otlp_endpoint"`
}

type App struct{}

func (a *App) Run() {
	formatter.InitLogger()

	var cli CLI
	ctx := kong.Parse(&cli, kong.UsageOnError())
	switch ctx.Command() {
	case "server":
		a.runServer(cli)
	case "migrate":
		a.runMigrate(cli)
	case "broker":
		a.runBroker(cli)
	default:
	}
}

func (a *App) runServer(cli CLI) {
	ctx := context.Background()

	var appConfig Config
	if err := config.FromFile(cli.Config, &appConfig); err != nil {
		logrus.Errorf("failed to load config: %v", err)
		os.Exit(128)
	}

	if endpoint := appConfig.OTLPEndpoint; endpoint != "" {
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
			logrus.Errorf("failed to initialize OTLP exporter: %v", err)
			os.Exit(128)
		}
		defer func() { _ = exporter.Shutdown(ctx) }()
	}

	apiConfig := api.APIConfig{
		Database:     appConfig.Database,
		LocalAddress: net.JoinHostPort(appConfig.Server.Host, strconv.Itoa(appConfig.Server.Port)),
	}
	apiServer, err := api.NewAPIWithConfig(apiConfig)
	if err != nil {
		logrus.Errorf("failed to create API server: %v", err)
		os.Exit(128)
	}

	managerAPIConfig := manager.ManagerAPIConfig{
		Database:     appConfig.Database,
		LocalAddress: net.JoinHostPort(appConfig.Manager.Host, strconv.Itoa(appConfig.Manager.Port)),
	}
	managerServer, err := manager.NewManagerAPI(managerAPIConfig)
	if err != nil {
		logrus.Errorf("failed to create Manager server: %v", err)
		os.Exit(128)
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	processorConfig := webhook.Config{
		Database:      appConfig.Database,
		CheckInterval: appConfig.Webhook.CheckInterval,
		BatchSize:     appConfig.Webhook.BatchSize,
		Timeout:       appConfig.Webhook.Timeout,
		MaxRetry:      appConfig.Webhook.MaxRetry,
	}
	processor, err := webhook.NewProcessorWithConfig(processorConfig)
	if err != nil {
		logrus.Errorf("failed to create webhook processor: %v", err)
		os.Exit(128)
	}

	wg := &sync.WaitGroup{}

	go func(wg *sync.WaitGroup) {
		wg.Add(1)
		defer wg.Done()

		if err := apiServer.Run(); err != nil {
			logrus.Errorf("failed to run API server: %v", err)
			os.Exit(1)
		}
	}(wg)

	go func(wg *sync.WaitGroup) {
		wg.Add(1)
		defer wg.Done()

		if err := managerServer.Run(); err != nil {
			logrus.Errorf("failed to run Manager server: %v", err)
			os.Exit(1)
		}
	}(wg)

	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		processor.Run(ctx)
	}(wg)

	// listen for the stop signal
	<-ctx.Done()

	// Restore default behavior on the signals we are listening to
	stop()
	logrus.Info("shutting down gracefully, press Ctrl+C again to force")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := apiServer.Close(ctx); err != nil {
		logrus.Warnf("failed to close API server: %v", err)
		os.Exit(1)
	}
	if err := managerServer.Close(ctx); err != nil {
		logrus.Warnf("failed to close Manager server: %v", err)
		os.Exit(1)
	}

	wg.Wait()
}

func (a *App) runMigrate(cli CLI) {
	var appConfig Config
	if err := config.FromFile(cli.Config, &appConfig); err != nil {
		logrus.Errorf("failed to load config: %v", err)
		os.Exit(128)
	}

	// set up the logger
	pop.SetLogger(func(lvl logging.Level, s string, args ...interface{}) {
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
			// Do nothing
		}
	})

	// setup database connection
	cd := pop.ConnectionDetails{
		Dialect:  "postgres",
		Database: appConfig.Database.Database,
		Host:     appConfig.Database.Host,
		Port:     strconv.Itoa(appConfig.Database.Port),
		User:     appConfig.Database.User,
		Password: appConfig.Database.Password,
	}
	conn, err := pop.NewConnection(&cd)
	if err != nil {
		logrus.Errorf("failed to create connection: %v", err)
		os.Exit(128)
	}

	// create the database if it doesn't exist
	if err = conn.Dialect.CreateDB(); err != nil {
		logrus.Warnf("failed to create database: %v", err)
	}

	migrator, err := pop.NewFileMigrator(cli.Migrate.Path, conn)
	if err != nil {
		logrus.Errorf("failed to create migrator: %v", err)
		os.Exit(128)
	}
	// Remove SchemaPath to prevent migrator try to dump schema.
	migrator.SchemaPath = ""

	// run the migrations
	if err = migrator.Up(); err != nil {
		logrus.Errorf("failed to migrate: %v", err)
		os.Exit(1)
	}
}

func (a *App) runBroker(cli CLI) {
	ctx := context.Background()

	var appConfig Config
	if err := config.FromFile(cli.Config, &appConfig); err != nil {
		logrus.Errorf("failed to load config: %v", err)
		os.Exit(128)
	}

	if endpoint := appConfig.OTLPEndpoint; endpoint != "" {
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
			logrus.Errorf("failed to initialize OTLP exporter: %v", err)
			os.Exit(128)
		}
		defer func() { _ = exporter.Shutdown(ctx) }()
	}

	dbStorage, err := postgres.NewStorageWithConfig(appConfig.Database)
	if err != nil {
		logrus.Errorf("failed to create database connection: %v", err)
		os.Exit(128)
	}

	certMgr := cert.NewCertManager(cert.WithCertStore(dbStorage), cert.WithCertServerURL(appConfig.Broker.CertServer))
	webhookCtrl := webhook.NewWebhookController(dbStorage)
	buMgr := business_unit.NewBusinessUnitManager(dbStorage, certMgr, webhookCtrl, nil)

	brokerService, err := broker.NewBroker(
		broker.WithClientID("default"),
		broker.WithCheckInterval(appConfig.Broker.CheckInterval),
		broker.WithBatchSize(appConfig.Broker.BatchSize),
		broker.WithRelayServer(appConfig.Broker.RelayServer),
		broker.WithInboxStore(dbStorage),
		broker.WithOutboxStore(dbStorage),
		broker.WithCertManager(certMgr),
		broker.WithBUManager(buMgr),
	)
	if err != nil {
		logrus.Errorf("failed to create broker: %v", err)
		os.Exit(128)
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	wg := &sync.WaitGroup{}

	go func(wg *sync.WaitGroup) {
		wg.Add(1)
		defer wg.Done()

		if err := brokerService.Run(ctx); err != nil {
			logrus.Errorf("failed to run broker: %v", err)
			os.Exit(1)
		}
	}(wg)

	// listen for the stop signal
	<-ctx.Done()

	// Restore default behavior on the signals we are listening to
	stop()
	logrus.Info("shutting down gracefully, press Ctrl+C again to force")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := brokerService.Close(ctx); err != nil {
		logrus.Warnf("failed to close broker: %v", err)
		os.Exit(1)
	}

	wg.Wait()
	logrus.Info("broker stopped")
}
