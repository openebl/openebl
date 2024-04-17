package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/gobuffalo/pop"
	"github.com/gobuffalo/pop/logging"
	"github.com/openebl/openebl/pkg/cert_server/api"
	"github.com/openebl/openebl/pkg/cert_server/model"
	"github.com/openebl/openebl/pkg/config"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	"github.com/openebl/openebl/pkg/util"
	"github.com/sirupsen/logrus"
)

const appName string = "cert-server"

type App struct{}

type PrivateKeyOption struct {
	KeyType   eblpkix.PrivateKeyType `enum:"RSA,ECDSA" short:"t" long:"type" help:"Key type" default:"RSA"`
	BitLength int                    `short:"b" long:"bit-length" help:"Key bit length" default:"2048"`
	CurveType eblpkix.ECDSACurveType `enum:"P-256,P-384,P-521" long:"curve" help:"Key curve type" default:"P-256"`
}

type ServerCmd struct {
	Config string `short:"c" long:"config" type:"existingfile" help:"Path to the configuration file"`
}

type MigrateCmd struct {
	Config     string `short:"c" long:"config" type:"existingfile" help:"Path to the configuration file"`
	Migrations string `short:"p" long:"path" type:"existingdir" help:"Path to the migration files" default:"migrations"`
}

type RootCertAddCmd struct {
	Requester string `short:"r" long:"requester" help:"Requester name" required:""`
	Cert      []byte `type:"filecontent" help:"Root certificate content" required:""`
}

type RootCertRevokeCmd struct {
	Requester string `short:"r" long:"requester" help:"Requester name" required:""`
	ID        string `required:""`
}

type RootCertListCmd struct {
	Offset int `long:"offset" help:"Offset" default:"0"`
	Limit  int `long:"limit" help:"Limit" default:"50"`
}

type RootCertGetCmd struct {
	ID string `required:""`
}

type CACertAddCmd struct {
	PrivateKeyOption
	Requester string `short:"r" long:"requester" help:"Requester name" required:""`

	Country    []string `long:"country" help:"Country name" required:""`
	Org        []string `long:"org" help:"Organization name" required:""`
	Unit       []string `long:"unit" help:"Unit name" required:""`
	CommonName string   `long:"common-name" help:"Common name" required:""`
}

type CACertRespondCmd struct {
	Requester string `short:"r" long:"requester" help:"Requester name" required:""`
	ID        string `help:"Certificate ID" required:""`
	Cert      []byte `type:"filecontent" help:"Certificate content" required:""`
}

type CACertListCmd RootCertListCmd
type CACertGetCmd RootCertGetCmd

type CertAddCmd struct {
	Requester string         `short:"r" long:"requester" help:"Requester name" required:""`
	CertType  model.CertType `enum:"business_unit,third_party_ca" required:""`
	CSR       []byte         `type:"filecontent" help:"Certificate Signing Request" required:""`
}

type CertIssueCmd struct {
	Requester string         `short:"r" long:"requester" help:"Requester name" required:""`
	ID        string         `required:""`
	CACertID  string         `required:""`
	CertType  model.CertType `enum:"business_unit,third_party_ca" required:""`
	NotBefore time.Time      `required:""`
	NotAfter  time.Time      `required:""`
}

type CertRejectCmd struct {
	Requester string         `short:"r" long:"requester" help:"Requester name" required:""`
	ID        string         `required:""`
	CertType  model.CertType `enum:"business_unit,third_party_ca" required:""`
	Reason    string         `required:"" help:"Reject Reason"`
}

type CertListCmd RootCertListCmd
type CertGetCmd RootCertGetCmd

type CertServerCli struct {
	Server  ServerCmd  `cmd:"" help:"Run cert server."`
	Migrate MigrateCmd `cmd:"" help:"Migrate database."`

	Client struct {
		Server string `short:"s" long:"server" help:"Server address" required:""`

		RootCert struct {
			Add    RootCertAddCmd    `cmd:""`
			Revoke RootCertRevokeCmd `cmd:""`
			List   RootCertListCmd   `cmd:""`
			Get    RootCertGetCmd    `cmd:""`
		} `cmd:""`

		CACert struct {
			Add     CACertAddCmd     `cmd:""`
			Respond CACertRespondCmd `cmd:""`
			List    CACertListCmd    `cmd:""`
			Get     CACertGetCmd     `cmd:""`
		} `cmd:""`

		Cert struct {
			Add    CertAddCmd    `cmd:""`
			Issue  CertIssueCmd  `cmd:""`
			Reject CertRejectCmd `cmd:""`
			List   CertListCmd   `cmd:""`
			Get    CertGetCmd    `cmd:""`
		} `cmd:""`
	} `cmd:""`
}

type Config struct {
	Database       util.PostgresDatabaseConfig `yaml:"database"`
	PrivateAddress string                      `yaml:"private_address"`
	PublicAddress  string                      `yaml:"public_address"`
}

func (*App) Run() {
	cli := CertServerCli{}
	ctx := kong.Parse(&cli)
	err := ctx.Run(&cli)
	if err != nil {
		logrus.Errorf("failed to run command: %v", err)
		os.Exit(1)
	}
}

func (cmd *ServerCmd) Run(cli *CertServerCli) error {
	cfg := api.RestServerConfig{}
	if err := config.FromFile(cli.Server.Config, &cfg); err != nil {
		logrus.Errorf("failed to load config: %v", err)
		os.Exit(1)
	}

	restServer, err := api.NewRestServerWithConfig(cfg)
	if err != nil {
		logrus.Errorf("failed to create rest server: %v", err)
		os.Exit(1)
	}

	logrus.Info("starting cert server.")
	go func() {
		if err := restServer.Run(); err != nil {
			logrus.Errorf("failed to start cert server: %v", err)
			os.Exit(1)
		}
	}()

	cmd.waitForInterrupt()
	restServer.Close(context.Background())
	return nil
}

func (cmd *ServerCmd) waitForInterrupt() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logrus.Info("Shutting down server......")
}

func (cmd *MigrateCmd) Run(cli *CertServerCli) error {
	popLogger := func(lvl logging.Level, s string, args ...interface{}) {
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

	pop.SetLogger(popLogger)
	cfg := api.RestServerConfig{}
	if err := config.FromFile(cli.Migrate.Config, &cfg); err != nil {
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

func (*RootCertAddCmd) Run(cli *CertServerCli) error {
	client := NewRestClient(cli.Client.Server, cli.Client.RootCert.Add.Requester)
	cert, err := client.AddRootCert(string(cli.Client.RootCert.Add.Cert))
	if err != nil {
		logrus.Errorf("failed to add root certificate: %v", err)
		os.Exit(1)
	}

	logrus.Infof("Root certificate added with ID: %s", cert.ID)
	return nil
}

func (*RootCertRevokeCmd) Run(cli *CertServerCli) error {
	client := NewRestClient(cli.Client.Server, cli.Client.RootCert.Revoke.Requester)
	cert, err := client.RevokeRootCert(cli.Client.RootCert.Revoke.ID)
	if err != nil {
		logrus.Errorf("failed to revoke root certificate: %v", err)
		os.Exit(1)
	}

	logrus.Infof("Root certificate revoked with ID: %s", cert.ID)
	return nil
}

func (*RootCertListCmd) Run(cli *CertServerCli) error {
	client := NewRestClient(cli.Client.Server, "")
	certs, err := client.ListRootCert(cli.Client.RootCert.List.Offset, cli.Client.RootCert.List.Limit)
	if err != nil {
		logrus.Errorf("failed to list root certificates: %v", err)
		os.Exit(1)
	}

	pretty := bytes.Buffer{}
	json.Indent(&pretty, []byte(util.StructToJSON(certs)), "", "  ")
	fmt.Println(pretty.String())
	return nil
}

func (*RootCertGetCmd) Run(cli *CertServerCli) error {
	client := NewRestClient(cli.Client.Server, "")
	cert, err := client.GetRootCert(cli.Client.RootCert.Get.ID)
	if err != nil {
		logrus.Errorf("failed to get root certificate: %v", err)
		os.Exit(1)
	}

	pretty := bytes.Buffer{}
	json.Indent(&pretty, []byte(util.StructToJSON(cert)), "", "  ")
	fmt.Println(pretty.String())
	return nil
}

func (*CACertAddCmd) Run(cli *CertServerCli) error {
	client := NewRestClient(cli.Client.Server, cli.Client.CACert.Add.Requester)

	cert, err := client.AddCACert(&cli.Client.CACert.Add)
	if err != nil {
		logrus.Errorf("failed to add CA certificate: %v", err)
		os.Exit(1)
	}

	logrus.Infof("CA certificate added with ID: %s", cert.ID)
	return nil
}

func (*CACertRespondCmd) Run(cli *CertServerCli) error {
	client := NewRestClient(cli.Client.Server, cli.Client.CACert.Respond.Requester)
	cert, err := client.RespondCACert(cli.Client.CACert.Respond.ID, string(cli.Client.CACert.Respond.Cert))
	if err != nil {
		logrus.Errorf("failed to respond CA certificate: %v", err)
		os.Exit(1)
	}

	logrus.Infof("CA certificate responded with ID: %s", cert.ID)
	return nil
}

func (*CACertListCmd) Run(cli *CertServerCli) error {
	client := NewRestClient(cli.Client.Server, "")
	certs, err := client.ListCACert(cli.Client.CACert.List.Offset, cli.Client.CACert.List.Limit)
	if err != nil {
		logrus.Errorf("failed to list CA certificates: %v", err)
		os.Exit(1)
	}

	pretty := bytes.Buffer{}
	json.Indent(&pretty, []byte(util.StructToJSON(certs)), "", "  ")
	fmt.Println(pretty.String())
	return nil
}

func (*CACertGetCmd) Run(cli *CertServerCli) error {
	client := NewRestClient(cli.Client.Server, "")
	cert, err := client.GetCACert(cli.Client.CACert.Get.ID)
	if err != nil {
		logrus.Errorf("failed to get CA certificate: %v", err)
		os.Exit(1)
	}

	pretty := bytes.Buffer{}
	json.Indent(&pretty, []byte(util.StructToJSON(cert)), "", "  ")
	fmt.Println(pretty.String())
	return nil
}

func (*CertAddCmd) Run(cli *CertServerCli) error {
	client := NewRestClient(cli.Client.Server, cli.Client.Cert.Add.Requester)
	cert, err := client.AddCert(&cli.Client.Cert.Add)
	if err != nil {
		logrus.Errorf("failed to add certificate: %v", err)
		os.Exit(1)
	}

	logrus.Infof("Certificate added with ID: %s", cert.ID)
	return nil
}

func (*CertIssueCmd) Run(cli *CertServerCli) error {
	client := NewRestClient(cli.Client.Server, cli.Client.Cert.Issue.Requester)
	cert, err := client.IssueCert(&cli.Client.Cert.Issue)
	if err != nil {
		logrus.Errorf("failed to issue certificate: %v", err)
		os.Exit(1)
	}

	logrus.Infof("Certificate issued with ID: %s", cert.ID)
	return nil
}

func (*CertRejectCmd) Run(cli *CertServerCli) error {
	client := NewRestClient(cli.Client.Server, cli.Client.Cert.Reject.Requester)
	cert, err := client.RejectCert(cli.Client.Cert.Reject.ID, cli.Client.Cert.Reject.CertType, cli.Client.Cert.Reject.Reason)
	if err != nil {
		logrus.Errorf("failed to reject certificate: %v", err)
		os.Exit(1)
	}

	logrus.Infof("Certificate rejected with ID: %s", cert.ID)
	return nil
}

func (*CertListCmd) Run(cli *CertServerCli) error {
	client := NewRestClient(cli.Client.Server, "")
	certs, err := client.ListCert(cli.Client.Cert.List.Offset, cli.Client.Cert.List.Limit)
	if err != nil {
		logrus.Errorf("failed to list certificates: %v", err)
		os.Exit(1)
	}

	pretty := bytes.Buffer{}
	json.Indent(&pretty, []byte(util.StructToJSON(certs)), "", "  ")
	fmt.Println(pretty.String())
	return nil
}

func (*CertGetCmd) Run(cli *CertServerCli) error {
	client := NewRestClient(cli.Client.Server, "")
	cert, err := client.GetCert(cli.Client.Cert.Get.ID)
	if err != nil {
		logrus.Errorf("failed to get certificate: %v", err)
		os.Exit(1)
	}

	pretty := bytes.Buffer{}
	json.Indent(&pretty, []byte(util.StructToJSON(cert)), "", "  ")
	fmt.Println(pretty.String())
	return nil
}
