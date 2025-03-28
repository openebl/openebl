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

	"github.com/gobuffalo/pop"
	"github.com/gobuffalo/pop/logging"
	"github.com/openebl/openebl/pkg/cert_server/api"
	"github.com/openebl/openebl/pkg/cert_server/model"
	"github.com/openebl/openebl/pkg/config"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	"github.com/openebl/openebl/pkg/util"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// Using a different name to avoid conflict with the one in ca_cli.go
const cobraAppName string = "cert-server"

// CobraApp is the main application structure for the Cobra-based CLI
type CobraApp struct {
	rootCmd *cobra.Command
}

// NewCobraApp creates a new instance of the Cobra CLI application
func NewCobraApp() *CobraApp {
	app := &CobraApp{}
	app.rootCmd = &cobra.Command{
		Use:   cobraAppName,
		Short: "Certificate Server for OpenEBL",
		Long:  `Certificate Server provides certificate management services for the OpenEBL platform.`,
	}

	// Add server command
	serverCmd := &cobra.Command{
		Use:   "server",
		Short: "Run the certificate server",
		RunE:  app.runServer,
	}
	serverCmd.Flags().StringP("config", "c", "", "Path to the configuration file")
	serverCmd.MarkFlagRequired("config")
	serverCmd.MarkFlagFilename("config")
	app.rootCmd.AddCommand(serverCmd)

	// Add migrate command
	migrateCmd := &cobra.Command{
		Use:   "migrate",
		Short: "Migrate the database",
		RunE:  app.runMigrate,
	}
	migrateCmd.Flags().StringP("config", "c", "", "Path to the configuration file")
	migrateCmd.Flags().StringP("path", "p", "migrations", "Path to the migration files")
	migrateCmd.MarkFlagRequired("config")
	migrateCmd.MarkFlagFilename("config")
	migrateCmd.MarkFlagDirname("path")
	app.rootCmd.AddCommand(migrateCmd)

	// Add client command
	clientCmd := &cobra.Command{
		Use:   "client",
		Short: "Client commands for interacting with the certificate server",
	}
	clientCmd.PersistentFlags().StringP("server", "s", "", "Server address")
	clientCmd.MarkPersistentFlagRequired("server")
	app.rootCmd.AddCommand(clientCmd)

	// Add root cert commands
	rootCertCmd := &cobra.Command{
		Use:   "root-cert",
		Short: "Manage root certificates",
	}
	clientCmd.AddCommand(rootCertCmd)

	rootCertAddCmd := &cobra.Command{
		Use:   "add",
		Short: "Add a root certificate",
		RunE:  app.runRootCertAdd,
	}
	rootCertAddCmd.Flags().StringP("requester", "r", "", "Requester name")
	rootCertAddCmd.Flags().BytesBase64P("cert", "", nil, "Root certificate content")
	rootCertAddCmd.MarkFlagRequired("requester")
	rootCertAddCmd.MarkFlagRequired("cert")
	rootCertCmd.AddCommand(rootCertAddCmd)

	rootCertRevokeCmd := &cobra.Command{
		Use:   "revoke [id]",
		Short: "Revoke a root certificate",
		Args:  cobra.ExactArgs(1),
		RunE:  app.runRootCertRevoke,
	}
	rootCertRevokeCmd.Flags().StringP("requester", "r", "", "Requester name")
	rootCertRevokeCmd.MarkFlagRequired("requester")
	rootCertCmd.AddCommand(rootCertRevokeCmd)

	rootCertListCmd := &cobra.Command{
		Use:   "list",
		Short: "List root certificates",
		RunE:  app.runRootCertList,
	}
	rootCertListCmd.Flags().Int("offset", 0, "Offset")
	rootCertListCmd.Flags().Int("limit", 50, "Limit")
	rootCertCmd.AddCommand(rootCertListCmd)

	rootCertGetCmd := &cobra.Command{
		Use:   "get [id]",
		Short: "Get a root certificate",
		Args:  cobra.ExactArgs(1),
		RunE:  app.runRootCertGet,
	}
	rootCertCmd.AddCommand(rootCertGetCmd)

	// Add CA cert commands
	caCertCmd := &cobra.Command{
		Use:   "ca-cert",
		Short: "Manage CA certificates",
	}
	clientCmd.AddCommand(caCertCmd)

	caCertAddCmd := &cobra.Command{
		Use:   "add",
		Short: "Add a CA certificate",
		RunE:  app.runCACertAdd,
	}
	caCertAddCmd.Flags().StringP("requester", "r", "", "Requester name")
	caCertAddCmd.Flags().StringP("type", "t", "RSA", "Key type (RSA or ECDSA)")
	caCertAddCmd.Flags().IntP("bit-length", "b", 2048, "Key bit length")
	caCertAddCmd.Flags().String("curve", "P-256", "Key curve type (P-256, P-384, P-521)")
	caCertAddCmd.Flags().StringArray("country", nil, "Country name")
	caCertAddCmd.Flags().StringArray("org", nil, "Organization name")
	caCertAddCmd.Flags().StringArray("unit", nil, "Unit name")
	caCertAddCmd.Flags().String("common-name", "", "Common name")
	caCertAddCmd.MarkFlagRequired("requester")
	caCertAddCmd.MarkFlagRequired("country")
	caCertAddCmd.MarkFlagRequired("org")
	caCertAddCmd.MarkFlagRequired("unit")
	caCertAddCmd.MarkFlagRequired("common-name")
	caCertCmd.AddCommand(caCertAddCmd)

	caCertRespondCmd := &cobra.Command{
		Use:   "respond [id]",
		Short: "Respond to a CA certificate request",
		Args:  cobra.ExactArgs(1),
		RunE:  app.runCACertRespond,
	}
	caCertRespondCmd.Flags().StringP("requester", "r", "", "Requester name")
	caCertRespondCmd.Flags().BytesBase64P("cert", "", nil, "Certificate content")
	caCertRespondCmd.MarkFlagRequired("requester")
	caCertRespondCmd.MarkFlagRequired("cert")
	caCertCmd.AddCommand(caCertRespondCmd)

	caCertRevokeCmd := &cobra.Command{
		Use:   "revoke [id]",
		Short: "Revoke a CA certificate",
		Args:  cobra.ExactArgs(1),
		RunE:  app.runCACertRevoke,
	}
	caCertRevokeCmd.Flags().StringP("requester", "r", "", "Requester name")
	caCertRevokeCmd.Flags().BytesBase64P("crl", "", nil, "Certificate Revocation List")
	caCertRevokeCmd.MarkFlagRequired("requester")
	caCertRevokeCmd.MarkFlagRequired("crl")
	caCertCmd.AddCommand(caCertRevokeCmd)

	caCertListCmd := &cobra.Command{
		Use:   "list",
		Short: "List CA certificates",
		RunE:  app.runCACertList,
	}
	caCertListCmd.Flags().Int("offset", 0, "Offset")
	caCertListCmd.Flags().Int("limit", 50, "Limit")
	caCertCmd.AddCommand(caCertListCmd)

	caCertGetCmd := &cobra.Command{
		Use:   "get [id]",
		Short: "Get a CA certificate",
		Args:  cobra.ExactArgs(1),
		RunE:  app.runCACertGet,
	}
	caCertCmd.AddCommand(caCertGetCmd)

	// Add cert commands
	certCmd := &cobra.Command{
		Use:   "cert",
		Short: "Manage certificates",
	}
	clientCmd.AddCommand(certCmd)

	certAddCmd := &cobra.Command{
		Use:   "add",
		Short: "Add a certificate",
		RunE:  app.runCertAdd,
	}
	certAddCmd.Flags().StringP("requester", "r", "", "Requester name")
	certAddCmd.Flags().String("cert-type", "", "Certificate type (business_unit, third_party_ca, trade_link_node)")
	certAddCmd.Flags().BytesBase64P("csr", "", nil, "Certificate Signing Request")
	certAddCmd.MarkFlagRequired("requester")
	certAddCmd.MarkFlagRequired("cert-type")
	certAddCmd.MarkFlagRequired("csr")
	certCmd.AddCommand(certAddCmd)

	certIssueCmd := &cobra.Command{
		Use:   "issue [id]",
		Short: "Issue a certificate",
		Args:  cobra.ExactArgs(1),
		RunE:  app.runCertIssue,
	}
	certIssueCmd.Flags().StringP("requester", "r", "", "Requester name")
	certIssueCmd.Flags().String("ca-cert-id", "", "CA Certificate ID")
	certIssueCmd.Flags().String("cert-type", "", "Certificate type (business_unit, third_party_ca, trade_link_node)")
	certIssueCmd.Flags().String("not-before", "", "Not before time (RFC3339 format)")
	certIssueCmd.Flags().String("not-after", "", "Not after time (RFC3339 format)")
	certIssueCmd.MarkFlagRequired("requester")
	certIssueCmd.MarkFlagRequired("ca-cert-id")
	certIssueCmd.MarkFlagRequired("cert-type")
	certIssueCmd.MarkFlagRequired("not-before")
	certIssueCmd.MarkFlagRequired("not-after")
	certCmd.AddCommand(certIssueCmd)

	certRejectCmd := &cobra.Command{
		Use:   "reject [id]",
		Short: "Reject a certificate",
		Args:  cobra.ExactArgs(1),
		RunE:  app.runCertReject,
	}
	certRejectCmd.Flags().StringP("requester", "r", "", "Requester name")
	certRejectCmd.Flags().String("cert-type", "", "Certificate type (business_unit, third_party_ca, trade_link_node)")
	certRejectCmd.Flags().String("reason", "", "Reject reason")
	certRejectCmd.MarkFlagRequired("requester")
	certRejectCmd.MarkFlagRequired("cert-type")
	certRejectCmd.MarkFlagRequired("reason")
	certCmd.AddCommand(certRejectCmd)

	certRevokeCmd := &cobra.Command{
		Use:   "revoke [id]",
		Short: "Revoke a certificate",
		Args:  cobra.ExactArgs(1),
		RunE:  app.runCertRevoke,
	}
	certRevokeCmd.Flags().StringP("requester", "r", "", "Requester name")
	certRevokeCmd.MarkFlagRequired("requester")
	certCmd.AddCommand(certRevokeCmd)

	certListCmd := &cobra.Command{
		Use:   "list",
		Short: "List certificates",
		RunE:  app.runCertList,
	}
	certListCmd.Flags().Int("offset", 0, "Offset")
	certListCmd.Flags().Int("limit", 50, "Limit")
	certCmd.AddCommand(certListCmd)

	certGetCmd := &cobra.Command{
		Use:   "get [id]",
		Short: "Get a certificate",
		Args:  cobra.ExactArgs(1),
		RunE:  app.runCertGet,
	}
	certCmd.AddCommand(certGetCmd)

	return app
}

// Run executes the CLI application
func (app *CobraApp) Run() {
	if err := app.rootCmd.Execute(); err != nil {
		logrus.Errorf("failed to run command: %v", err)
		os.Exit(1)
	}
}

// Server command implementation
func (app *CobraApp) runServer(cmd *cobra.Command, args []string) error {
	configPath, _ := cmd.Flags().GetString("config")
	cfg := api.RestServerConfig{}
	if err := config.FromFile(configPath, &cfg); err != nil {
		logrus.Errorf("failed to load config: %v", err)
		return err
	}

	restServer, err := api.NewRestServerWithConfig(cfg)
	if err != nil {
		logrus.Errorf("failed to create rest server: %v", err)
		return err
	}

	logrus.Info("starting cert server.")
	go func() {
		if err := restServer.Run(); err != nil {
			logrus.Errorf("failed to start cert server: %v", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logrus.Info("Shutting down server......")
	restServer.Close(context.Background())
	return nil
}

// Migrate command implementation
func (app *CobraApp) runMigrate(cmd *cobra.Command, args []string) error {
	configPath, _ := cmd.Flags().GetString("config")
	migrationsPath, _ := cmd.Flags().GetString("path")

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
	if err := config.FromFile(configPath, &cfg); err != nil {
		logrus.Errorf("failed to load config: %v", err)
		return err
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
		return err
	}

	if err := conn.Dialect.CreateDB(); err != nil {
		logrus.Warnf("failed to create database: %v", err)
	}

	migrator, err := pop.NewFileMigrator(migrationsPath, conn)
	if err != nil {
		logrus.Errorf("failed to create migrator: %v", err)
		return err
	}
	// Remove SchemaPath to prevent migrator try to dump schema.
	migrator.SchemaPath = ""

	if err := migrator.Up(); err != nil {
		logrus.Errorf("failed to migrate: %v", err)
		return err
	}

	return nil
}

// Root cert command implementations
func (app *CobraApp) runRootCertAdd(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	requester, _ := cmd.Flags().GetString("requester")
	cert, _ := cmd.Flags().GetBytesBase64("cert")

	client := NewRestClient(server, requester)
	returnedCert, err := client.AddRootCert(string(cert))
	if err != nil {
		logrus.Errorf("failed to add root certificate: %v", err)
		return err
	}

	logrus.Infof("Root certificate added with ID: %s", returnedCert.ID)
	return nil
}

func (app *CobraApp) runRootCertRevoke(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	requester, _ := cmd.Flags().GetString("requester")
	certID := args[0]

	client := NewRestClient(server, requester)
	returnedCert, err := client.RevokeRootCert(certID)
	if err != nil {
		logrus.Errorf("failed to revoke root certificate: %v", err)
		return err
	}

	logrus.Infof("Root certificate revoked with ID: %s", returnedCert.ID)
	return nil
}

func (app *CobraApp) runRootCertList(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	offset, _ := cmd.Flags().GetInt("offset")
	limit, _ := cmd.Flags().GetInt("limit")

	client := NewRestClient(server, "")
	certs, err := client.ListRootCert(offset, limit)
	if err != nil {
		logrus.Errorf("failed to list root certificates: %v", err)
		return err
	}

	pretty := bytes.Buffer{}
	json.Indent(&pretty, []byte(util.StructToJSON(certs)), "", "  ")
	fmt.Println(pretty.String())
	return nil
}

func (app *CobraApp) runRootCertGet(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	certID := args[0]

	client := NewRestClient(server, "")
	cert, err := client.GetRootCert(certID)
	if err != nil {
		logrus.Errorf("failed to get root certificate: %v", err)
		return err
	}

	pretty := bytes.Buffer{}
	json.Indent(&pretty, []byte(util.StructToJSON(cert)), "", "  ")
	fmt.Println(pretty.String())
	return nil
}

// CA cert command implementations
func (app *CobraApp) runCACertAdd(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	requester, _ := cmd.Flags().GetString("requester")
	keyType, _ := cmd.Flags().GetString("type")
	bitLength, _ := cmd.Flags().GetInt("bit-length")
	curveType, _ := cmd.Flags().GetString("curve")
	country, _ := cmd.Flags().GetStringArray("country")
	org, _ := cmd.Flags().GetStringArray("org")
	unit, _ := cmd.Flags().GetStringArray("unit")
	commonName, _ := cmd.Flags().GetString("common-name")

	client := NewRestClient(server, requester)
	caCertAddCmd := &CACertAddCmd{
		PrivateKeyOption: PrivateKeyOption{
			KeyType:   eblpkix.PrivateKeyType(keyType),
			BitLength: bitLength,
			CurveType: eblpkix.ECDSACurveType(curveType),
		},
		Requester:  requester,
		Country:    country,
		Org:        org,
		Unit:       unit,
		CommonName: commonName,
	}

	returnedCert, err := client.AddCACert(caCertAddCmd)
	if err != nil {
		logrus.Errorf("failed to add CA certificate: %v", err)
		return err
	}

	logrus.Infof("CA certificate added with ID: %s", returnedCert.ID)
	return nil
}

func (app *CobraApp) runCACertRespond(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	requester, _ := cmd.Flags().GetString("requester")
	certID := args[0]
	cert, _ := cmd.Flags().GetBytesBase64("cert")

	client := NewRestClient(server, requester)
	returnedCert, err := client.RespondCACert(certID, string(cert))
	if err != nil {
		logrus.Errorf("failed to respond CA certificate: %v", err)
		return err
	}

	logrus.Infof("CA certificate responded with ID: %s", returnedCert.ID)
	return nil
}

func (app *CobraApp) runCACertRevoke(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	requester, _ := cmd.Flags().GetString("requester")
	certID := args[0]
	crl, _ := cmd.Flags().GetBytesBase64("crl")

	client := NewRestClient(server, requester)
	returnedCert, err := client.RevokeCACert(certID, string(crl))
	if err != nil {
		logrus.Errorf("failed to revoke CA certificate: %v", err)
		return err
	}

	logrus.Infof("CA certificate revoked with ID: %s", returnedCert.ID)
	return nil
}

func (app *CobraApp) runCACertList(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	offset, _ := cmd.Flags().GetInt("offset")
	limit, _ := cmd.Flags().GetInt("limit")

	client := NewRestClient(server, "")
	certs, err := client.ListCACert(offset, limit)
	if err != nil {
		logrus.Errorf("failed to list CA certificates: %v", err)
		return err
	}

	pretty := bytes.Buffer{}
	json.Indent(&pretty, []byte(util.StructToJSON(certs)), "", "  ")
	fmt.Println(pretty.String())
	return nil
}

func (app *CobraApp) runCACertGet(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	certID := args[0]

	client := NewRestClient(server, "")
	cert, err := client.GetCACert(certID)
	if err != nil {
		logrus.Errorf("failed to get CA certificate: %v", err)
		return err
	}

	pretty := bytes.Buffer{}
	json.Indent(&pretty, []byte(util.StructToJSON(cert)), "", "  ")
	fmt.Println(pretty.String())
	return nil
}

// Cert command implementations
func (app *CobraApp) runCertAdd(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	requester, _ := cmd.Flags().GetString("requester")
	certType, _ := cmd.Flags().GetString("cert-type")
	csr, _ := cmd.Flags().GetBytesBase64("csr")

	client := NewRestClient(server, requester)
	certAddCmd := &CertAddCmd{
		Requester: requester,
		CertType:  model.CertType(certType),
		CSR:       csr,
	}

	returnedCert, err := client.AddCert(certAddCmd)
	if err != nil {
		logrus.Errorf("failed to add certificate: %v", err)
		return err
	}

	logrus.Infof("Certificate added with ID: %s", returnedCert.ID)
	return nil
}

func (app *CobraApp) runCertIssue(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	requester, _ := cmd.Flags().GetString("requester")
	certID := args[0]
	caCertID, _ := cmd.Flags().GetString("ca-cert-id")
	certType, _ := cmd.Flags().GetString("cert-type")
	notBeforeStr, _ := cmd.Flags().GetString("not-before")
	notAfterStr, _ := cmd.Flags().GetString("not-after")

	notBefore, err := time.Parse(time.RFC3339, notBeforeStr)
	if err != nil {
		logrus.Errorf("failed to parse not-before time: %v", err)
		return err
	}

	notAfter, err := time.Parse(time.RFC3339, notAfterStr)
	if err != nil {
		logrus.Errorf("failed to parse not-after time: %v", err)
		return err
	}

	client := NewRestClient(server, requester)
	certIssueCmd := &CertIssueCmd{
		Requester: requester,
		ID:        certID,
		CACertID:  caCertID,
		CertType:  model.CertType(certType),
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}

	returnedCert, err := client.IssueCert(certIssueCmd)
	if err != nil {
		logrus.Errorf("failed to issue certificate: %v", err)
		return err
	}

	logrus.Infof("Certificate issued with ID: %s", returnedCert.ID)
	return nil
}

func (app *CobraApp) runCertReject(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	requester, _ := cmd.Flags().GetString("requester")
	certID := args[0]
	certType, _ := cmd.Flags().GetString("cert-type")
	reason, _ := cmd.Flags().GetString("reason")

	client := NewRestClient(server, requester)
	returnedCert, err := client.RejectCert(certID, model.CertType(certType), reason)
	if err != nil {
		logrus.Errorf("failed to reject certificate: %v", err)
		return err
	}

	logrus.Infof("Certificate rejected with ID: %s", returnedCert.ID)
	return nil
}

func (app *CobraApp) runCertRevoke(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	requester, _ := cmd.Flags().GetString("requester")
	certID := args[0]

	client := NewRestClient(server, requester)
	returnedCert, err := client.RevokeCert(certID)
	if err != nil {
		logrus.Errorf("failed to revoke certificate: %v", err)
		return err
	}

	logrus.Infof("Certificate revoked with ID: %s", returnedCert.ID)
	return nil
}

func (app *CobraApp) runCertList(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	offset, _ := cmd.Flags().GetInt("offset")
	limit, _ := cmd.Flags().GetInt("limit")

	client := NewRestClient(server, "")
	certs, err := client.ListCert(offset, limit)
	if err != nil {
		logrus.Errorf("failed to list certificates: %v", err)
		return err
	}

	pretty := bytes.Buffer{}
	json.Indent(&pretty, []byte(util.StructToJSON(certs)), "", "  ")
	fmt.Println(pretty.String())
	return nil
}

func (app *CobraApp) runCertGet(cmd *cobra.Command, args []string) error {
	server, _ := cmd.Flags().GetString("server")
	certID := args[0]

	client := NewRestClient(server, "")
	cert, err := client.GetCert(certID)
	if err != nil {
		logrus.Errorf("failed to get certificate: %v", err)
		return err
	}

	pretty := bytes.Buffer{}
	json.Indent(&pretty, []byte(util.StructToJSON(cert)), "", "  ")
	fmt.Println(pretty.String())
	return nil
}
