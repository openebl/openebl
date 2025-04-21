package cmd

import (
	"fmt"
	"time"

	"github.com/openebl/openebl/cmd/openebl-cli/client"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/spf13/cobra"
)

var onboardCmd = &cobra.Command{
	Use:   "onboard",
	Short: "Onboard a new business unit",
	Long: `Onboard a new business unit to the OpenEBL platform.
This process includes:
1. Creating a business unit
2. Creating an authentication for the business unit
3. Submitting the CSR to the CA server
4. Getting the certificate signed
5. Signing the CSR`,
	RunE: runOnboard,
}

func init() {
	// Business Unit parameters
	onboardCmd.Flags().String("name", "", "Name of the business unit")
	onboardCmd.Flags().StringSlice("addresses", []string{}, "Addresses of the business unit (comma-separated)")
	onboardCmd.Flags().String("country", "", "Country code of the business unit (e.g., US, TW, JP)")
	onboardCmd.Flags().StringSlice("emails", []string{}, "Email addresses of the business unit (comma-separated)")
	onboardCmd.Flags().StringSlice("phone-numbers", []string{}, "Phone numbers of the business unit (comma-separated)")
	onboardCmd.Flags().String("status", "active", "Status of the business unit (active or inactive)")

	// Authentication parameters
	onboardCmd.Flags().String("key-type", "RSA", "Key type for authentication (RSA or ECDSA)")
	onboardCmd.Flags().Int("bit-length", 2048, "Bit length for RSA keys")
	
	// CA Certificate parameter
	onboardCmd.Flags().String("ca-cert-id", "", "ID of the CA certificate to use for signing (if not provided, will try to find an active one)")

	// Required flags
	onboardCmd.MarkFlagRequired("name")
	onboardCmd.MarkFlagRequired("country")
	onboardCmd.MarkFlagRequired("emails")
}

func runOnboard(cmd *cobra.Command, args []string) error {
	// Get flags
	buServer, _ := cmd.Flags().GetString("bu-server")
	caServer, _ := cmd.Flags().GetString("ca-server")
	requester, _ := cmd.Flags().GetString("requester")
	apiKey, _ := cmd.Flags().GetString("api-key")

	if requester == "" {
		return fmt.Errorf("requester name is required")
	}

	name, _ := cmd.Flags().GetString("name")
	addresses, _ := cmd.Flags().GetStringSlice("addresses")
	country, _ := cmd.Flags().GetString("country")
	emails, _ := cmd.Flags().GetStringSlice("emails")
	phoneNumbers, _ := cmd.Flags().GetStringSlice("phone-numbers")
	status, _ := cmd.Flags().GetString("status")

	keyType, _ := cmd.Flags().GetString("key-type")
	bitLength, _ := cmd.Flags().GetInt("bit-length")

	// Create clients
	buClient := client.NewBUClient(buServer, requester, apiKey)
	caClient := client.NewCAClient(caServer, requester)

	// Step 1: Create the business unit
	fmt.Println("Step 1: Creating business unit...")
	businessUnit := &model.BusinessUnit{
		Name:         name,
		Addresses:    addresses,
		Country:      country,
		Emails:       emails,
		PhoneNumbers: phoneNumbers,
		Status:       model.BusinessUnitStatus(status),
	}

	createdBU, err := buClient.CreateBusinessUnit(businessUnit)
	if err != nil {
		return fmt.Errorf("failed to create business unit: %w", err)
	}
	fmt.Printf("Business unit created successfully with ID: %s\n", createdBU.ID)

	// Step 2: Create BU authentication
	fmt.Println("\nStep 2: Creating business unit authentication...")
	auth, err := buClient.CreateBUAuthentication(createdBU.ID, keyType, bitLength)
	if err != nil {
		return fmt.Errorf("failed to create business unit authentication: %w", err)
	}
	fmt.Printf("Business unit authentication created with ID: %s\n", auth.ID)

	// Step 3: Pass the CSR to CA server
	fmt.Println("\nStep 3: Submitting CSR to CA server...")
	cert, err := caClient.AddCert(auth.CertificateSigningRequest)
	if err != nil {
		return fmt.Errorf("failed to submit CSR to CA server: %w", err)
	}
	fmt.Printf("CSR submitted to CA server with ID: %s\n", cert.ID)

	// Step 4: Find or use the specified CA certificate to sign the CSR
	fmt.Println("\nStep 4: Finding CA certificate to sign the CSR...")
	caCertID, _ := cmd.Flags().GetString("ca-cert-id")
	
	// If no CA cert ID is provided, try to find an active one
	if caCertID == "" {
		caCerts, _, err := caClient.ListCACerts(0, 10)
		if err != nil {
			return fmt.Errorf("failed to list CA certificates: %w", err)
		}

		for _, caCert := range caCerts {
			if caCert.Status == "active" {
				caCertID = caCert.ID
				break
			}
		}

		if caCertID == "" {
			return fmt.Errorf("no active CA certificate found. Please specify a CA certificate ID using --ca-cert-id flag")
		}
	}
	
	fmt.Printf("Using CA certificate with ID: %s\n", caCertID)

	// Step 5: Sign the CSR
	fmt.Println("\nStep 5: Signing the CSR...")
	_, err = caClient.IssueCert(cert.ID, caCertID)
	if err != nil {
		return fmt.Errorf("failed to sign the CSR: %w", err)
	}
	fmt.Printf("Certificate signed successfully\n")

	// Give the server a moment to process and sync the certificate
	fmt.Println("\nWaiting for the BU server to synchronize the certificate...")
	time.Sleep(2 * time.Second)
	
	// Verify the authentication status
	updatedAuth, err := buClient.GetBUAuthentication(createdBU.ID, auth.ID)
	if err != nil {
		return fmt.Errorf("failed to get updated authentication: %w", err)
	}

	fmt.Printf("\nBusiness unit onboarding completed successfully!\n")
	fmt.Printf("Business Unit ID: %s\n", createdBU.ID)
	fmt.Printf("Authentication ID: %s\n", updatedAuth.ID)
	fmt.Printf("Authentication Status: %s\n", updatedAuth.Status)

	return nil
}
