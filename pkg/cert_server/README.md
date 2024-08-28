# Certificate Server

Certificate Server is a service that provides certificate management functions. All certificates managed by the service are stored in a database. The certificates issued by the service will be published to TradeLink network. They will be public to all TradeLink network participants.

## Cert Type

There are four types of certificates in the service.

1. Root Certificate
   The certificate is the root of certificate trust path. For more information, refer to the [RFC 5280 Section 3.2](https://datatracker.ietf.org/doc/html/rfc5280#section-3.2). It is self-signed and has no parent certificate. It is signed/generated outside the service. The service only stores and publishes the certificate not the private key of the certificate.

1. CA (Certificate Authority) Certificate
   The certificate is the intermediate certificate between the root certificate and the business unit or third party CA certificate. It is signed by the root certificate or other certificate authority certificate. It is used to sign the business unit certificate and third party CA certificate. The service stores and publishes the certificate and the private key of the certificate.

1. Third Party CA Certificate
   A certificate server is allowed to issue CA certificates for other certificate server. The certificate belongs to another certificate server is called third party CA certificate. The service stores and publishes the certificate but not the private key of the certificate.

1. Business Unit Certificate
   The certificate is used by the business unit to sign the data. The certificate is signed by the CA certificate. The service stores and publishes the certificate but not the private key of the certificate. The certificate is not allowed to issue another certificate.

## Requirement of Root Certificate, CA Certificate and Third Party CA Certificate

## Initialize

    When a new certificate server is deployed, the first thing is to setup the root certificate and the first CA certificate for the certificate server. There are several steps to initialize the certificate server. The following steps assume you run the commands on the certificate server and the management API binds localhost:9100.

1. Install root certificate.

   ```
   cert_server client --server=http://localhost:9100 root-cert add --requester=your_name --cert=root_cert.crt
   ```

   The command install a root certificate into the certificate server. root_cert.crt is the root certificate file. The certificate is self-signed and generated outside the service. It's PEM format. The private key of root_cert.crt must be kept secured and not shared with anyone.

1. Create the certificate signing request (CSR) for the first CA certificate.

   ```
   cert_server client --server=http://localhost:9100 ca-cert add --key-type="RSA" --bit-length=4096 --requester=your_name --country=US --org="ORG" --unit="DDDD" --common-name="Internal Demo CA"
   ```

   The command creates a CSR for the first CA certificate. The CSR is signed by the root certificate. The command returns the Cert/CSR ID. The ID is used to get the CSR and install the CA certificate.

   ```
   cert_server client ca-cert --server=http://localhost:9100 list
   ```

   The command lists all the CA certificates. The response is like the following.

   ```
   {
   "total": 1,
   "certs": [
    {
      "id": "c3d597dd-8401-41c7-9e9d-c9f311faf8e0",
      "version": 5,
      "type": "ca",
      "status": "waiting_for_issued",
      "not_before": 1713524694,
      "not_after": 4835588694,
      "issued_serial_number": 2,
      "issued_crl_serial_number": 1,
      "created_at": 1713524474,
      "created_by": "ennio",
      "revoked_at": 0,
      "revoked_by": "",
      "issued_at": 1713524773,
      "issued_by": "ennio",
      "rejected_at": 0,
      "rejected_by": "",
      "private_key": "",
      "public_key_id": "21960c0209f4c0103f82f655dd6416b2a546f1a9",
      "issuer_key_id": "",
      "certificate": "",
      "certificate_serial_number": "",
      "certificate_signing_request": "-----BEGIN CERTIFICATE REQUEST-----\nMIIClDCCAXwCAQAwTzELMAkGA1UEBhMCVFcxEjAQBgNVBAoTCUJsdXhUcmFkZTEW\nMBQGA1UECxMNUkQgRGVwYXJ0bWVudDEUMBIGA1UEAxMLQmx1ZVggUkQgQ0EwggEi\nMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0OZXBrggqgp+o8oYYdARrTD4z\nJpP0Fa7Ms2jjbVphC4VuAGBf0emGgKL2CS0iB0vCrMqleFouQcbe3Fj/casNXa8B\nCyYgKbjD/Pv8aibV+rMYvkbpJ5Q82DrbCMQVXWdTOD/Wm7/8e/igW56wXKKWlOLV\nAajHQUCP7JmUKNKFqtPBSZkIWI8CyC8yfGgPo3OEJmDUyRKKirUkMlu1X49+aPnb\n7e5uETDkkVSktKq8k2sGs1nlT567c7MgGjOGn7uJT1rrx4sz38KNv0/Q4xkl3WVm\nzWbphldyJ4U8PXzGNkd+88t23DneRd0XkZNSXCYEzHBNDzqFQX0DTeqopBJVAgMB\nAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAWIlqVq0h8WtYG4Pdl2oqqeq4FGxTumKE\ny1zrge7C4bko4p4WI2+ZCHEYowTpAJmjY+iyLFL8ENldN3gLZ659kI7P8A3dThbD\nyZUC8oqTi8768FRK6DgFf6ird0cxnDU8nD120wxjE0e6CiAxbtVU+rF3dg3AjiXi\npyRJ/1QsNloN+WDZkl07m1secwdMuaovgpQrv7erOLIu/TPyXcJSds37y42ZmNbz\nC/p/kHMHd0rlgwpnm5rVWlV3cYTFQh5z54HO5Qz7a8WyFld3uOk9YHDhZ61SXDRB\nCWgVzYlf2L/Etv7sKa0/m6tM6XiAr3DjykrxX0/CIuLZ8MpdYzMt8Q==\n-----END CERTIFICATE REQUEST-----\n",
      "cert_fingerprint": "",
      "reject_reason": ""
    }
   ]
   }
   ```

   _certificate_signing_request_ is the CSR for the CA certificate. You have to use Root Certificate to issue the certificate for the CSR.

1. Sign the CSR with the root certificate.

   ```
   openssl x509 -req -in ca_cert.csr -extensions v3_req -extfile openssl.cnf -CAkey root_cert.pem -CA root_cert.crt -days 365
   ```

   The command shows how to issue a CA certificate with the root certificate with OpenSSL.
   It's important to use X509v3 extension to set the basicConstraints and keyUsage. The basicConstraints must be CA:TRUE.
   The keyUsage must include digitalSignature, keyEncipherment, keyCertSign, and cRLSign.
   Here is the config file for OpenSSL to turn on the extension.

   ```
   [req]
   distinguished_name = req_distinguished_name
   req_extensions = v3_req

   [req_distinguished_name]

   [v3_req]
   basicConstraints = CA:TRUE
   keyUsage = digitalSignature, keyEncipherment, keyCertSign, cRLSign
   ```

1. Install the CA certificate.

   ```
   cert_server client ca-cert respond --server=http://localhost:9100 --requester=you_name --id=98dea887-15b3-4ffa-8dd3-51d92f499191 --cert=ca_cert.crt
   ```

   The command install the CA certificate into the certificate server. ca_cert.crt is the CA certificate file in PEM format.
   The CA certificate is ready to issue certificates for the others now.

## Issue Certificate

To issue a certificate for a business unit, you have to create a CSR for the business unit (or third party CA) first.
The CSR will be signed by the CA certificate.

1. Add CSR
   The command to add a CSR of a business_unit into the certificate server.

   ```
   cert_server client cert add --server=http://localhost:9100 --requester=your_name --cert-type=business_unit --csr=bu.csr
   ```

   _bu.csr_ is the CSR file of the business unit in PEM format. The command returns the Cert/CSR ID.

1. Issue Certificate
   The command to issue a certificate for a CSR.

   ```
   cert_server client cert issue --server=http://localhost:9100 --requester=your_name --id=e2bc37df-d273-415e-a5e7-883a4aa7477d --ca-cert-id=c3d597dd-8401-41c7-9e9d-c9f311faf8e0 --cert-type=business_unit --not-before=2024-05-01T00:00:00Z --not-after=2100-05-01T00:00:00Z
   ```

## Revoke Certificate

```
client cert revoke --server=http://localhost:9100 --requester=your_name --id=cert_id
```
