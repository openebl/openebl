package postgres

import (
	"context"

	"github.com/openebl/openebl/pkg/relay/server/storage"
)

func (s *_Storage) AddRootCert(ctx context.Context, ts int64, fingerPrint string, cert []byte) error {
	tx, err := s.CreateTX(ctx, false)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	query := `
INSERT INTO root_cert (cert_fingerprint, revoked, created_at, updated_at, cert)
VALUES ($1, false, $2, $2, $3)
ON CONFLICT (cert_fingerprint) DO UPDATE SET
	updated_at = excluded.updated_at,
	cert = excluded.cert
`
	_, err = tx.Exec(
		ctx,
		query,
		fingerPrint,
		ts,
		cert,
	)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

func (s *_Storage) RevokeRootCert(ctx context.Context, ts int64, fingerPrinter string) error {
	tx, err := s.CreateTX(ctx, false)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	query := `
UPDATE root_cert
SET revoked = true, updated_at = $1
WHERE cert_fingerprint = $2`
	_, err = tx.Exec(
		ctx,
		query,
		ts,
		fingerPrinter,
	)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

func (s *_Storage) GetActiveRootCert(ctx context.Context) ([][]byte, error) {
	tx, err := s.CreateTX(ctx, true)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	query := `
SELECT cert
FROM root_cert
WHERE revoked = false
`
	rows, err := tx.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var certs [][]byte
	for rows.Next() {
		var cert []byte
		if err := rows.Scan(&cert); err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

func (s *_Storage) AddCRL(ctx context.Context, ts int64, issuerKeyID string, certSerialNumber string, revokedAt int64, crl []byte) error {
	tx, err := s.CreateTX(ctx, false)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	query := `
INSERT INTO cert_revocation_list (issuer_key_id, cert_serial_number, revoked_at, cert_revocation_list, created_at)
VALUES ($1, $2, $3, $4, $5)`
	_, err = tx.Exec(
		ctx,
		query,
		issuerKeyID,
		certSerialNumber,
		revokedAt,
		crl,
		ts,
	)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

func (s *_Storage) GetCRL(ctx context.Context, req storage.GetCRLRequest) (storage.GetCRLResult, error) {
	tx, err := s.CreateTX(ctx, true)
	if err != nil {
		return storage.GetCRLResult{}, err
	}
	defer tx.Rollback(ctx)

	query := `
SELECT crl.issuer_key_id, crl.cert_serial_number, crl.cert_revocation_list
FROM cert_revocation_list AS crl
JOIN json_to_recordset($1) AS req (issuer_key_id TEXT,cert_serial_number TEXT)
ON crl.issuer_key_id = req.issuer_key_id AND crl.cert_serial_number = req.cert_serial_number
WHERE ($2 = 0 OR crl.revoked_at <= $2)
`
	result := storage.GetCRLResult{}
	rows, err := tx.Query(ctx, query, req.IssuerKeysAndCertSerialNumbers, req.RevokedAt)
	if err != nil {
		return storage.GetCRLResult{}, err
	}
	defer rows.Close()

	result.CRLs = make(map[storage.IssuerKeyAndCertSerialNumber][]byte)
	for rows.Next() {
		keyID := ""
		certSerial := ""
		var crl []byte
		if err := rows.Scan(&keyID, &certSerial, &crl); err != nil {
			return storage.GetCRLResult{}, err
		}
		keyAndSerial := storage.IssuerKeyAndCertSerialNumber{
			IssuerKeyID:       keyID,
			CertificateSerial: certSerial,
		}
		result.CRLs[keyAndSerial] = crl
	}
	if err := rows.Err(); err != nil {
		return storage.GetCRLResult{}, err
	}

	return result, nil
}
