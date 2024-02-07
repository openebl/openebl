package postgres

import (
	"context"

	"github.com/openebl/openebl/pkg/bu_server/cert_authority"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
)

func (s *_Storage) AddCertificate(ctx context.Context, tx storage.Tx, cert model.Cert) error {
	query := `
WITH ins AS (
	INSERT INTO certificate (id, "version", "status", valid_time, cert_type, cert_fingerprint, created_at, updated_at, cert)
	VALUES ($1, $2, $3, int8range($4, $5), $6, $7, $8, $8, $9)
	ON CONFLICT (id) DO UPDATE SET
		"version" = excluded."version",
	 	"status" = excluded."status",
		valid_time = excluded.valid_time,
		cert_fingerprint = excluded.cert_fingerprint,
		updated_at = excluded.updated_at,
		cert = excluded.cert
	RETURNING id, "version", updated_at, cert
)
INSERT INTO certificate_history (id, "version", created_at, cert)
SELECT * FROM ins
`
	_, err := tx.Exec(
		ctx,
		query,
		cert.ID,
		cert.Version,
		cert.Status,
		cert.NotBefore,
		cert.NotAfter,
		cert.Type,
		cert.CertFingerPrint,
		max(cert.CreatedAt, cert.RevokedAt),
		cert,
	)
	if err != nil {
		return err
	}
	return nil
}

func (s *_Storage) ListCertificates(ctx context.Context, tx storage.Tx, req cert_authority.ListCertificatesRequest) ([]model.Cert, error) {
	query := `
SELECT cert FROM certificate
WHERE
	(COALESCE(ARRAY_LENGTH($3::TEXT[], 1), 0) = 0 OR id = ANY($3)) AND
	(COALESCE(ARRAY_LENGTH($4::TEXT[], 1), 0) = 0 OR status = ANY($4)) AND 
	(($5 = 0 AND $6 = 0) OR int8range($5, $6) <@ valid_time)
ORDER BY rec_id ASC
OFFSET $1 LIMIT $2
`
	rows, err := tx.Query(ctx, query, req.Offset, req.Limit, req.IDs, req.Statuses, req.ValidFrom, req.ValidTo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	certs := make([]model.Cert, 0, max(10, min(req.Limit, 100)))
	for rows.Next() {
		var cert model.Cert
		if err := rows.Scan(&cert); err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
