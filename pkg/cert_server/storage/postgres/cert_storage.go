package postgres

import (
	"context"

	"github.com/openebl/openebl/pkg/cert_server/model"
	"github.com/openebl/openebl/pkg/cert_server/storage"
)

func (s *_Storage) AddCertificate(ctx context.Context, tx storage.Tx, cert model.Cert) error {
	query := `
WITH ins AS (
	INSERT INTO cert (id, version, type, status, created_at, updated_at, cert)
	VALUES ($1, $2, $3, $4, $5, $5, $6)
	ON CONFLICT (id) DO UPDATE SET
		version = excluded.version,
		type = excluded.type,
		status = excluded.status,
		updated_at = excluded.updated_at,
		cert = excluded.cert
	RETURNING id, version, updated_at, cert
)
INSERT INTO cert_history (id, version, created_at, cert)
SELECT * FROM ins
`
	_, err := tx.Exec(
		ctx,
		query,
		cert.ID,
		cert.Version,
		cert.Type,
		cert.Status,
		max(cert.CreatedAt, cert.RejectedAt, cert.IssuedAt, cert.RevokedAt),
		cert,
	)
	if err != nil {
		return err
	}
	return nil
}

func (s *_Storage) ListCertificates(ctx context.Context, tx storage.Tx, req storage.ListCertificatesRequest) (storage.ListCertificatesResponse, error) {
	query := `
WITH filtered AS (
	SELECT rec_id, "cert" FROM "cert"
	WHERE
		(COALESCE(ARRAY_LENGTH($3::TEXT[], 1), 0) = 0 OR id = ANY($3)) AND
		(COALESCE(ARRAY_LENGTH($4::TEXT[], 1), 0) = 0 OR status = ANY($4)) AND
		(COALESCE(ARRAY_LENGTH($5::TEXT[], 1), 0) = 0 OR type = ANY($5))
)
, paged AS (
	SELECT "cert" FROM filtered
	ORDER BY rec_id ASC
	OFFSET $1 LIMIT $2
)
, total AS (
	SELECT COUNT(*) AS total FROM filtered
)
SELECT total, "cert" FROM paged FULL JOIN total ON FALSE
`
	rows, err := tx.Query(
		ctx,
		query,
		req.Offset,
		req.Limit,
		req.IDs,
		req.Statuses,
		req.Types,
	)
	if err != nil {
		return storage.ListCertificatesResponse{}, err
	}
	defer rows.Close()

	result := storage.ListCertificatesResponse{}
	for rows.Next() {
		var total *int64
		var cert *model.Cert
		if err := rows.Scan(&total, &cert); err != nil {
			return storage.ListCertificatesResponse{}, err
		}
		if total != nil {
			result.Total = *total
		}
		if cert != nil {
			result.Certs = append(result.Certs, *cert)
		}
	}
	if err := rows.Err(); err != nil {
		return storage.ListCertificatesResponse{}, err
	}

	return result, nil
}
