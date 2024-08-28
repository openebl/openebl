package postgres

import (
	"context"

	"github.com/openebl/openebl/pkg/cert_server/model"
	"github.com/openebl/openebl/pkg/cert_server/storage"
)

func (s *_Storage) AddCertificate(ctx context.Context, tx storage.Tx, cert model.Cert) error {
	query := `
WITH ins AS (
	INSERT INTO cert (id, version, type, status, created_at, updated_at, cert, cert_fingerprint, cert_public_key_id, cert_issuer_key_id, cert_serial)
	VALUES ($1, $2, $3, $4, $5, $5, $6, $7, $8, $9, $10)
	ON CONFLICT (id) DO UPDATE SET
		version = excluded.version,
		type = excluded.type,
		status = excluded.status,
		updated_at = excluded.updated_at,
		cert = excluded.cert,
		cert_fingerprint = excluded.cert_fingerprint,
		cert_public_key_id = excluded.cert_public_key_id,
		cert_issuer_key_id = excluded.cert_issuer_key_id,
		cert_serial = excluded.cert_serial
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
		cert.CertFingerPrint,
		cert.PublicKeyID,
		cert.IssuerKeyID,
		cert.CertificateSerialNumber,
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
		(COALESCE(ARRAY_LENGTH($5::TEXT[], 1), 0) = 0 OR type = ANY($5)) AND
		(COALESCE(ARRAY_LENGTH($6::TEXT[], 1), 0) = 0 OR cert_public_key_id = ANY($6))
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
		req.PublicKeyIDs,
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

func (s *_Storage) AddCertificateRevocationList(ctx context.Context, tx storage.Tx, crl model.CertRevocationList) error {
	query := `
INSERT INTO cert_revocation_list (id, issuer_key_id, number, created_at, cert_revocation_list)
VALUES ($1, $2, $3, $4, $5)
`
	_, err := tx.Exec(
		ctx,
		query,
		crl.ID,
		crl.IssuerKeyID,
		crl.Number,
		crl.CreatedAt,
		crl,
	)
	if err != nil {
		return err
	}
	return nil
}

func (s *_Storage) AddCertificateOutboxMsg(ctx context.Context, tx storage.Tx, ts int64, key string, kind int, payload []byte) error {
	query := `INSERT INTO cert_outbox (key, kind, created_at, payload) VALUES ($1, $2, $3, $4)`

	_, err := tx.Exec(ctx, query, key, kind, ts, payload)
	if err != nil {
		return err
	}
	return nil
}

func (s *_Storage) GetCertificateOutboxMsg(ctx context.Context, tx storage.Tx, batchSize int) ([]storage.CertificateOutboxMsg, error) {
	query := `
SELECT rec_id, key, kind, payload
FROM cert_outbox
ORDER BY rec_id ASC LIMIT $1
FOR UPDATE`

	rows, err := tx.Query(ctx, query, batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []storage.CertificateOutboxMsg
	for rows.Next() {
		var msg storage.CertificateOutboxMsg
		if err := rows.Scan(&msg.RecID, &msg.Key, &msg.Kind, &msg.Msg); err != nil {
			return nil, err
		}
		result = append(result, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

func (s *_Storage) DeleteCertificateOutboxMsg(ctx context.Context, tx storage.Tx, recIDs ...int64) error {
	query := `DELETE FROM cert_outbox WHERE rec_id = ANY($1)`

	_, err := tx.Exec(ctx, query, recIDs)
	if err != nil {
		return err
	}
	return nil
}
