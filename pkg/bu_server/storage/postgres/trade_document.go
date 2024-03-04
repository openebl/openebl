package postgres

import (
	"context"

	"github.com/openebl/openebl/pkg/bu_server/storage"
)

func (s *_Storage) AddTradeDocument(ctx context.Context, tx storage.Tx, tradeDoc storage.TradeDocument) error {
	query := `
INSERT INTO trade_document (id, kind, doc_id, doc_version, doc, created_at, meta) VALUES (
	$1,	-- id
	$2,	-- kind
	$3, -- doc_id
	$4,	-- doc_version
	$5,	-- doc
	$6,	-- created_at
	$7	-- meta
) ON CONFLICT (id) DO NOTHING`
	_, err := tx.Exec(
		ctx,
		query,
		tradeDoc.RawID,
		tradeDoc.Kind,
		tradeDoc.DocID,
		tradeDoc.DocVersion,
		tradeDoc.Doc,
		tradeDoc.CreatedAt,
		tradeDoc.Meta,
	)
	if err != nil {
		return err
	}
	return nil
}

func (s *_Storage) ListTradeDocument(ctx context.Context, tx storage.Tx, req storage.ListTradeDocumentRequest) (storage.ListTradeDocumentResponse, error) {
	query := `
WITH filtered_record AS (
	SELECT DISTINCT ON (rec_id, doc_id)
		first_value(rec_id) OVER (PARTITION BY doc_id ORDER BY doc_version DESC) AS rec_id,
		first_value(id) OVER (PARTITION BY doc_id ORDER BY doc_version DESC) AS id,
		first_value(kind) OVER (PARTITION BY doc_id ORDER BY doc_version DESC) AS kind,
		doc_id,
		first_value(doc_version) OVER (PARTITION BY doc_id ORDER BY doc_version DESC) AS doc_version,
		first_value(doc) OVER (PARTITION BY doc_id ORDER BY doc_version DESC) AS doc,
		first_value(created_at) OVER (PARTITION BY doc_id ORDER BY doc_version DESC) AS created_at,
		first_value(meta) OVER (PARTITION BY doc_id ORDER BY doc_version DESC) AS meta
	FROM trade_document td
	WHERE
		($3 = 0 OR $3 = kind) AND
		(COALESCE(ARRAY_LENGTH($4::TEXT[], 1), 0) = 0 OR doc_id = ANY($4)) AND
		($5::JSONB IS NULL OR meta @> $5)
)
, report AS (
	SELECT COUNT(*) AS total FROM filtered_record
) 
, paged_record AS (
	SELECT
		id,
		kind,
		doc_id,
		doc_version,
		doc,
		created_at,
		meta
	FROM filtered_record ORDER BY rec_id DESC OFFSET $1 LIMIT $2 
)
SELECT *
FROM paged_record
FULL JOIN report ON TRUE
`

	rows, err := tx.Query(
		ctx,
		query,
		req.Offset,
		req.Limit,
		req.Kind,
		req.DocIDs,
		req.Meta,
	)
	if err != nil {
		return storage.ListTradeDocumentResponse{}, err
	}
	defer rows.Close()

	result := storage.ListTradeDocumentResponse{}
	for rows.Next() {
		var tradeDoc storage.TradeDocument
		err = rows.Scan(
			&tradeDoc.RawID,
			&tradeDoc.Kind,
			&tradeDoc.DocID,
			&tradeDoc.DocVersion,
			&tradeDoc.Doc,
			&tradeDoc.CreatedAt,
			&tradeDoc.Meta,
			&result.Total,
		)
		if err != nil {
			return storage.ListTradeDocumentResponse{}, err
		}
		if tradeDoc.RawID != "" {
			result.Docs = append(result.Docs, tradeDoc)
		}
	}
	if err := rows.Err(); err != nil {
		return storage.ListTradeDocumentResponse{}, err
	}

	return result, nil
}
