package postgres

import (
	"context"
	"database/sql"

	"github.com/openebl/openebl/pkg/bu_server/storage"
)

func (s *_Storage) AddTradeDocument(ctx context.Context, tx storage.Tx, tradeDoc storage.TradeDocument) error {
	query := `
INSERT INTO trade_document (id, kind, doc_id, doc_version, doc_reference, doc, decrypted_doc, created_at, meta) VALUES (
	$1,	-- id
	$2,	-- kind
	$3, -- doc_id
	$4,	-- doc_version
	$5, -- doc_reference
	$6,	-- doc
	$7,	-- decrypted_doc
	$8,	-- created_at
	$9	-- meta
) ON CONFLICT (id) DO NOTHING`
	_, err := tx.Exec(
		ctx,
		query,
		tradeDoc.RawID,
		tradeDoc.Kind,
		tradeDoc.DocID,
		tradeDoc.DocVersion,
		tradeDoc.DocReference,
		tradeDoc.Doc,
		tradeDoc.DecryptedDoc,
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
WITH prefiltered_bu AS (
	SELECT
		id,
		CASE
			WHEN $8 = '' THEN 0
			WHEN UPPER($8) = UPPER(name) THEN 2
			ELSE WORD_SIMILARITY($8, name)
		END AS keyword_score
	FROM business_unit
	WHERE
		$8 = '' OR $8 <% name
)
, filtered_bu AS (
	SELECT 
		id AS bu_id
	FROM prefiltered_bu
	WHERE
		keyword_score = (SELECT MAX(keyword_score) FROM prefiltered_bu)
)
, latest_visible AS (
    SELECT DISTINCT ON (rec_id, doc_id)
		first_value(rec_id) OVER w AS rec_id,
		first_value(id) OVER w AS id,
		first_value(kind) OVER w AS kind,
		doc_id,
		first_value(doc_version) OVER w AS doc_version,
		first_value(doc_reference) OVER w AS doc_reference,
		first_value(doc) OVER w AS doc,
		first_value(decrypted_doc) OVER w AS decrypted_doc,
		first_value(created_at) OVER w AS created_at,
		first_value(meta) OVER w AS meta
	FROM trade_document td
    WHERE ($6 = '' OR meta @> jsonb_build_object('visible_to_bu', ARRAY[$6]))
    WINDOW w AS (PARTITION BY doc_id ORDER BY doc_version DESC)
)
, filtered_record AS (
	SELECT *
	FROM latest_visible
	WHERE
		NOT (meta ? 'deleted') AND
		(COALESCE(ARRAY_LENGTH($3::BIGINT[], 1), 0) = 0 OR kind = ANY($3)) AND
		(COALESCE(ARRAY_LENGTH($4::TEXT[], 1), 0) = 0 OR doc_id = ANY($4)) AND
		($5::JSONB IS NULL OR meta @> $5) AND
		(
			($8 = '' AND $9 = '') OR
			meta->>'from' = ANY(SELECT * FROM filtered_bu) OR
		    doc_reference ILIKE '%' || $9 || '%' ESCAPE '\'
		)
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
	    doc_reference,
		doc,
		decrypted_doc,
		created_at,
		meta
	FROM filtered_record ORDER BY rec_id DESC OFFSET $1 LIMIT $2 
)
SELECT *
FROM paged_record
FULL JOIN report ON TRUE
LEFT JOIN LATERAL(
  SELECT 
    jsonb_build_object(
      'action_needed', COUNT(*) FILTER(WHERE meta @> jsonb_build_object('action_needed', ARRAY[$6])),
      'upcoming', COUNT(*) FILTER(WHERE meta @> jsonb_build_object('upcoming', ARRAY[$6])),
      'sent', COUNT(*) FILTER(WHERE meta @> jsonb_build_object('sent', ARRAY[$6])),
      'archive', COUNT(*) FILTER(WHERE meta @> jsonb_build_object('archive', ARRAY[$6]))
    ) AS report
  FROM latest_visible
) AS status_report ON $7
`

	rows, err := tx.Query(
		ctx,
		query,
		req.Offset,
		req.Limit,
		req.Kinds,
		req.DocIDs,
		req.Meta,
		req.RequestBy,
		req.Report,
		req.From,
		req.DocReference,
	)
	if err != nil {
		return storage.ListTradeDocumentResponse{}, err
	}
	defer rows.Close()

	result := storage.ListTradeDocumentResponse{}
	for rows.Next() {
		var rawID sql.NullString
		var kind sql.NullInt32
		var docID sql.NullString
		var docVersion sql.NullInt64
		var docReference sql.NullString
		var doc []byte
		var decryptedDoc []byte
		var createdAt sql.NullInt64
		var meta map[string]interface{}
		err = rows.Scan(
			&rawID,
			&kind,
			&docID,
			&docVersion,
			&docReference,
			&doc,
			&decryptedDoc,
			&createdAt,
			&meta,
			&result.Total,
			&result.Report,
		)
		if err != nil {
			return storage.ListTradeDocumentResponse{}, err
		}
		if rawID.Valid {
			result.Docs = append(result.Docs,
				storage.TradeDocument{
					RawID:        rawID.String,
					Kind:         int(kind.Int32),
					DocID:        docID.String,
					DocVersion:   docVersion.Int64,
					DocReference: docReference.String,
					Doc:          doc,
					DecryptedDoc: decryptedDoc,
					CreatedAt:    createdAt.Int64,
					Meta:         meta,
				},
			)
		}
	}
	if err := rows.Err(); err != nil {
		return storage.ListTradeDocumentResponse{}, err
	}

	return result, nil
}
