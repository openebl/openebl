ALTER TABLE trade_document ADD COLUMN IF NOT EXISTS decrypted_doc BYTEA;
ALTER TABLE trade_document_outbox ADD COLUMN IF NOT EXISTS kind BIGINT;
UPDATE trade_document_outbox o
SET kind = COALESCE((
    SELECT kind FROM trade_document WHERE doc_id = o.key ORDER BY rec_id LIMIT 1
), 1001);
ALTER TABLE trade_document_outbox ALTER COLUMN kind SET NOT NULL;
