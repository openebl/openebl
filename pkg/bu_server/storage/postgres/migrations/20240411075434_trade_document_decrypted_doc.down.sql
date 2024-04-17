ALTER TABLE trade_document DROP COLUMN IF EXISTS decrypted_doc;
ALTER TABLE trade_document_outbox DROP COLUMN IF EXISTS kind;
