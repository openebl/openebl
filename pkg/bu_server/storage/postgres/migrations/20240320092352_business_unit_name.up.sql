CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE FUNCTION decode_base64url(TEXT) RETURNS BYTEA AS $$
  SELECT decode(
    rpad(translate($1, '-_', '+/')   -- pad to the next multiple of 4 bytes
	 ,4*((length($1)+3)/4)
	 ,'=')
    ,'base64');
$$ LANGUAGE sql strict immutable;

ALTER TABLE business_unit ADD COLUMN IF NOT EXISTS "name" TEXT;
ALTER TABLE trade_document ADD COLUMN IF NOT EXISTS "doc_reference" TEXT;

UPDATE business_unit SET "name" = "business_unit"->>'name';
UPDATE trade_document SET "doc_reference" =
convert_from(decode_base64url(convert_from("doc", 'UTF8')::jsonb->>'payload'), 'UTF8')::jsonb->'events'->0->'bill_of_lading'->'bill_of_lading'->>'transportDocumentReference';
ALTER TABLE business_unit ALTER COLUMN "name" SET NOT NULL;
ALTER TABLE trade_document ALTER COLUMN "doc_reference" SET NOT NULL;

CREATE INDEX IF NOT EXISTS business_unit_name_idx ON business_unit USING GIN(name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS trade_document_doc_reference_idx ON trade_document USING GIN(doc_reference gin_trgm_ops);

DROP FUNCTION IF EXISTS decode_base64url(TEXT);
