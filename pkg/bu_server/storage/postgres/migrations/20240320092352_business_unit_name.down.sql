DROP INDEX IF EXISTS business_unit_name_idx;
DROP INDEX IF EXISTS trade_document_doc_reference_idx;
ALTER TABLE business_unit DROP COLUMN IF EXISTS "name";
ALTER TABLE trade_document DROP COLUMN IF EXISTS "doc_reference";
