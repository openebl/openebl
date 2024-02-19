CREATE TABLE trade_document (
    rec_id BIGSERIAL,
    id TEXT PRIMARY KEY,            -- Raw ID of the whole document including JWS/JWE envelope.
    kind BIGINT NOT NULL,           -- Kind of the trade document.
    doc_id TEXT NOT NULL,           -- ID of the trade document.
    doc_version BIGINT NOT NULL,    -- Version of the trade document.
    doc BYTEA NOT NULL,             -- trade document (binary format).
    created_at BIGINT NOT NULL,     -- Timestamp of the creation of the trade document.
    meta JSONB NOT NULL             -- Metadata of the trade document.
);

CREATE INDEX idx_trade_document_doc_id ON trade_document (doc_id);
CREATE INDEX idx_trade_document_kind ON trade_document (kind);
CREATE INDEX idx_trade_document_meta ON trade_document USING GIN (meta);

