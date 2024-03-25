CREATE TABLE IF NOT EXISTS trade_document_outbox (
    rec_id BIGSERIAL,
    key TEXT,
    payload BYTEA,
    created_at BIGINT,
    PRIMARY KEY(rec_id)
);
