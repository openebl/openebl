CREATE TABLE cert (
    rec_id BIGSERIAL,
    id TEXT PRIMARY KEY,
    "version" BIGINT NOT NULL,
    "type" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    "cert" JSONB NOT NULL,
    cert_fingerprint TEXT NOT NULL,
    cert_public_key_id TEXT NOT NULL,
    cert_issuer_key_id TEXT NOT NULL,
    cert_serial TEXT NOT NULL
);
CREATE INDEX cert_type_idx ON cert("type");
CREATE INDEX cert_fingerprint_idx ON cert("cert_fingerprint");
CREATE INDEX cert_public_key_id_idx ON cert("cert_public_key_id");
CREATE INDEX cert_issuer_key_id_serial_idx ON cert("cert_issuer_key_id", "cert_serial");

CREATE TABLE cert_history (
    rec_id BIGSERIAL,
    id TEXT NOT NULL,
    "version" BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    "cert" JSONB NOT NULL,
    PRIMARY KEY (id, version)
);

CREATE TABLE cert_revocation_list (
    rec_id BIGSERIAL,
    id TEXT PRIMARY KEY,
    issuer_key_id TEXT NOT NULL,
    "number" TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    "cert_revocation_list" JSONB NOT NULL
);
CREATE INDEX cert_revocation_list_issuer_key_id_number_idx ON cert_revocation_list("issuer_key_id", "number");

CREATE TABLE cert_outbox (
    rec_id BIGSERIAL,
    "key" TEXT NOT NULL,
    kind BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    payload BYTEA NOT NULL
);
CREATE INDEX cert_outbox_rec_id_idx ON cert_outbox("rec_id");
