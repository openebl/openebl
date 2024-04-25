ALTER TABLE business_unit_authentication ADD COLUMN cert_public_key_id TEXT;
ALTER TABLE business_unit_authentication ADD COLUMN cert_issuer_key_id TEXT;
ALTER TABLE business_unit_authentication ADD COLUMN cert_serial TEXT;
ALTER TABLE business_unit_authentication ADD COLUMN cert_fingerprint TEXT;

CREATE INDEX idx_business_unit_authentication_cert_public_key_id ON business_unit_authentication(cert_public_key_id);
CREATE INDEX idx_business_unit_authentication_cert_issuer_key_id ON business_unit_authentication(cert_issuer_key_id);
CREATE INDEX idx_business_unit_authentication_cert_fingerprint ON business_unit_authentication(cert_fingerprint);

CREATE TABLE cert_revocation_list (
    rec_id BIGSERIAL,
    issuer_key_id TEXT NOT NULL,
    "cert_serial_number" TEXT NOT NULL,
    revoked_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    "cert_revocation_list" BYTEA NOT NULL
);
CREATE INDEX cert_revocation_list_issuer_key_id_number_idx ON cert_revocation_list("issuer_key_id", "cert_serial_number");

CREATE TABLE root_cert (
    rec_id BIGSERIAL,
    cert_fingerprint TEXT PRIMARY KEY,
    revoked BOOLEAN NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    "cert" BYTEA NOT NULL
);
