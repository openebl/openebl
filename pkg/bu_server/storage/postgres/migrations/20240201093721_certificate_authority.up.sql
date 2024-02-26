CREATE TABLE certificate (
    rec_id BIGSERIAL,
    id TEXT PRIMARY KEY,
    "version" BIGINT NOT NULL,
    "status" TEXT NOT NULL,
    valid_time INT8RANGE NOT NULL,
    cert_type TEXT NOT NULL,
    cert_fingerprint TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    "cert" JSONB NOT NULL
);
CREATE INDEX certificate_status_idx ON certificate (status);
CREATE INDEX certificate_valid_time_idx ON certificate (valid_time);
CREATE INDEX certificate_cert_type_idx ON certificate (cert_type);
CREATE INDEX certificate_cert_fingerprint_idx ON certificate (cert_fingerprint);

CREATE TABLE certificate_history (
    rec_id BIGSERIAL,
    id TEXT NOT NULL,
    "version" BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    "cert" JSONB NOT NULL
);
ALTER TABLE certificate_history ADD CONSTRAINT certificate_history_pkey PRIMARY KEY (id, version);
