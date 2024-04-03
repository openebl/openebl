CREATE TABLE cert (
    rec_id BIGSERIAL,
    id TEXT PRIMARY KEY,
    "version" BIGINT NOT NULL,
    "type" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    "cert" JSONB NOT NULL
);
CREATE INDEX cert_type_idx ON cert("type");

CREATE TABLE cert_history (
    rec_id BIGSERIAL,
    id TEXT NOT NULL,
    "version" BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    "cert" JSONB NOT NULL,
    PRIMARY KEY (id, version)
);