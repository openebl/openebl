CREATE TABLE api_key (
    rec_id BIGSERIAL NOT NULL,
    id TEXT PRIMARY KEY,
    "version" BIGINT NOT NULL,
    application_id TEXT NOT NULL,
    "status" TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    api_key JSONB NOT NULL
);
CREATE INDEX api_key_application_id_idx ON api_key (application_id);

CREATE TABLE api_key_history (
    rec_id BIGSERIAL NOT NULL,
    id TEXT NOT NULL,
    "version" BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    api_key JSONB NOT NULL
);
ALTER TABLE api_key_history ADD CONSTRAINT api_key_history_id_version_constraint UNIQUE (id, "version");
