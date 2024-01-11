CREATE TABLE application (
    rec_id BIGSERIAL NOT NULL,
    id TEXT PRIMARY KEY,
    "version" BIGINT NOT NULL,
    "status" TEXT NOT NULL,
    name TEXT NOT NULL,
    company_name TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    application JSONB NOT NULL
);

CREATE TABLE application_history (
    rec_id BIGSERIAL NOT NULL,
    id TEXT,
    "version" BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    application JSONB NOT NULL
);
ALTER TABLE application_history ADD CONSTRAINT application_history_id_version_constraint UNIQUE (id, "version");
