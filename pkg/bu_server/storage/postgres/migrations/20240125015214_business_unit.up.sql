CREATE TABLE business_unit (
    rec_id BIGSERIAL,
    id TEXT PRIMARY KEY,
    "version" BIGINT NOT NULL,
    application_id TEXT NOT NULL REFERENCES application(id) ON DELETE CASCADE,
    "status" TEXT NOT NULL,
    business_unit JSONB NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX business_unit_application_id_id_idx ON business_unit (application_id, id);

CREATE TABLE business_unit_history (
    rec_id BIGSERIAL,
    id TEXT NOT NULL,
    "version" BIGINT NOT NULL,
    business_unit JSONB NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (id, version)
);

CREATE TABLE business_unit_authentication (
    rec_id BIGSERIAL,
    id TEXT PRIMARY KEY,
    "version" BIGINT NOT NULL,
    business_unit_id TEXT NOT NULL REFERENCES business_unit(id) ON DELETE CASCADE,
    "status" TEXT NOT NULL,
    "authentication" JSONB NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX business_unit_authentication_business_unit_id_id_idx ON business_unit_authentication (business_unit_id, id);

CREATE TABLE business_unit_authentication_history (
    rec_id BIGSERIAL,
    id TEXT NOT NULL,
    "version" BIGINT NOT NULL,
    "authentication" JSONB NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (id, version)
);
