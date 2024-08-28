CREATE TABLE event (
    "offset" BIGSERIAL,
    id TEXT PRIMARY KEY,
    "type" INT NOT NULL,
    created_at BIGINT NOT NULL,
    "event" BYTEA NOT NULL
);

CREATE INDEX event_offset_type_idx ON event ("offset", "type");

CREATE TABLE "offset" (
    peer TEXT PRIMARY KEY,
    "offset" BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE storage_identify(
    id TEXT PRIMARY KEY,
    created_at BIGINT NOT NULL
);

INSERT INTO storage_identify (id, created_at) VALUES (gen_random_uuid()::TEXT, EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::BIGINT);
