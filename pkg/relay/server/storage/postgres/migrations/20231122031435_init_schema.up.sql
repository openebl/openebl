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
