CREATE TABLE event (
    "offset" BIGSERIAL,
    id TEXT PRIMARY KEY,
    "type" INT NOT NULL,
    created_at BIGINT NOT NULL,
    "event" BYTEA NOT NULL
);

CREATE INDEX event_offset_type_idx ON event ("offset", "type");
