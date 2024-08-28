CREATE TABLE IF NOT EXISTS webhook (
    rec_id BIGSERIAL,
    id TEXT PRIMARY KEY,
    version BIGINT NOT NULL,
    deleted BOOLEAN NOT NULL,
    application_id TEXT NOT NULL REFERENCES application(id) ON DELETE CASCADE,
    events TEXT[] NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    webhook JSONB NOT NULL
);

CREATE INDEX webhook_application_id_id_idx ON webhook (application_id, id);
CREATE INDEX webhook_events_idx ON webhook USING GIN (events);

CREATE TABLE IF NOT EXISTS webhook_history (
    rec_id BIGSERIAL,
    id TEXT NOT NULL,
    "version" BIGINT NOT NULL,
    webhook JSONB NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (id, version)
);

CREATE TABLE IF NOT EXISTS webhook_outbox (
    rec_id BIGSERIAL,
    key TEXT,
    event BYTEA,
    created_at BIGINT,
    PRIMARY KEY(rec_id)
);
