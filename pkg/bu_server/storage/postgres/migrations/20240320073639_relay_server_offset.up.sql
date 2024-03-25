CREATE TABLE IF NOT EXISTS relay_server_offset (
    server_id TEXT NOT NULL,
    comsumed_offset BIGINT NOT NULL,
    updated_at BIGINT DEFAULT EXTRACT(EPOCH FROM NOW()),
    PRIMARY KEY (server_id)
);

ALTER TABLE relay_server_offset ADD CONSTRAINT relay_server_offset_server_id_check CHECK (TRIM(server_id) <> '');
