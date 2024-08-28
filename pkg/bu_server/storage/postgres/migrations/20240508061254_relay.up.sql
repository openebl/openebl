CREATE TABLE relay_event (
    id TEXT PRIMARY KEY,
    "type" INT NOT NULL,
    created_at BIGINT NOT NULL,
    "event" BYTEA NOT NULL,
    stored_at BIGINT NOT NULL
);

ALTER TABLE business_unit DROP CONSTRAINT business_unit_application_id_fkey;
ALTER TABLE business_unit_authentication DROP CONSTRAINT business_unit_authentication_business_unit_id_fkey;
