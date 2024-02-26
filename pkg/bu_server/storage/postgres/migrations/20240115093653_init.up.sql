CREATE TABLE "user" (
    rec_id BIGSERIAL NOT NULL,
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    "version" BIGINT NOT NULL,
    "status" TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    "user" JSONB NOT NULL
);
ALTER TABLE "user" ADD CONSTRAINT user_username_lowercase_check CHECK (username = LOWER(TRIM(username)));
CREATE UNIQUE INDEX IF NOT EXISTS user_username_key ON "user"(username);

CREATE TABLE "user_history" (
    rec_id BIGSERIAL NOT NULL,
    id TEXT NOT NULL,
    "version" BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    "user" JSONB NOT NULL
);
ALTER TABLE user_history ADD CONSTRAINT user_history_id_version_key UNIQUE (id, "version");

-- Install a default user. UserID is "root", password is also "root".
INSERT INTO "user" (
	id,
	username,
	"version",
	"status",
	created_at,
	updated_at,
	"user"
) VALUES (
	'usr_00000000-0000-0000-0000-000000000000',
	'root',
	1,
	'active',
	extract(epoch FROM now())::BIGINT,
	extract(epoch FROM now())::BIGINT ,
	jsonb_build_object(
		'id', 'usr_00000000-0000-0000-0000-000000000000',
		'username', 'root',
		'status', 'active',
		'version', 1,
		'password', '$2a$10$7jenPP1tbsqet7j9PrMcwOnC8emt6jeyGiWBQNnu4adW9RF3j3KUu',
		'name', 'root',
		'note', 'default root user',
		'created_at', extract(epoch FROM now())::BIGINT,
		'updated_at', extract(epoch FROM now())::BIGINT
	)
);

CREATE TABLE user_token (
	token TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	created_at BIGINT NOT NULL,
	expired_at BIGINT NOT NULL,
	FOREIGN KEY (user_id) REFERENCES "user"(id) ON DELETE CASCADE
);

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
ALTER TABLE application_history ADD CONSTRAINT application_history_id_version_key UNIQUE (id, "version");

CREATE TABLE api_key (
    rec_id BIGSERIAL NOT NULL,
    id TEXT PRIMARY KEY,
    "version" BIGINT NOT NULL,
    application_id TEXT NOT NULL,
    "status" TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    api_key JSONB NOT NULL,
    FOREIGN KEY (application_id) REFERENCES application (id) ON DELETE CASCADE
);
CREATE INDEX api_key_application_id_idx ON api_key (application_id);

CREATE TABLE api_key_history (
    rec_id BIGSERIAL NOT NULL,
    id TEXT NOT NULL,
    "version" BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    api_key JSONB NOT NULL
);
ALTER TABLE api_key_history ADD CONSTRAINT api_key_history_id_version_key UNIQUE (id, "version");
