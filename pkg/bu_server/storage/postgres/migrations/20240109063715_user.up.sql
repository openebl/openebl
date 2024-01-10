CREATE TABLE "user" (
    rec_id BIGSERIAL NOT NULL,
    id TEXT PRIMARY KEY,
    "version" BIGINT NOT NULL,
    "status" TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    "user" JSONB NOT NULL
);

CREATE TABLE "user_history" (
    rec_id BIGSERIAL NOT NULL,
    id TEXT NOT NULL,
    "version" BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    "user" JSONB NOT NULL
);
ALTER TABLE user_history ADD CONSTRAINT user_history_id_version_constraint UNIQUE (id, "version");

-- Install a default user. UserID is "root", password is also "root".
INSERT INTO "user" (
	id,
	"version",
	"status",
	created_at,
	updated_at,
	"user"
) VALUES (
	'root',
	1,
	'active',
	extract(epoch FROM now())::BIGINT,
	extract(epoch FROM now())::BIGINT ,
	jsonb_build_object(
		'id', 'root',
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
