package postgres

import (
	"context"

	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/openebl/openebl/pkg/bu_server/storage"
)

func (s *_Storage) StoreUser(ctx context.Context, tx storage.Tx, user auth.User) error {
	query := `
WITH new_data AS (
	INSERT INTO "user" (id, "version", status, created_at, updated_at, "user")
	VALUES ($1, $2, $3, $4, $4, $5)
	ON CONFLICT (id) DO UPDATE SET
		id = excluded.id,
		"version" = excluded."version",
		status = excluded.status,
		updated_at = excluded.updated_at,
		"user" = excluded."user"
	RETURNING id, "version", updated_at, "user"
)
INSERT INTO user_history (id, "version", created_at, "user")
SELECT * FROM new_data`

	_, err := tx.Exec(ctx, query, user.ID, user.Version, user.Status, user.UpdatedAt, user)
	if err != nil {
		return err
	}

	return nil
}

func (s *_Storage) ListUsers(ctx context.Context, tx storage.Tx, req auth.ListUserRequest) (auth.ListUserResult, error) {
	query := `
SELECT count(*) OVER () , "user" FROM "user"
WHERE
	(COALESCE(array_length($3::TEXT[], 1), 0) = 0 OR id = ANY($3))
ORDER BY rec_id ASC
OFFSET $1 LIMIT $2`

	rows, err := tx.Query(ctx, query, req.Offset, req.Limit, req.IDs)
	if err != nil {
		return auth.ListUserResult{}, err
	}
	defer rows.Close()

	result := auth.ListUserResult{}
	for rows.Next() {
		var user auth.User
		if err := rows.Scan(&result.Total, &user); err != nil {
			return auth.ListUserResult{}, err
		}
		result.Users = append(result.Users, user)
	}
	if err := rows.Err(); err != nil {
		return auth.ListUserResult{}, err
	}

	return result, nil
}
