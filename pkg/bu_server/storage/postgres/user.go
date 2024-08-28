package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/openebl/openebl/pkg/bu_server/storage"
)

func (s *_Storage) StoreUser(ctx context.Context, tx storage.Tx, user auth.User) error {
	query := `
WITH new_data AS (
	INSERT INTO "user" (id, username, "version", status, created_at, updated_at, "user")
	VALUES ($1, $2, $3, $4, $5, $5, $6)
	ON CONFLICT (id) DO UPDATE SET
		id = excluded.id,
		username = excluded.username,
		"version" = excluded."version",
		status = excluded.status,
		updated_at = excluded.updated_at,
		"user" = excluded."user"
	RETURNING id, "version", updated_at, "user"
)
INSERT INTO user_history (id, "version", created_at, "user")
SELECT * FROM new_data`

	_, err := tx.Exec(ctx, query, user.ID, user.Username, user.Version, user.Status, user.UpdatedAt, user)
	if err != nil {
		return err
	}

	return nil
}

func (s *_Storage) ListUsers(ctx context.Context, tx storage.Tx, req auth.ListUserRequest) (auth.ListUserResult, error) {
	query := `
SELECT count(*) OVER () , "user" FROM "user"
WHERE
	(COALESCE(array_length($3::TEXT[], 1), 0) = 0 OR id = ANY($3)) AND
	(COALESCE(array_length($4::TEXT[], 1), 0) = 0 OR username = ANY($4))
ORDER BY rec_id ASC
OFFSET $1 LIMIT $2`

	rows, err := tx.Query(ctx, query, req.Offset, req.Limit, req.IDs, req.Usernames)
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

func (s *_Storage) StoreUserToken(ctx context.Context, tx storage.Tx, token auth.UserToken) error {
	query := `INSERT INTO user_token (token, user_id, created_at, expired_at) VALUES ($1, $2, $3, $4)`
	_, err := tx.Exec(ctx, query, token.Token, token.UserID, token.CreatedAt, token.ExpiredAt)
	if err != nil {
		return err
	}
	return nil
}

func (s *_Storage) GetUserToken(ctx context.Context, tx storage.Tx, token string) (auth.UserToken, error) {
	query := `SELECT token, user_id, created_at, expired_at FROM user_token WHERE token = $1`
	var userToken auth.UserToken
	err := tx.QueryRow(ctx, query, token).Scan(&userToken.Token, &userToken.UserID, &userToken.CreatedAt, &userToken.ExpiredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.UserToken{}, sql.ErrNoRows
	} else if err != nil {
		return auth.UserToken{}, err
	}
	return userToken, nil
}

func (s *_Storage) RemoveUserTokenByExpiredAt(ctx context.Context, tx storage.Tx, expiredAt int64) error {
	query := `DELETE FROM user_token WHERE expired_at <= $1`
	_, err := tx.Exec(ctx, query, expiredAt)
	if err != nil {
		return err
	}
	return nil
}
