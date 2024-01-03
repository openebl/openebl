package postgres

import (
	"context"

	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/openebl/openebl/pkg/bu_server/storage"
)

func (s *_Storage) StoreAPIKey(ctx context.Context, tx storage.Tx, key auth.APIKey) error {
	query := `
WITH new_data AS (
	INSERT INTO api_key (id, "version", application_id, status, created_at, updated_at, api_key)
	VALUES ($1, $2, $3, $4, $5, $5, $6)
	ON CONFLICT (id) DO UPDATE SET
		"version" = excluded."version",
		application_id = excluded.application_id,
		status = excluded.status,
		updated_at = excluded.updated_at,
		api_key = excluded.api_key
	RETURNING id, "version", updated_at, api_key
)
INSERT INTO api_key_history (id, "version", created_at, api_key)
SELECT * FROM new_data`

	_, err := tx.Exec(ctx, query, key.ID, key.Version, key.ApplicationID, key.Status, key.CreatedAt, key)
	if err != nil {
		return err
	}

	return nil
}

func (s *_Storage) GetAPIKey(ctx context.Context, tx storage.Tx, id string) (auth.ListAPIKeyRecord, error) {
	query := `SELECT api_key, application FROM api_key JOIN application app ON app.id = api_key.application_id WHERE api_key.id = $1`
	row := tx.QueryRow(ctx, query, id)
	key := auth.ListAPIKeyRecord{}
	if err := row.Scan(&(key.APIKey), &(key.Application)); err != nil {
		return auth.ListAPIKeyRecord{}, err
	}

	return key, nil
}

func (s *_Storage) ListAPIKeys(ctx context.Context, tx storage.Tx, req auth.ListAPIKeysRequest) (auth.ListAPIKeysResult, error) {
	query := `
SELECT count(*) OVER (), api_key, application
FROM api_key 
JOIN application app ON app.id = api_key.application_id
WHERE
	(COALESCE(array_length($3::TEXT[], 1), 0) = 0 OR api_key.application_id = ANY($3)) AND
	(COALESCE(array_length($4::TEXT[], 1), 0) = 0 OR api_key.status = ANY($4))
ORDER BY api_key.rec_id ASC
OFFSET $1 LIMIT $2`

	rows, err := tx.Query(ctx, query, req.Offset, req.Limit, req.ApplicationIDs, req.Statuses)
	if err != nil {
		return auth.ListAPIKeysResult{}, err
	}
	defer rows.Close()

	result := auth.ListAPIKeysResult{}
	for rows.Next() {
		apiKey := auth.ListAPIKeyRecord{}
		if err := rows.Scan(&result.Total, &(apiKey.APIKey), &(apiKey.Application)); err != nil {
			return auth.ListAPIKeysResult{}, err
		}
		result.Keys = append(result.Keys, apiKey)
	}
	if err := rows.Err(); err != nil {
		return auth.ListAPIKeysResult{}, err
	}

	return result, nil
}
