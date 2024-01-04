package postgres

import (
	"context"

	"github.com/openebl/openebl/pkg/bu_server/auth"
	"github.com/openebl/openebl/pkg/bu_server/storage"
)

func (s *_Storage) StoreApplication(ctx context.Context, tx storage.Tx, app auth.Application) error {
	query := `
WITH new_data AS (
	INSERT INTO application (id, "version", name, company_name, status, created_at, updated_at, application)
	VALUES ($1, $2, $3, $4, $5, $6, $6, $7)
	ON CONFLICT (id) DO UPDATE SET
		"version" = excluded."version",
		name = excluded.name,
		status = excluded.status,
		updated_at = excluded.updated_at,
		application = excluded.application
	RETURNING id, "version", updated_at, application
)
INSERT INTO application_history (id, "version", created_at, application)
SELECT * FROM new_data`

	_, err := tx.Exec(ctx, query, app.ID, app.Version, app.Name, app.CompanyName, app.Status, app.UpdatedAt, app)
	if err != nil {
		return err
	}

	return nil
}

func (s *_Storage) ListApplication(ctx context.Context, tx storage.Tx, req auth.ListApplicationRequest) (auth.ListApplicationResult, error) {
	query := `
SELECT count(*) OVER () , application FROM application
WHERE
	(COALESCE(array_length($3::TEXT[], 1), 0) = 0 OR id = ANY($3)) AND
	(COALESCE(array_length($4::TEXT[], 1), 0) = 0 OR status = ANY($4))
ORDER BY rec_id ASC
OFFSET $1 LIMIT $2`

	rows, err := tx.Query(ctx, query, req.Offset, req.Limit, req.IDs, req.Statuses)
	if err != nil {
		return auth.ListApplicationResult{}, err
	}
	defer rows.Close()

	result := auth.ListApplicationResult{}
	for rows.Next() {
		var app auth.Application
		if err := rows.Scan(&result.Total, &app); err != nil {
			return auth.ListApplicationResult{}, err
		}
		result.Applications = append(result.Applications, app)
	}
	if err := rows.Err(); err != nil {
		return auth.ListApplicationResult{}, err
	}

	return result, nil
}
