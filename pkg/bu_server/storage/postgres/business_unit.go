package postgres

import (
	"context"

	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/bu_server/storage"
)

func (s *_Storage) StoreBusinessUnit(ctx context.Context, tx storage.Tx, bu model.BusinessUnit) error {
	query := `
WITH new_data AS (
	INSERT INTO business_unit (id, "version", application_id, "status", business_unit, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, $6)
	ON CONFLICT (id) DO UPDATE SET
		"version" = excluded."version",
		application_id = excluded.application_id,
		"status" = excluded."status",
		business_unit = excluded.business_unit,
		updated_at = excluded.updated_at
	RETURNING id, "version", business_unit, updated_at
)
INSERT INTO business_unit_history (id, "version", business_unit, created_at)
SELECT * FROM new_data
`
	_, err := tx.Exec(
		ctx,
		query,
		bu.ID,
		bu.Version,
		bu.ApplicationID,
		bu.Status,
		bu,
		bu.UpdatedAt,
	)
	if err != nil {
		return err
	}
	return err
}

func (s *_Storage) ListBusinessUnits(ctx context.Context, tx storage.Tx, req business_unit.ListBusinessUnitsRequest) (business_unit.ListBusinessUnitsResult, error) {
	query := `
WITH filtered_record AS (
	SELECT
		rec_id,
		business_unit,
		(SELECT JSONB_AGG(authentication ORDER BY ba.rec_id ASC) FROM business_unit_authentication ba WHERE ba.business_unit_id  = bu.id) As authentications
	FROM business_unit bu
	WHERE
		($3 = '' OR application_id = $3) AND
		(COALESCE(array_length($4::TEXT[], 1), 0) = 0 OR id = ANY($4))
)
SELECT
	total,
	business_unit,
	authentications
FROM (SELECT COUNT(*) AS total FROM filtered_record) AS report 
FULL OUTER JOIN (SELECT business_unit, authentications FROM filtered_record ORDER BY rec_id ASC OFFSET $1 LIMIT $2) AS record ON FALSE
`
	rows, err := tx.Query(ctx, query, req.Offset, req.Limit, req.ApplicationID, req.BusinessUnitIDs)
	if err != nil {
		return business_unit.ListBusinessUnitsResult{}, err
	}
	defer rows.Close()

	result := business_unit.ListBusinessUnitsResult{}

	for rows.Next() {
		var total *int
		var bu *model.BusinessUnit
		var authentications []model.BusinessUnitAuthentication

		if err := rows.Scan(&total, &bu, &authentications); err != nil {
			return business_unit.ListBusinessUnitsResult{}, err
		}
		if total != nil {
			result.Total = *total
		}
		if bu != nil {
			record := business_unit.ListBusinessUnitsRecord{
				BusinessUnit:    *bu,
				Authentications: authentications,
			}
			result.Records = append(result.Records, record)
		}
	}
	if err := rows.Err(); err != nil {
		return business_unit.ListBusinessUnitsResult{}, err
	}

	return result, nil
}

func (s *_Storage) StoreAuthentication(ctx context.Context, tx storage.Tx, auth model.BusinessUnitAuthentication) error {
	query := `
WITH new_data AS (
	INSERT INTO business_unit_authentication (id, "version", business_unit_id, "status", "authentication", created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, $6)
	ON CONFLICT (id) DO UPDATE SET
		"version" = excluded."version",
		business_unit_id = excluded.business_unit_id,
		"status" = excluded."status",
		"authentication" = excluded."authentication",
		updated_at = excluded.updated_at
	RETURNING id, "version", "authentication", updated_at
)
INSERT INTO business_unit_authentication_history (id, "version", "authentication", created_at)
SELECT * FROM new_data
`
	_, err := tx.Exec(
		ctx,
		query,
		auth.ID,
		auth.Version,
		auth.BusinessUnit,
		auth.Status,
		auth,
		max(auth.CreatedAt, auth.RevokedAt),
	)
	if err != nil {
		return err
	}
	return nil
}
func (s *_Storage) ListAuthentication(ctx context.Context, tx storage.Tx, req business_unit.ListAuthenticationRequest) (business_unit.ListAuthenticationResult, error) {
	query := `
WITH filtered_record AS (
	SELECT
		ba.rec_id,
		ba.authentication
	FROM business_unit_authentication ba 
	JOIN business_unit bu ON bu.id = ba.business_unit_id
	WHERE
		($3 = '' OR bu.application_id = $3) AND
		($4 = '' OR ba.business_unit_id = $4) AND
		(COALESCE(array_length($5::TEXT[], 1), 0) = 0 OR ba.id = ANY($5))
)
SELECT
	total,
	authentication
FROM (SELECT COUNT(*) AS total FROM filtered_record) AS report
FULL OUTER JOIN (SELECT authentication FROM filtered_record ORDER BY rec_id ASC OFFSET $1 LIMIT $2) AS record ON FALSE
`

	rows, err := tx.Query(ctx, query, req.Offset, req.Limit, req.ApplicationID, req.BusinessUnitID, req.AuthenticationIDs)
	if err != nil {
		return business_unit.ListAuthenticationResult{}, err
	}
	defer rows.Close()

	result := business_unit.ListAuthenticationResult{}
	for rows.Next() {
		var total *int
		var auth *model.BusinessUnitAuthentication
		if err := rows.Scan(&total, &auth); err != nil {
			return business_unit.ListAuthenticationResult{}, err
		}
		if total != nil {
			result.Total = *total
		}
		if auth != nil {
			result.Records = append(result.Records, *auth)
		}
	}

	return result, nil
}
