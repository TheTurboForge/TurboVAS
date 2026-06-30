// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{SCAN_CONFIG_ASSET_DEFAULT_SORT, SCAN_CONFIG_ASSET_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    scan_config_payloads::{
        ScanConfigAssetDetail, ScanConfigAssetItem, ScanConfigFamiliesPayload,
        ScanConfigTaskReference, scan_config_asset_from_row,
        scan_config_families_payload_from_rows, scan_config_task_reference_from_row,
    },
    user_tags::ReportUserTag,
};

pub(crate) async fn scan_config_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ScanConfigAssetItem>>, ApiError> {
    let predefined_filter = query.predefined.clone().unwrap_or_default();
    if !matches!(predefined_filter.as_str(), "" | "0" | "1") {
        return Err(ApiError::BadRequest("invalid predefined filter".into()));
    }
    let params = normalize_collection_query(query, SCAN_CONFIG_ASSET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCAN_CONFIG_ASSET_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH scan_config_rows AS (
             SELECT c.id AS internal_id,
                    c.uuid AS id,
                    coalesce(c.name, '') AS name,
                    coalesce(c.comment, '') AS comment,
                    coalesce(u.name, '') AS owner_name,
                    coalesce(c.family_count, 0)::bigint AS family_count,
                    coalesce(c.nvt_count, 0)::bigint AS nvt_count,
                    coalesce(c.families_growing, 0)::integer AS families_growing,
                    coalesce(c.nvts_growing, 0)::integer AS nvts_growing,
                    coalesce(c.predefined, 0)::integer AS predefined_int,
                    coalesce(c.usage_type, 'scan') AS usage_type,
                    CASE WHEN EXISTS (
                       SELECT 1 FROM tasks t
                        WHERE t.config = c.id
                          AND t.config_location = 0
                          AND t.hidden = 0
                    ) THEN 1 ELSE 0 END AS in_use_int,
                    CASE WHEN EXISTS (
                       SELECT 1 FROM deprecated_feed_data d
                        WHERE d.type = 'config' AND d.uuid = c.uuid
                    ) THEN 1 ELSE 0 END AS deprecated_int,
                    coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(c.modification_time, 0)::bigint AS modified_at_unix
               FROM configs c
          LEFT JOIN users u ON u.id = c.owner
              WHERE coalesce(c.usage_type, 'scan') = 'scan'
         ),
         filtered AS (
             SELECT * FROM scan_config_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(owner_name) LIKE '%' || lower($1) || '%')
                AND ($4 = ''
                     OR ($4 = '1' AND predefined_int = 1)
                     OR ($4 = '0' AND predefined_int = 0))
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &params.page_size,
                &params.offset,
                &predefined_filter,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(scan_config_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn scan_config_asset_detail(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
) -> Result<Json<ScanConfigAssetDetail>, ApiError> {
    parse_uuid(&scan_config_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT c.id AS internal_id,
                      c.uuid AS id,
                      coalesce(c.name, '') AS name,
                      coalesce(c.comment, '') AS comment,
                      coalesce(u.name, '') AS owner_name,
                      coalesce(c.family_count, 0)::bigint AS family_count,
                      coalesce(c.nvt_count, 0)::bigint AS nvt_count,
                      coalesce(c.families_growing, 0)::integer AS families_growing,
                      coalesce(c.nvts_growing, 0)::integer AS nvts_growing,
                      coalesce(c.predefined, 0)::integer AS predefined_int,
                      coalesce(c.usage_type, 'scan') AS usage_type,
                      CASE WHEN EXISTS (
                         SELECT 1 FROM tasks t
                          WHERE t.config = c.id
                            AND t.config_location = 0
                            AND t.hidden = 0
                      ) THEN 1 ELSE 0 END AS in_use_int,
                      CASE WHEN EXISTS (
                         SELECT 1 FROM deprecated_feed_data d
                          WHERE d.type = 'config' AND d.uuid = c.uuid
                      ) THEN 1 ELSE 0 END AS deprecated_int,
                      coalesce(c.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(c.modification_time, 0)::bigint AS modified_at_unix
                 FROM configs c
            LEFT JOIN users u ON u.id = c.owner
                WHERE c.uuid = $1
                  AND coalesce(c.usage_type, 'scan') = 'scan'
                LIMIT 1;"#,
            &[&scan_config_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;

    let tasks = scan_config_task_references(&client, &scan_config_id).await?;
    let user_tags = scan_config_user_tags(&client, &scan_config_id).await?;
    Ok(Json(ScanConfigAssetDetail {
        asset: scan_config_asset_from_row(&row),
        tasks,
        user_tags,
    }))
}

pub(crate) fn scan_config_task_references_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.usage_type, 'scan') AS usage_type
         FROM configs c
         JOIN tasks t ON t.config = c.id
        WHERE lower(c.uuid) = lower($1)
          AND t.config_location = 0
          AND coalesce(t.hidden, 0) = 0
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn scan_config_task_references(
    client: &tokio_postgres::Client,
    scan_config_id: &str,
) -> Result<Vec<ScanConfigTaskReference>, ApiError> {
    let rows = client
        .query(scan_config_task_references_sql(), &[&scan_config_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config task-reference query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(scan_config_task_reference_from_row)
        .collect())
}

pub(crate) fn scan_config_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN configs c ON c.id = tr.resource
        WHERE lower(c.uuid) = lower($1)
          AND tr.resource_type = 'config'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn scan_config_user_tags(
    client: &tokio_postgres::Client,
    scan_config_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(scan_config_user_tags_sql(), &[&scan_config_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config user-tag query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ReportUserTag {
            id: row.get("id"),
            name: row.get("name"),
            value: row.get("value"),
            comment: row.get("comment"),
        })
        .collect())
}

pub(crate) async fn scan_config_asset_families(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
) -> Result<Json<ScanConfigFamiliesPayload>, ApiError> {
    parse_uuid(&scan_config_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            r#"WITH config_row AS (
                    SELECT c.uuid AS scan_config_id,
                           coalesce(c.nvt_selector, '') AS nvt_selector,
                           coalesce(c.family_count, 0)::bigint AS family_count,
                           coalesce(c.families_growing, 0)::integer AS families_growing
                      FROM configs c
                     WHERE c.uuid = $1
                       AND coalesce(c.usage_type, 'scan') = 'scan'
                     LIMIT 1
                ),
                all_mode_families AS (
                    SELECT DISTINCT n.family
                      FROM nvts n
                      JOIN config_row c ON c.families_growing <> 0
                     WHERE n.family != 'Credentials'
                    EXCEPT
                    SELECT DISTINCT ns.family
                      FROM nvt_selectors ns
                      JOIN config_row c ON c.families_growing <> 0
                     WHERE ns.name = c.nvt_selector
                       AND ns.type = 1
                       AND ns.exclude = 1
                    UNION
                    SELECT DISTINCT ns.family
                      FROM nvt_selectors ns
                      JOIN config_row c ON c.families_growing <> 0
                     WHERE ns.name = c.nvt_selector
                       AND ns.type = 2
                       AND ns.exclude = 0
                ),
                static_mode_families AS (
                    SELECT DISTINCT ns.family
                      FROM nvt_selectors ns
                      JOIN config_row c ON c.families_growing = 0
                     WHERE ns.name = c.nvt_selector
                       AND ns.type IN (1, 2)
                       AND ns.family != 'Credentials'
                ),
                family_rows AS (
                    SELECT family FROM all_mode_families
                    UNION
                    SELECT family FROM static_mode_families
                ),
                family_state AS (
                    SELECT c.scan_config_id,
                           c.family_count,
                           c.families_growing,
                           f.family AS name,
                           CASE
                             WHEN c.families_growing <> 0 THEN
                               CASE WHEN EXISTS (
                                      SELECT 1 FROM nvt_selectors ns
                                       WHERE ns.name = c.nvt_selector
                                         AND ns.type = 1
                                         AND ns.family_or_nvt = f.family
                                         AND ns.exclude = 1
                                    ) THEN 0 ELSE 1 END
                             ELSE
                               CASE WHEN EXISTS (
                                      SELECT 1 FROM nvt_selectors ns
                                       WHERE ns.name = c.nvt_selector
                                         AND ns.type = 1
                                         AND ns.family_or_nvt = f.family
                                         AND ns.exclude = 0
                                    ) THEN 1 ELSE 0 END
                           END AS growing,
                           (SELECT count(*)::bigint
                              FROM nvts n
                             WHERE n.family = f.family) AS max_nvt_count
                      FROM config_row c
                      JOIN family_rows f ON f.family IS NOT NULL AND f.family != ''
                )
                SELECT scan_config_id,
                       family_count,
                       families_growing,
                       name,
                       growing::integer AS growing,
                       CASE
                         WHEN growing <> 0 THEN
                           max_nvt_count -
                           (SELECT count(*)::bigint
                              FROM nvt_selectors ns
                              JOIN config_row c ON true
                             WHERE ns.name = c.nvt_selector
                               AND ns.exclude = 1
                               AND ns.type = 2
                               AND ns.family = family_state.name)
                         ELSE
                           (SELECT count(*)::bigint
                              FROM nvt_selectors ns
                              JOIN config_row c ON true
                             WHERE ns.name = c.nvt_selector
                               AND ns.exclude = 0
                               AND ns.type = 2
                               AND ns.family = family_state.name)
                       END AS nvt_count,
                       max_nvt_count
                  FROM family_state
                 ORDER BY lower(name), name;"#,
            &[&scan_config_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config family query failed");
            ApiError::Database
        })?;

    if rows.is_empty() {
        let exists = client
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM configs WHERE uuid = $1 AND coalesce(usage_type, 'scan') = 'scan');",
                &[&scan_config_id],
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "scan config family existence query failed");
                ApiError::Database
            })?
            .get::<_, bool>(0);
        if !exists {
            return Err(ApiError::NotFound);
        }
    }

    Ok(Json(scan_config_families_payload_from_rows(
        scan_config_id,
        &rows,
    )))
}
