// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    errors::ApiError,
    path_ids::parse_uuid,
    scan_config_payloads::{ScanConfigFamiliesPayload, scan_config_families_payload_from_rows},
};

pub(crate) async fn scan_config_asset_families(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
) -> Result<Json<ScanConfigFamiliesPayload>, ApiError> {
    parse_uuid(&scan_config_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(scan_config_families_sql(), &[&scan_config_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scan config family query failed");
            ApiError::Database
        })?;

    if rows.is_empty() {
        let exists = client
            .query_one(scan_config_families_exists_sql(), &[&scan_config_id])
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

pub(crate) fn scan_config_families_sql() -> &'static str {
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
         ORDER BY lower(name), name;"#
}

pub(crate) fn scan_config_families_exists_sql() -> &'static str {
    "SELECT EXISTS (SELECT 1 FROM configs WHERE uuid = $1 AND coalesce(usage_type, 'scan') = 'scan');"
}
