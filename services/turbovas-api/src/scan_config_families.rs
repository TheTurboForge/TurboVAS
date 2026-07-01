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
    scan_config_query_sql::{scan_config_families_exists_sql, scan_config_families_sql},
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
