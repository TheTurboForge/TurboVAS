// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};
use tokio_postgres::Client;

use crate::{
    app_state::AppState,
    collections::{REPORT_CONFIG_DEFAULT_SORT, REPORT_CONFIG_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
    report_config_payloads::{ReportConfigAssetItem, report_config_asset_from_row},
    report_config_query_sql::{report_config_asset_detail_sql, report_config_assets_sql},
};

pub(crate) async fn report_config_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ReportConfigAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, REPORT_CONFIG_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_CONFIG_SORT_FIELDS)?;
    let sql = report_config_assets_sql(&sort_sql);
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report config asset list query failed");
            ApiError::Database
        })?;
    let total = collection_total_with_empty_page_probe(
        &client,
        &rows,
        &sql,
        &params,
        "report config asset list",
    )
    .await?;
    let mut items = Vec::new();
    for row in &rows {
        items.push(report_config_asset_from_row(&client, row).await?);
    }
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn report_config_asset_detail(
    State(state): State<AppState>,
    Path(report_config_id): Path<String>,
) -> Result<Json<ReportConfigAssetItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_report_config_asset_detail(&client, &report_config_id).await?,
    ))
}

pub(crate) async fn export_report_config_metadata(
    State(state): State<AppState>,
    Path(report_config_id): Path<String>,
) -> Result<Json<ReportConfigAssetItem>, ApiError> {
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    Ok(Json(
        load_report_config_asset_detail(&client, &report_config_id).await?,
    ))
}

pub(crate) async fn load_report_config_asset_detail(
    client: &Client,
    report_config_id: &str,
) -> Result<ReportConfigAssetItem, ApiError> {
    parse_uuid(&report_config_id)?;
    let row = client
        .query_opt(report_config_asset_detail_sql(), &[&report_config_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report config asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;

    report_config_asset_from_row(client, &row).await
}
