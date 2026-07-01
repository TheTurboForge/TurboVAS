// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
};
use tokio_postgres::Transaction;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    scan_config_payloads::ScanConfigAssetDetail,
    scan_config_write_db::*,
    scan_config_write_sql::*,
    scan_config_write_validation::{
        ScanConfigPatchRequest, ValidatedScanConfigPatch, validate_scan_config_patch_request,
    },
    scan_configs::load_scan_config_asset_detail,
};

pub(crate) async fn patch_scan_config(
    State(state): State<AppState>,
    Path(scan_config_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ScanConfigPatchRequest>,
) -> Result<Json<ScanConfigAssetDetail>, ApiError> {
    let operator = require_scan_config_write_operator(operator)?;
    let request = validate_scan_config_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_scan_config_write_db_error(error, "begin patch scan-config transaction")
    })?;
    resolve_scan_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE configs, configs_trash IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| {
            map_scan_config_write_db_error(error, "lock scan-config tables for patch")
        })?;
    let config_state = load_scan_config_write_state(&tx, &scan_config_id).await?;
    if config_state.predefined {
        return Err(ApiError::Conflict(
            "predefined scan configs cannot be patched".to_string(),
        ));
    }
    if let Some(name) = request.name.as_ref() {
        ensure_unique_scan_config_name(&tx, name, config_state.internal_id).await?;
    }
    let record =
        execute_scan_config_patch_transaction(&tx, config_state.internal_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_scan_config_write_db_error(error, "commit patch scan-config transaction")
    })?;
    Ok(Json(
        load_scan_config_asset_detail(&client, &record.uuid).await?,
    ))
}

pub(crate) async fn execute_scan_config_patch_transaction(
    tx: &Transaction<'_>,
    scan_config_internal_id: i32,
    request: &ValidatedScanConfigPatch,
) -> Result<ScanConfigWriteRecord, ApiError> {
    query_scan_config_write_record(
        tx,
        scan_config_update_metadata_sql(),
        &[&scan_config_internal_id, &request.name, &request.comment],
        "update scan-config metadata",
    )
    .await
}
