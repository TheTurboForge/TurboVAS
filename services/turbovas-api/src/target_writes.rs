// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
};
use tokio_postgres::Transaction;

use crate::{
    app_state::AppState,
    auth::DirectApiOperator,
    errors::ApiError,
    target_handlers::load_target_detail,
    target_write_db::*,
    target_write_sql::{
        target_clone_login_data_sql, target_clone_metadata_sql, target_clone_tags_sql,
        target_update_metadata_sql,
    },
    target_write_validation::{
        TargetCloneRequest, TargetPatchRequest, ValidatedTargetClone, ValidatedTargetPatch,
        validate_target_clone_request, validate_target_patch_request,
    },
    task_target_payloads::TargetItem,
};

pub(crate) async fn clone_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TargetCloneRequest>,
) -> Result<(StatusCode, HeaderMap, Json<TargetItem>), ApiError> {
    let operator = require_target_write_operator(operator)?;
    let request = validate_target_clone_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_target_write_db_error(error, "begin clone target transaction"))?;
    let owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE targets, targets_login_data, port_lists, credentials, tag_resources IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_target_write_db_error(error, "lock target tables for clone"))?;
    let source = load_target_write_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(source.owner_id, owner_id)?;
    ensure_target_source_port_list_assignable(&tx, source.internal_id, owner_id).await?;
    ensure_target_source_credentials_assignable(&tx, source.internal_id, owner_id).await?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_target_name(&tx, name, -1, owner_id).await?;
    }
    let record =
        execute_target_clone_transaction(&tx, source.internal_id, owner_id, &request).await?;
    tx.commit()
        .await
        .map_err(|error| map_target_write_db_error(error, "commit clone target transaction"))?;

    Ok((
        StatusCode::CREATED,
        target_write_location_headers(&record.uuid)?,
        Json(load_target_detail(&client, &record.uuid).await?),
    ))
}

pub(crate) async fn patch_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<TargetPatchRequest>,
) -> Result<Json<TargetItem>, ApiError> {
    let operator = require_target_write_operator(operator)?;
    let request = validate_target_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_target_write_db_error(error, "begin patch target transaction"))?;
    let operator_owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE targets, port_lists IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| map_target_write_db_error(error, "lock targets for patch"))?;
    let target_state = load_target_write_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(target_state.owner_id, operator_owner_id)?;
    if let Some(name) = request.name.as_ref() {
        ensure_unique_target_name(&tx, name, target_state.internal_id, target_state.owner_id)
            .await?;
    }
    let port_list_internal_id = if let Some(port_list_id) = request.port_list_id.as_ref() {
        Some(
            load_assignable_target_port_list(&tx, port_list_id, operator_owner_id)
                .await?
                .internal_id,
        )
    } else {
        None
    };
    if request.changes_task_in_use_guarded_scan_inputs() {
        ensure_target_not_in_use_for_scan_inputs(&tx, target_state.internal_id).await?;
    }
    let record = execute_target_patch_transaction(
        &tx,
        target_state.internal_id,
        &request,
        &port_list_internal_id,
    )
    .await?;
    tx.commit()
        .await
        .map_err(|error| map_target_write_db_error(error, "commit patch target transaction"))?;

    Ok(Json(load_target_detail(&client, &record.uuid).await?))
}

pub(crate) async fn execute_target_patch_transaction(
    tx: &Transaction<'_>,
    target_internal_id: i32,
    request: &ValidatedTargetPatch,
    port_list_internal_id: &Option<i32>,
) -> Result<TargetWriteRecord, ApiError> {
    query_target_write_record(
        tx,
        target_update_metadata_sql(),
        &[
            &target_internal_id,
            &request.name,
            &request.comment,
            &request.alive_test,
            &request.allow_simultaneous_ips,
            &request.reverse_lookup_only,
            &request.reverse_lookup_unify,
            port_list_internal_id,
            &request.hosts,
            &request.exclude_hosts,
        ],
        "update target metadata",
    )
    .await
}

pub(crate) async fn execute_target_clone_transaction(
    tx: &Transaction<'_>,
    source_internal_id: i32,
    owner_id: i32,
    request: &ValidatedTargetClone,
) -> Result<TargetWriteRecord, ApiError> {
    let record = query_target_write_record_with_internal_id(
        tx,
        target_clone_metadata_sql(),
        &[
            &source_internal_id,
            &owner_id,
            &request.name,
            &request.comment,
        ],
        "clone target metadata",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_clone_login_data_sql(),
        &[&source_internal_id, &record.internal_id],
        "clone target credential references",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_clone_tags_sql(),
        &[&source_internal_id, &record.internal_id, &record.uuid],
        "clone target tag links",
    )
    .await?;
    Ok(TargetWriteRecord { uuid: record.uuid })
}

fn target_write_location_headers(target_id: &str) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let value = HeaderValue::from_str(&format!("/api/v1/targets/{target_id}"))
        .map_err(|_| ApiError::Database)?;
    headers.insert(header::LOCATION, value);
    Ok(headers)
}
