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
    target_write_sql::*,
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

pub(crate) async fn delete_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_target_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_target_write_db_error(error, "begin delete target transaction"))?;
    let owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE targets, targets_trash, targets_login_data, targets_trash_login_data, tasks, scope_targets, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_target_write_db_error(error, "lock target tables for delete"))?;
    let state = load_target_write_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(state.owner_id, owner_id)?;
    ensure_target_not_in_use_for_delete(&tx, state.internal_id).await?;
    ensure_target_not_in_scope(&tx, state.internal_id).await?;
    execute_target_trash_transaction(&tx, state.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_target_write_db_error(error, "commit delete target transaction"))?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn hard_delete_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<StatusCode, ApiError> {
    let operator = require_target_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_target_write_db_error(error, "begin hard-delete target transaction")
    })?;
    let owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE targets_trash, targets_trash_login_data, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_target_write_db_error(error, "lock target trash tables for hard delete"))?;
    let trash = load_target_trash_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(trash.owner_id, owner_id)?;
    ensure_trash_target_not_in_use(&tx, trash.internal_id).await?;
    execute_target_hard_delete_transaction(&tx, trash.internal_id).await?;
    tx.commit().await.map_err(|error| {
        map_target_write_db_error(error, "commit hard-delete target transaction")
    })?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn restore_target(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<Json<TargetItem>, ApiError> {
    let operator = require_target_write_operator(operator)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client
        .transaction()
        .await
        .map_err(|error| map_target_write_db_error(error, "begin restore target transaction"))?;
    let owner_id = resolve_target_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute(
        "LOCK TABLE targets, targets_trash, targets_login_data, targets_trash_login_data, tasks, tag_resources, tag_resources_trash IN SHARE ROW EXCLUSIVE MODE;",
    )
    .await
    .map_err(|error| map_target_write_db_error(error, "lock target tables for restore"))?;
    let trash = load_target_trash_state(&tx, &target_id).await?;
    ensure_target_owner_matches_operator(trash.owner_id, owner_id)?;
    ensure_unique_live_target_name_for_owner(&tx, &trash.name, trash.owner_id).await?;
    ensure_target_uuid_not_live(&tx, &trash.uuid).await?;
    ensure_trash_target_references_live_resources(&tx, trash.internal_id).await?;
    let record = execute_target_restore_transaction(&tx, trash.internal_id).await?;
    tx.commit()
        .await
        .map_err(|error| map_target_write_db_error(error, "commit restore target transaction"))?;

    Ok(Json(load_target_detail(&client, &record.uuid).await?))
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

pub(crate) async fn execute_target_trash_transaction(
    tx: &Transaction<'_>,
    target_internal_id: i32,
) -> Result<TargetWriteRecordWithInternalId, ApiError> {
    let record = query_target_write_record_with_internal_id(
        tx,
        target_trash_insert_sql(),
        &[&target_internal_id],
        "move target metadata to trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_trash_login_data_insert_sql(),
        &[&record.internal_id, &target_internal_id],
        "move target credential references to trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_trash_task_relink_sql(),
        &[&record.internal_id, &target_internal_id],
        "relink trash tasks to trashed target",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_tag_locations_to_trash_sql(),
        &[&record.internal_id, &target_internal_id],
        "move target tag links to trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_trash_tag_locations_to_trash_sql(),
        &[&record.internal_id, &target_internal_id],
        "move trashed tag links to target trash id",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_login_data_sql(),
        &[&target_internal_id],
        "delete live target credential references after trash move",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_metadata_sql(),
        &[&target_internal_id],
        "delete live target after trash move",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_target_restore_transaction(
    tx: &Transaction<'_>,
    trash_target_internal_id: i32,
) -> Result<TargetWriteRecordWithInternalId, ApiError> {
    let record = query_target_write_record_with_internal_id(
        tx,
        target_restore_metadata_sql(),
        &[&trash_target_internal_id],
        "restore target metadata from trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_restore_login_data_sql(),
        &[&trash_target_internal_id, &record.internal_id],
        "restore target credential references from trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_restore_task_relink_sql(),
        &[&trash_target_internal_id, &record.internal_id],
        "relink trash tasks to restored target",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_tag_locations_to_live_sql(),
        &[&trash_target_internal_id, &record.internal_id],
        "restore target tag links from trash",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_trash_tag_locations_to_live_sql(),
        &[&trash_target_internal_id, &record.internal_id],
        "restore trashed tag links from target trash id",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_trash_login_data_sql(),
        &[&trash_target_internal_id],
        "delete target trash credential references after restore",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_trash_metadata_sql(),
        &[&trash_target_internal_id],
        "delete target trash metadata after restore",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_target_hard_delete_transaction(
    tx: &Transaction<'_>,
    trash_target_internal_id: i32,
) -> Result<(), ApiError> {
    execute_target_write_sql(
        tx,
        target_trash_tag_delete_sql(),
        &[&trash_target_internal_id],
        "delete target trash tag links",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_trash_tag_trash_delete_sql(),
        &[&trash_target_internal_id],
        "delete trashed tag links to target trash id",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_trash_login_data_sql(),
        &[&trash_target_internal_id],
        "delete target trash credential references for hard delete",
    )
    .await?;
    execute_target_write_sql(
        tx,
        target_delete_trash_metadata_sql(),
        &[&trash_target_internal_id],
        "delete target trash metadata for hard delete",
    )
    .await?;
    Ok(())
}

fn target_write_location_headers(target_id: &str) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let value = HeaderValue::from_str(&format!("/api/v1/targets/{target_id}"))
        .map_err(|_| ApiError::Database)?;
    headers.insert(header::LOCATION, value);
    Ok(headers)
}
