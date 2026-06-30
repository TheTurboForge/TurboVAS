// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use std::collections::{BTreeMap, BTreeSet};
use tokio_postgres::{Row, Transaction, types::ToSql};

use crate::{
    auth::DirectApiOperator,
    errors::ApiError,
    path_ids::parse_uuid,
    report_config_write_sql::*,
    report_config_write_validation::{
        ReportConfigFormatParam, ReportConfigFormatState, ValidatedReportConfigClone,
        ValidatedReportConfigCreate, ValidatedReportConfigParamWrite, ValidatedReportConfigPatch,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportConfigWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportConfigWriteState {
    pub(crate) internal_id: i32,
    pub(crate) report_format_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportConfigTrashState {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
    pub(crate) name: String,
    pub(crate) owner_id: i32,
}

pub(crate) fn require_report_config_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("report config write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_report_config_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(
        report_config_write_operator_owner_sql(),
        &[&operator.user_uuid()],
    )
    .await
    .map_err(|error| {
        map_report_config_write_db_error(error, "resolve report config write operator")
    })?
    .map(|row| row.get(0))
    .ok_or_else(|| {
        tracing::warn!(
            "direct API report config write operator does not resolve to a database user"
        );
        ApiError::Forbidden
    })
}

pub(crate) async fn ensure_unique_live_report_config_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: Option<i32>,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            report_config_unique_live_name_sql(),
            &[&name, &except_internal_id],
        )
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "check report config name uniqueness")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "report config with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_unique_live_report_config_name_for_owner(
    tx: &Transaction<'_>,
    name: &str,
    owner_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            report_config_unique_live_owner_name_sql(),
            &[&name, &owner_id],
        )
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "check report config restore name conflict")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "report config with the same owner and name already exists".to_string(),
        ))
    }
}

pub(crate) async fn ensure_report_config_uuid_not_live(
    tx: &Transaction<'_>,
    report_config_id: &str,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(report_config_live_uuid_conflict_sql(), &[&report_config_id])
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "check report config restore UUID conflict")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "live report config with the same id already exists".to_string(),
        ))
    }
}

pub(crate) async fn load_report_config_format_state(
    tx: &Transaction<'_>,
    report_format_id: &str,
) -> Result<ReportConfigFormatState, ApiError> {
    let report_format = tx
        .query_opt(report_config_format_state_sql(), &[&report_format_id])
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "load report format for report config create")
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = report_format.get(0);
    let param_rows = tx
        .query(report_config_format_params_sql(), &[&internal_id])
        .await
        .map_err(|error| map_report_config_write_db_error(error, "load report format params"))?;
    if param_rows.is_empty() {
        return Err(ApiError::Conflict(
            "report format is not configurable".to_string(),
        ));
    }

    let param_ids = param_rows
        .iter()
        .map(|row| row.get::<_, i32>("internal_id"))
        .collect::<Vec<_>>();
    let option_rows = tx
        .query(report_config_format_param_options_sql(), &[&param_ids])
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "load report format param options")
        })?;
    let mut options_by_param = BTreeMap::<i32, BTreeSet<String>>::new();
    for row in option_rows {
        options_by_param
            .entry(row.get("report_format_param"))
            .or_default()
            .insert(row.get("value"));
    }

    let params = param_rows
        .into_iter()
        .map(|row| {
            let param = report_config_format_param_from_row(&row, &options_by_param);
            (row.get("name"), param)
        })
        .collect();
    Ok(ReportConfigFormatState { params })
}

pub(crate) async fn load_report_config_trash_state(
    tx: &Transaction<'_>,
    report_config_id: &str,
) -> Result<ReportConfigTrashState, ApiError> {
    let report_config_id = parse_uuid(report_config_id)?.to_string();
    tx.query_opt(report_config_trash_state_sql(), &[&report_config_id])
        .await
        .map_err(|error| map_report_config_write_db_error(error, "load report config trash state"))?
        .map(|row| ReportConfigTrashState {
            internal_id: row.get(0),
            uuid: row.get(1),
            name: row.get(2),
            owner_id: row.get(3),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn load_report_config_write_state(
    tx: &Transaction<'_>,
    report_config_id: &str,
) -> Result<ReportConfigWriteState, ApiError> {
    let report_config_id = parse_uuid(report_config_id)?.to_string();
    tx.query_opt(report_config_write_state_sql(), &[&report_config_id])
        .await
        .map_err(|error| map_report_config_write_db_error(error, "load report config write state"))?
        .map(|row| ReportConfigWriteState {
            internal_id: row.get(0),
            report_format_id: row.get(2),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn ensure_report_config_not_in_use_by_alerts(
    tx: &Transaction<'_>,
    _report_config_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(report_config_in_use_by_alerts_sql(), &[])
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "check report config alert usage")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "report config is still referenced by an alert".to_string(),
        ))
    }
}

pub(crate) async fn ensure_trash_report_config_not_in_use_by_alerts(
    tx: &Transaction<'_>,
    _report_config_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(report_config_trash_in_use_by_alerts_sql(), &[])
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "check trash report config alert usage")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "trash report config is still referenced by an alert".to_string(),
        ))
    }
}

pub(crate) async fn execute_report_config_create_transaction(
    tx: &Transaction<'_>,
    owner_id: i32,
    request: &ValidatedReportConfigCreate,
) -> Result<ReportConfigWriteRecord, ApiError> {
    let comment = request.comment.as_deref().unwrap_or("");
    let record = query_report_config_write_record(
        tx,
        report_config_insert_sql(),
        &[
            &request.name,
            &comment,
            &request.report_format_id,
            &owner_id,
        ],
        "insert report config",
    )
    .await?;
    replace_report_config_params(tx, record.internal_id, &request.params).await?;
    Ok(record)
}

pub(crate) async fn execute_report_config_restore_transaction(
    tx: &Transaction<'_>,
    trash_report_config_internal_id: i32,
) -> Result<ReportConfigWriteRecord, ApiError> {
    let record = query_report_config_write_record(
        tx,
        report_config_restore_metadata_sql(),
        &[&trash_report_config_internal_id],
        "restore report config metadata from trash",
    )
    .await?;
    execute_report_config_write_sql(
        tx,
        report_config_restore_params_sql(),
        &[&trash_report_config_internal_id, &record.internal_id],
        "restore report config params from trash",
    )
    .await?;
    execute_report_config_write_sql(
        tx,
        report_config_tag_locations_to_live_sql(),
        &[&trash_report_config_internal_id, &record.internal_id],
        "restore report config tag links from trash",
    )
    .await?;
    execute_report_config_write_sql(
        tx,
        report_config_delete_trash_params_sql(),
        &[&trash_report_config_internal_id],
        "delete report config trash params after restore",
    )
    .await?;
    execute_report_config_write_sql(
        tx,
        report_config_delete_trash_metadata_sql(),
        &[&trash_report_config_internal_id],
        "delete report config trash metadata after restore",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_report_config_trash_transaction(
    tx: &Transaction<'_>,
    report_config_internal_id: i32,
) -> Result<ReportConfigWriteRecord, ApiError> {
    let record = query_report_config_write_record(
        tx,
        report_config_trash_insert_sql(),
        &[&report_config_internal_id],
        "move report config metadata to trash",
    )
    .await?;
    execute_report_config_write_sql(
        tx,
        report_config_trash_params_insert_sql(),
        &[&record.internal_id, &report_config_internal_id],
        "move report config params to trash",
    )
    .await?;
    execute_report_config_write_sql(
        tx,
        report_config_tag_locations_to_trash_sql(),
        &[&record.internal_id, &report_config_internal_id],
        "move report config tag links to trash",
    )
    .await?;
    execute_report_config_write_sql(
        tx,
        report_config_delete_params_sql(),
        &[&report_config_internal_id],
        "delete live report config params after trash move",
    )
    .await?;
    execute_report_config_write_sql(
        tx,
        report_config_delete_metadata_sql(),
        &[&report_config_internal_id],
        "delete live report config after trash move",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_report_config_hard_delete_transaction(
    tx: &Transaction<'_>,
    trash_report_config_internal_id: i32,
) -> Result<(), ApiError> {
    execute_report_config_write_sql(
        tx,
        report_config_trash_tag_delete_sql(),
        &[&trash_report_config_internal_id],
        "delete report config trash tag links",
    )
    .await?;
    execute_report_config_write_sql(
        tx,
        report_config_delete_trash_params_sql(),
        &[&trash_report_config_internal_id],
        "delete report config trash params",
    )
    .await?;
    execute_report_config_write_sql(
        tx,
        report_config_delete_trash_metadata_sql(),
        &[&trash_report_config_internal_id],
        "delete report config trash metadata",
    )
    .await?;
    Ok(())
}

pub(crate) async fn execute_report_config_clone_transaction(
    tx: &Transaction<'_>,
    source_report_config_internal_id: i32,
    owner_id: i32,
    request: &ValidatedReportConfigClone,
) -> Result<ReportConfigWriteRecord, ApiError> {
    let record = query_report_config_write_record(
        tx,
        report_config_clone_sql(),
        &[&source_report_config_internal_id, &owner_id, &request.name],
        "clone report config metadata",
    )
    .await?;
    execute_report_config_write_sql(
        tx,
        report_config_clone_params_sql(),
        &[&source_report_config_internal_id, &record.internal_id],
        "clone report config params",
    )
    .await?;
    execute_report_config_write_sql(
        tx,
        report_config_clone_tags_sql(),
        &[
            &source_report_config_internal_id,
            &record.internal_id,
            &record.uuid,
        ],
        "clone report config tags",
    )
    .await?;
    Ok(record)
}

pub(crate) async fn execute_report_config_patch_transaction(
    tx: &Transaction<'_>,
    report_config_internal_id: i32,
    request: &ValidatedReportConfigPatch,
) -> Result<ReportConfigWriteRecord, ApiError> {
    let mut record = if request.name.is_some() || request.comment.is_some() {
        query_report_config_write_record(
            tx,
            report_config_update_metadata_sql(),
            &[&report_config_internal_id, &request.name, &request.comment],
            "update report config metadata",
        )
        .await?
    } else {
        query_report_config_write_record(
            tx,
            report_config_by_internal_id_sql(),
            &[&report_config_internal_id],
            "load report config after params-only patch",
        )
        .await?
    };

    if let Some(params) = request.params.as_ref() {
        replace_report_config_params(tx, record.internal_id, params).await?;
        record = query_report_config_write_record(
            tx,
            report_config_touch_sql(),
            &[&record.internal_id],
            "touch report config after params patch",
        )
        .await?;
    }
    Ok(record)
}

fn report_config_format_param_from_row(
    row: &Row,
    options_by_param: &BTreeMap<i32, BTreeSet<String>>,
) -> ReportConfigFormatParam {
    let internal_id = row.get("internal_id");
    ReportConfigFormatParam {
        param_type: row.get("param_type"),
        min: row.get::<_, Option<i64>>("type_min").unwrap_or(0),
        max: row.get::<_, Option<i64>>("type_max").unwrap_or(0),
        options: options_by_param
            .get(&internal_id)
            .cloned()
            .unwrap_or_default(),
    }
}

async fn replace_report_config_params(
    tx: &Transaction<'_>,
    report_config_internal_id: i32,
    params: &[ValidatedReportConfigParamWrite],
) -> Result<(), ApiError> {
    execute_report_config_write_sql(
        tx,
        report_config_delete_params_sql(),
        &[&report_config_internal_id],
        "delete report config params",
    )
    .await?;
    for param in params {
        execute_report_config_write_sql(
            tx,
            report_config_insert_param_sql(),
            &[&report_config_internal_id, &param.name, &param.value],
            "insert report config param",
        )
        .await?;
    }
    Ok(())
}

async fn query_report_config_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<ReportConfigWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_report_config_write_db_error(error, action))?
        .map(|row| report_config_write_record_from_row(&row))
        .ok_or(ApiError::NotFound)
}

async fn execute_report_config_write_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<u64, ApiError> {
    tx.execute(sql, params)
        .await
        .map_err(|error| map_report_config_write_db_error(error, action))
}

fn report_config_write_record_from_row(row: &Row) -> ReportConfigWriteRecord {
    ReportConfigWriteRecord {
        internal_id: row.get(0),
        uuid: row.get(1),
    }
}

pub(crate) fn map_report_config_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "report config write database operation failed");
    ApiError::Database
}
