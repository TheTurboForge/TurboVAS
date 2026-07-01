// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::{Row, Transaction, types::ToSql};

use crate::{
    errors::ApiError,
    report_config_write_sql::*,
    report_config_write_validation::{
        ValidatedReportConfigClone, ValidatedReportConfigCreate, ValidatedReportConfigParamWrite,
        ValidatedReportConfigPatch,
    },
};

use super::{checks::ReportConfigWriteRecord, map_report_config_write_db_error};

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
