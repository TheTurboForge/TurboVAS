// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{
    auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid, scan_config_write_sql::*,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanConfigWriteRecord {
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanConfigWriteState {
    pub(crate) internal_id: i32,
    pub(crate) predefined: bool,
}

pub(crate) fn require_scan_config_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("scan-config write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_scan_config_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(
        scan_config_write_operator_owner_sql(),
        &[&operator.user_uuid()],
    )
    .await
    .map_err(|error| map_scan_config_write_db_error(error, "resolve scan-config write operator"))?
    .map(|row| row.get(0))
    .ok_or_else(|| {
        tracing::warn!("direct API scan-config write operator does not resolve to a database user");
        ApiError::Forbidden
    })
}

pub(crate) async fn load_scan_config_write_state(
    tx: &Transaction<'_>,
    scan_config_id: &str,
) -> Result<ScanConfigWriteState, ApiError> {
    let scan_config_id = parse_uuid(scan_config_id)?.to_string();
    tx.query_opt(scan_config_write_state_sql(), &[&scan_config_id])
        .await
        .map_err(|error| map_scan_config_write_db_error(error, "load scan-config write state"))?
        .map(|row| ScanConfigWriteState {
            internal_id: row.get(0),
            predefined: row.get::<_, i32>(1) != 0,
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn ensure_unique_scan_config_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(scan_config_unique_name_sql(), &[&name, &except_internal_id])
        .await
        .map_err(|error| {
            map_scan_config_write_db_error(error, "check scan-config name uniqueness")
        })?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "scan config with the same name already exists".to_string(),
        ))
    }
}

pub(crate) async fn query_scan_config_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<ScanConfigWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_scan_config_write_db_error(error, action))?
        .map(|row| ScanConfigWriteRecord { uuid: row.get(0) })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn map_scan_config_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "scan-config write database operation failed");
    ApiError::Database
}
