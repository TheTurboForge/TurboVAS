// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::extract::Extension;
use tokio_postgres::{Transaction, types::ToSql};

use crate::{auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid, task_write_sql::*};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskWriteRecord {
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskWriteState {
    pub(crate) internal_id: i32,
    pub(crate) owner_id: i32,
}

pub(crate) fn require_task_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("task write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) async fn resolve_task_write_operator_owner(
    tx: &Transaction<'_>,
    operator: &DirectApiOperator,
) -> Result<i32, ApiError> {
    tx.query_opt(task_write_operator_owner_sql(), &[&operator.user_uuid()])
        .await
        .map_err(|error| map_task_write_db_error(error, "resolve task write operator"))?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            tracing::warn!("direct API task write operator does not resolve to a database user");
            ApiError::Forbidden
        })
}

pub(crate) async fn load_task_write_state(
    tx: &Transaction<'_>,
    task_id: &str,
) -> Result<TaskWriteState, ApiError> {
    let task_id = parse_uuid(task_id)?.to_string();
    tx.query_opt(task_write_state_sql(), &[&task_id])
        .await
        .map_err(|error| map_task_write_db_error(error, "load task write state"))?
        .map(|row| TaskWriteState {
            internal_id: row.get(0),
            owner_id: row.get(1),
        })
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn ensure_unique_task_name(
    tx: &Transaction<'_>,
    name: &str,
    except_internal_id: i32,
    owner_id: i32,
) -> Result<(), ApiError> {
    let count: i64 = tx
        .query_one(
            task_unique_name_sql(),
            &[&name, &except_internal_id, &owner_id],
        )
        .await
        .map_err(|error| map_task_write_db_error(error, "check task name uniqueness"))?
        .get(0);
    if count == 0 {
        Ok(())
    } else {
        Err(ApiError::Conflict(
            "task with the same name already exists".to_string(),
        ))
    }
}

pub(crate) fn ensure_task_owner_matches_operator(
    task_owner_id: i32,
    operator_owner_id: i32,
) -> Result<(), ApiError> {
    if task_owner_id == operator_owner_id {
        Ok(())
    } else {
        tracing::warn!("direct API task write operator does not own task");
        Err(ApiError::Forbidden)
    }
}

pub(crate) async fn query_task_write_record(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    action: &'static str,
) -> Result<TaskWriteRecord, ApiError> {
    tx.query_opt(sql, params)
        .await
        .map_err(|error| map_task_write_db_error(error, action))?
        .map(|row| TaskWriteRecord { uuid: row.get(0) })
        .ok_or(ApiError::NotFound)
}

pub(crate) fn map_task_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "task write database operation failed");
    ApiError::Database
}
