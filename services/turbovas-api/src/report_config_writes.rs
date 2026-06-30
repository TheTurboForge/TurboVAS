// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use tokio_postgres::{Row, Transaction, types::ToSql};

use crate::{
    app_state::AppState, auth::DirectApiOperator, errors::ApiError, path_ids::parse_uuid,
    report_config_payloads::ReportConfigAssetItem, report_configs::load_report_config_asset_detail,
};

const MAX_REPORT_CONFIG_TEXT_BYTES: usize = 4096;
const MAX_REPORT_CONFIG_PARAM_VALUE_BYTES: usize = 65_536;
const MAX_REPORT_CONFIG_PARAMS: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReportConfigParamWriteRequest {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReportConfigCreateRequest {
    name: String,
    report_format_id: String,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    params: Vec<ReportConfigParamWriteRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReportConfigPatchRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    params: Option<Vec<ReportConfigParamWriteRequest>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedReportConfigParamWrite {
    pub(crate) name: String,
    pub(crate) value: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedReportConfigCreate {
    pub(crate) name: String,
    pub(crate) comment: Option<String>,
    pub(crate) report_format_id: String,
    pub(crate) params: Vec<ValidatedReportConfigParamWrite>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedReportConfigPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
    pub(crate) params: Option<Vec<ValidatedReportConfigParamWrite>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportConfigWriteRecord {
    pub(crate) internal_id: i32,
    pub(crate) uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportConfigWriteState {
    internal_id: i32,
    uuid: String,
    report_format_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportConfigFormatState {
    params: BTreeMap<String, ReportConfigFormatParam>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportConfigFormatParam {
    param_type: i32,
    min: i64,
    max: i64,
    options: BTreeSet<String>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportConfigWriteOperation {
    Create,
    Patch,
    Delete,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReportConfigWriteStep {
    ResolveOperatorOwner,
    VerifyReportFormatVisible,
    VerifyReportFormatParams,
    VerifyUniqueLiveName,
    VerifyExistingReportConfigMutable,
    InsertReportConfig,
    UpdateReportConfigMetadata,
    ReplaceReportConfigParams,
    MoveReportConfigToTrash,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ReportConfigWriteTransactionPlan {
    pub(crate) operation: ReportConfigWriteOperation,
    pub(crate) steps: Vec<ReportConfigWriteStep>,
}

pub(crate) async fn create_report_config(
    State(state): State<AppState>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ReportConfigCreateRequest>,
) -> Result<(StatusCode, HeaderMap, Json<ReportConfigAssetItem>), ApiError> {
    let operator = require_report_config_write_operator(operator)?;
    let request = validate_report_config_create_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_report_config_write_db_error(error, "begin create report config transaction")
    })?;
    let owner_id = resolve_report_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE report_configs IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "lock report configs for create")
        })?;
    ensure_unique_live_report_config_name(&tx, &request.name, None).await?;
    let format = load_report_config_format_state(&tx, &request.report_format_id).await?;
    validate_report_config_param_values(&request.params, &format)?;
    let record = execute_report_config_create_transaction(&tx, owner_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_report_config_write_db_error(error, "commit create report config transaction")
    })?;

    let report_config = load_report_config_asset_detail(&client, &record.uuid).await?;
    Ok((
        StatusCode::CREATED,
        report_config_write_location_headers(&record.uuid)?,
        Json(report_config),
    ))
}

pub(crate) async fn patch_report_config(
    State(state): State<AppState>,
    Path(report_config_id): Path<String>,
    operator: Option<Extension<DirectApiOperator>>,
    Json(request): Json<ReportConfigPatchRequest>,
) -> Result<Json<ReportConfigAssetItem>, ApiError> {
    let operator = require_report_config_write_operator(operator)?;
    let request = validate_report_config_patch_request(request)?;
    let mut client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tx = client.transaction().await.map_err(|error| {
        map_report_config_write_db_error(error, "begin patch report config transaction")
    })?;
    resolve_report_config_write_operator_owner(&tx, &operator).await?;
    tx.batch_execute("LOCK TABLE report_configs IN SHARE ROW EXCLUSIVE MODE;")
        .await
        .map_err(|error| {
            map_report_config_write_db_error(error, "lock report configs for patch")
        })?;
    let state = load_report_config_write_state(&tx, &report_config_id).await?;
    if let Some(params) = request.params.as_ref() {
        let format = load_report_config_format_state(&tx, &state.report_format_id).await?;
        validate_report_config_param_values(params, &format)?;
    }
    if let Some(name) = request.name.as_ref() {
        ensure_unique_live_report_config_name(&tx, name, Some(state.internal_id)).await?;
    }
    let record = execute_report_config_patch_transaction(&tx, state.internal_id, &request).await?;
    tx.commit().await.map_err(|error| {
        map_report_config_write_db_error(error, "commit patch report config transaction")
    })?;

    Ok(Json(
        load_report_config_asset_detail(&client, &record.uuid).await?,
    ))
}

fn require_report_config_write_operator(
    operator: Option<Extension<DirectApiOperator>>,
) -> Result<DirectApiOperator, ApiError> {
    let Some(Extension(operator)) = operator else {
        tracing::warn!("report config write request missing direct API operator context");
        return Err(ApiError::Forbidden);
    };
    Ok(operator)
}

pub(crate) fn validate_report_config_create_request(
    request: ReportConfigCreateRequest,
) -> Result<ValidatedReportConfigCreate, ApiError> {
    Ok(ValidatedReportConfigCreate {
        name: normalize_required_report_config_text(request.name, "name")?,
        comment: normalize_optional_report_config_text(request.comment, "comment")?,
        report_format_id: normalize_report_format_id(request.report_format_id)?,
        params: normalize_report_config_params(request.params)?,
    })
}

pub(crate) fn validate_report_config_patch_request(
    request: ReportConfigPatchRequest,
) -> Result<ValidatedReportConfigPatch, ApiError> {
    let validated = ValidatedReportConfigPatch {
        name: normalize_optional_required_report_config_text(request.name, "name")?,
        comment: normalize_optional_report_config_text(request.comment, "comment")?,
        params: request
            .params
            .map(normalize_report_config_params)
            .transpose()?,
    };
    if validated.name.is_none() && validated.comment.is_none() && validated.params.is_none() {
        return Err(ApiError::BadRequest(
            "report config patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

#[cfg(test)]
pub(crate) fn report_config_create_transaction_plan(
    _request: &ValidatedReportConfigCreate,
) -> ReportConfigWriteTransactionPlan {
    ReportConfigWriteTransactionPlan {
        operation: ReportConfigWriteOperation::Create,
        steps: vec![
            ReportConfigWriteStep::ResolveOperatorOwner,
            ReportConfigWriteStep::VerifyReportFormatVisible,
            ReportConfigWriteStep::VerifyReportFormatParams,
            ReportConfigWriteStep::VerifyUniqueLiveName,
            ReportConfigWriteStep::InsertReportConfig,
            ReportConfigWriteStep::ReplaceReportConfigParams,
        ],
    }
}

#[cfg(test)]
pub(crate) fn report_config_patch_transaction_plan(
    request: &ValidatedReportConfigPatch,
) -> ReportConfigWriteTransactionPlan {
    let mut steps = vec![
        ReportConfigWriteStep::ResolveOperatorOwner,
        ReportConfigWriteStep::VerifyExistingReportConfigMutable,
    ];
    if request.params.is_some() {
        steps.push(ReportConfigWriteStep::VerifyReportFormatParams);
    }
    if request.name.is_some() {
        steps.push(ReportConfigWriteStep::VerifyUniqueLiveName);
    }
    if request.name.is_some() || request.comment.is_some() {
        steps.push(ReportConfigWriteStep::UpdateReportConfigMetadata);
    }
    if request.params.is_some() {
        steps.push(ReportConfigWriteStep::ReplaceReportConfigParams);
    }
    ReportConfigWriteTransactionPlan {
        operation: ReportConfigWriteOperation::Patch,
        steps,
    }
}

#[cfg(test)]
pub(crate) fn report_config_delete_transaction_plan() -> ReportConfigWriteTransactionPlan {
    ReportConfigWriteTransactionPlan {
        operation: ReportConfigWriteOperation::Delete,
        steps: vec![
            ReportConfigWriteStep::ResolveOperatorOwner,
            ReportConfigWriteStep::VerifyExistingReportConfigMutable,
            ReportConfigWriteStep::MoveReportConfigToTrash,
        ],
    }
}

fn normalize_required_report_config_text(
    value: String,
    field_name: &str,
) -> Result<String, ApiError> {
    let value = normalize_report_config_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_required_report_config_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_report_config_text(value, field_name))
        .transpose()
}

fn normalize_optional_report_config_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_report_config_text_value(value, field_name))
        .transpose()
}

fn normalize_report_config_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_REPORT_CONFIG_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_REPORT_CONFIG_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}

fn normalize_report_format_id(value: String) -> Result<String, ApiError> {
    parse_uuid(value.trim()).map(|uuid| uuid.to_string())
}

fn normalize_report_config_params(
    params: Vec<ReportConfigParamWriteRequest>,
) -> Result<Vec<ValidatedReportConfigParamWrite>, ApiError> {
    if params.len() > MAX_REPORT_CONFIG_PARAMS {
        return Err(ApiError::BadRequest(format!(
            "params must contain at most {MAX_REPORT_CONFIG_PARAMS} entries"
        )));
    }
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(params.len());
    for param in params {
        let name = normalize_required_report_config_text(param.name, "param.name")?;
        if !seen.insert(name.clone()) {
            return Err(ApiError::Conflict(format!(
                "params contains duplicate name: {name}"
            )));
        }
        let value = normalize_report_config_param_value(param.value)?;
        normalized.push(ValidatedReportConfigParamWrite { name, value });
    }
    Ok(normalized)
}

fn normalize_report_config_param_value(value: String) -> Result<String, ApiError> {
    if value.len() > MAX_REPORT_CONFIG_PARAM_VALUE_BYTES || value.contains('\0') {
        return Err(ApiError::BadRequest(format!(
            "param.value must be text up to {MAX_REPORT_CONFIG_PARAM_VALUE_BYTES} bytes without NUL bytes"
        )));
    }
    Ok(value)
}

async fn resolve_report_config_write_operator_owner(
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

async fn ensure_unique_live_report_config_name(
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

async fn load_report_config_format_state(
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

fn validate_report_config_param_values(
    params: &[ValidatedReportConfigParamWrite],
    format: &ReportConfigFormatState,
) -> Result<(), ApiError> {
    for param in params {
        let Some(format_param) = format.params.get(&param.name) else {
            return Err(ApiError::BadRequest(format!(
                "report format has no parameter named {}",
                param.name
            )));
        };
        validate_report_config_param_value(param, format_param)?;
    }
    Ok(())
}

fn validate_report_config_param_value(
    param: &ValidatedReportConfigParamWrite,
    format_param: &ReportConfigFormatParam,
) -> Result<(), ApiError> {
    match format_param.param_type {
        1 => validate_report_config_integer_param(param, format_param),
        2 => validate_report_config_selection_param(param, format_param),
        3 | 4 => validate_report_config_text_param(param, format_param),
        5 => validate_report_config_report_format_list_param(param),
        6 => validate_report_config_multi_selection_param(param, format_param),
        _ => Ok(()),
    }
}

fn validate_report_config_integer_param(
    param: &ValidatedReportConfigParamWrite,
    format_param: &ReportConfigFormatParam,
) -> Result<(), ApiError> {
    let actual = param.value.parse::<i64>().map_err(|_| {
        ApiError::BadRequest(format!("value of param {} must be an integer", param.name))
    })?;
    if actual < format_param.min {
        return Err(ApiError::BadRequest(format!(
            "value of param {} is below minimum",
            param.name
        )));
    }
    if actual > format_param.max {
        return Err(ApiError::BadRequest(format!(
            "value of param {} is above maximum",
            param.name
        )));
    }
    Ok(())
}

fn validate_report_config_selection_param(
    param: &ValidatedReportConfigParamWrite,
    format_param: &ReportConfigFormatParam,
) -> Result<(), ApiError> {
    if format_param.options.contains(&param.value) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "value of param {} is not a valid selection option",
            param.name
        )))
    }
}

fn validate_report_config_text_param(
    param: &ValidatedReportConfigParamWrite,
    format_param: &ReportConfigFormatParam,
) -> Result<(), ApiError> {
    let actual = param.value.len() as i64;
    if actual < format_param.min {
        return Err(ApiError::BadRequest(format!(
            "value of param {} is too short",
            param.name
        )));
    }
    if actual > format_param.max {
        return Err(ApiError::BadRequest(format!(
            "value of param {} is too long",
            param.name
        )));
    }
    Ok(())
}

fn validate_report_config_report_format_list_param(
    param: &ValidatedReportConfigParamWrite,
) -> Result<(), ApiError> {
    if param.value.is_empty()
        || param.value.split(',').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
    {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "value of param {} is not a valid UUID list",
            param.name
        )))
    }
}

fn validate_report_config_multi_selection_param(
    param: &ValidatedReportConfigParamWrite,
    format_param: &ReportConfigFormatParam,
) -> Result<(), ApiError> {
    let values = serde_json::from_str::<Vec<String>>(&param.value).map_err(|_| {
        ApiError::BadRequest(format!(
            "value of param {} is not a valid JSON string array",
            param.name
        ))
    })?;
    let count = values.len() as i64;
    if count < format_param.min {
        return Err(ApiError::BadRequest(format!(
            "value of param {} has too few options",
            param.name
        )));
    }
    if count > format_param.max {
        return Err(ApiError::BadRequest(format!(
            "value of param {} has too many options",
            param.name
        )));
    }
    for value in values {
        if !format_param.options.contains(&value) {
            return Err(ApiError::BadRequest(format!(
                "value of param {} contains an invalid selection option",
                param.name
            )));
        }
    }
    Ok(())
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

async fn load_report_config_write_state(
    tx: &Transaction<'_>,
    report_config_id: &str,
) -> Result<ReportConfigWriteState, ApiError> {
    let report_config_id = parse_uuid(report_config_id)?.to_string();
    tx.query_opt(report_config_write_state_sql(), &[&report_config_id])
        .await
        .map_err(|error| map_report_config_write_db_error(error, "load report config write state"))?
        .map(|row| ReportConfigWriteState {
            internal_id: row.get(0),
            uuid: row.get(1),
            report_format_id: row.get(2),
        })
        .ok_or(ApiError::NotFound)
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

pub(crate) fn report_config_write_state_sql() -> &'static str {
    "SELECT id::integer,
            uuid::text,
            coalesce(report_format_id, '')::text
       FROM report_configs
      WHERE uuid = $1;"
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

fn report_config_write_location_headers(report_config_id: &str) -> Result<HeaderMap, ApiError> {
    let mut headers = HeaderMap::new();
    let location = format!("/api/v1/report-configs/{report_config_id}");
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&location).map_err(|_| ApiError::Config)?,
    );
    Ok(headers)
}

fn map_report_config_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "report config write database operation failed");
    ApiError::Database
}

pub(crate) fn report_config_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer, uuid::text, coalesce(name, '')::text
       FROM users
      WHERE uuid = $1;"
}

pub(crate) fn report_config_unique_live_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM report_configs
      WHERE name = $1
        AND ($2::integer IS NULL OR id != $2);"
}

pub(crate) fn report_config_format_state_sql() -> &'static str {
    "SELECT id::integer, uuid::text
       FROM report_formats
      WHERE uuid = $1;"
}

pub(crate) fn report_config_format_params_sql() -> &'static str {
    "SELECT id::integer AS internal_id,
            coalesce(name, '') AS name,
            coalesce(type, 100)::integer AS param_type,
            type_min,
            type_max
       FROM report_format_params
      WHERE report_format = $1
      ORDER BY name ASC, id ASC;"
}

pub(crate) fn report_config_format_param_options_sql() -> &'static str {
    "SELECT report_format_param::integer,
            coalesce(value, '') AS value
       FROM report_format_param_options
      WHERE report_format_param = ANY($1::integer[])
      ORDER BY report_format_param ASC, value ASC;"
}

pub(crate) fn report_config_insert_sql() -> &'static str {
    "INSERT INTO report_configs
        (uuid, name, comment, report_format_id, owner, creation_time, modification_time)
     VALUES (make_uuid(), $1, $2, $3, $4, m_now(), m_now())
     RETURNING id::integer, uuid::text;"
}

pub(crate) fn report_config_update_metadata_sql() -> &'static str {
    "UPDATE report_configs
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            modification_time = m_now()
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn report_config_touch_sql() -> &'static str {
    "UPDATE report_configs
        SET modification_time = m_now()
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn report_config_by_internal_id_sql() -> &'static str {
    "SELECT id::integer, uuid::text
       FROM report_configs
      WHERE id = $1;"
}

pub(crate) fn report_config_delete_params_sql() -> &'static str {
    "DELETE FROM report_config_params WHERE report_config = $1;"
}

pub(crate) fn report_config_insert_param_sql() -> &'static str {
    "INSERT INTO report_config_params (report_config, name, value)
     VALUES ($1, $2, $3)
     ON CONFLICT (report_config, name) DO UPDATE SET value = EXCLUDED.value;"
}

#[cfg(test)]
#[path = "report_config_writes_tests.rs"]
mod report_config_writes_tests;
