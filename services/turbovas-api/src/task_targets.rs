// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;
use tokio_postgres::Row;

use crate::{
    app_state::AppState,
    collections::{TARGET_DEFAULT_SORT, TARGET_SORT_FIELDS, TASK_DEFAULT_SORT, TASK_SORT_FIELDS},
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    row_helpers::{alive_test_labels, boolean_int, csv_values, task_has_active_current_report},
};

#[derive(Debug, Serialize)]
struct TargetReference {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct PortListReference {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct CredentialReference {
    id: String,
    name: String,
    credential_type: String,
    port: Option<i64>,
}

#[derive(Debug, Serialize)]
struct TargetCredentials {
    ssh: Option<CredentialReference>,
    ssh_elevate: Option<CredentialReference>,
    smb: Option<CredentialReference>,
    esxi: Option<CredentialReference>,
    snmp: Option<CredentialReference>,
    krb5: Option<CredentialReference>,
}

#[derive(Debug, Serialize)]
pub(crate) struct TargetItem {
    id: String,
    name: String,
    comment: String,
    hosts: Vec<String>,
    exclude_hosts: Vec<String>,
    max_hosts: i64,
    alive_tests: Vec<String>,
    allow_simultaneous_ips: bool,
    reverse_lookup_only: bool,
    reverse_lookup_unify: bool,
    port_list: Option<PortListReference>,
    credentials: TargetCredentials,
    task_count: i64,
    tasks: Vec<TargetReference>,
    creation_time: Option<String>,
    modification_time: Option<String>,
}

#[derive(Debug, Serialize)]
struct TaskReportCount {
    total: i64,
    finished: i64,
}

#[derive(Debug, Serialize)]
struct TaskReportReference {
    id: String,
    timestamp: Option<String>,
    scan_start: Option<String>,
    scan_end: Option<String>,
    severity: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct TaskItem {
    id: String,
    name: String,
    comment: String,
    status: String,
    progress: i64,
    trend: String,
    usage_type: String,
    target: Option<TargetReference>,
    config: Option<TargetReference>,
    scanner: Option<TargetReference>,
    scanner_type: Option<i32>,
    schedule: Option<TargetReference>,
    report_count: TaskReportCount,
    current_report: Option<TaskReportReference>,
    last_report: Option<TaskReportReference>,
    max_severity: f64,
    creation_time: Option<String>,
    modification_time: Option<String>,
}

fn target_reference(id: Option<String>, name: Option<String>) -> Option<TargetReference> {
    let id = id?;
    let name = name.unwrap_or_else(|| id.clone());
    Some(TargetReference { id, name })
}

fn port_list_reference(id: Option<String>, name: Option<String>) -> Option<PortListReference> {
    let id = id?;
    let name = name.unwrap_or_else(|| id.clone());
    Some(PortListReference { id, name })
}

fn credential_reference(
    row: &Row,
    id_field: &str,
    name_field: &str,
    type_field: &str,
    port_field: &str,
) -> Option<CredentialReference> {
    let id: Option<String> = row.get(id_field);
    id.map(|id| CredentialReference {
        name: row
            .get::<_, Option<String>>(name_field)
            .unwrap_or_else(|| id.clone()),
        credential_type: row
            .get::<_, Option<String>>(type_field)
            .unwrap_or_else(|| "unknown".to_string()),
        port: row.get(port_field),
        id,
    })
}

fn target_credentials(row: &Row) -> TargetCredentials {
    TargetCredentials {
        ssh: credential_reference(
            row,
            "ssh_credential_id",
            "ssh_credential_name",
            "ssh_credential_type",
            "ssh_credential_port",
        ),
        ssh_elevate: credential_reference(
            row,
            "ssh_elevate_credential_id",
            "ssh_elevate_credential_name",
            "ssh_elevate_credential_type",
            "ssh_elevate_credential_port",
        ),
        smb: credential_reference(
            row,
            "smb_credential_id",
            "smb_credential_name",
            "smb_credential_type",
            "smb_credential_port",
        ),
        esxi: credential_reference(
            row,
            "esxi_credential_id",
            "esxi_credential_name",
            "esxi_credential_type",
            "esxi_credential_port",
        ),
        snmp: credential_reference(
            row,
            "snmp_credential_id",
            "snmp_credential_name",
            "snmp_credential_type",
            "snmp_credential_port",
        ),
        krb5: credential_reference(
            row,
            "krb5_credential_id",
            "krb5_credential_name",
            "krb5_credential_type",
            "krb5_credential_port",
        ),
    }
}

fn target_task_references(row: &Row) -> Vec<TargetReference> {
    let ids: Vec<String> = row.get("task_ids");
    let names: Vec<String> = row.get("task_names");
    ids.into_iter()
        .enumerate()
        .map(|(index, id)| TargetReference {
            name: names.get(index).cloned().unwrap_or_else(|| id.clone()),
            id,
        })
        .collect()
}

pub(crate) fn target_from_row(row: &Row) -> TargetItem {
    let hosts = csv_values(&row.get::<_, String>("hosts"));
    TargetItem {
        id: row.get("uuid"),
        name: row.get("name"),
        comment: row.get("comment"),
        max_hosts: row.get("host_entry_count"),
        hosts,
        exclude_hosts: csv_values(&row.get::<_, String>("exclude_hosts")),
        alive_tests: alive_test_labels(row.get("alive_test")),
        allow_simultaneous_ips: boolean_int(row.get("allow_simultaneous_ips")),
        reverse_lookup_only: boolean_int(row.get("reverse_lookup_only")),
        reverse_lookup_unify: boolean_int(row.get("reverse_lookup_unify")),
        port_list: port_list_reference(row.get("port_list_id"), row.get("port_list_name")),
        credentials: target_credentials(row),
        task_count: row.get("task_count"),
        tasks: target_task_references(row),
        creation_time: unix_ts_to_rfc3339(row.get("creation_time")),
        modification_time: unix_ts_to_rfc3339(row.get("modification_time")),
    }
}

fn task_report_reference(
    row: &Row,
    id_field: &str,
    timestamp_field: &str,
    scan_start_field: &str,
    scan_end_field: &str,
    severity_field: &str,
) -> Option<TaskReportReference> {
    let id: Option<String> = row.get(id_field);
    id.map(|id| TaskReportReference {
        id,
        timestamp: unix_ts_to_rfc3339(row.get(timestamp_field)),
        scan_start: unix_ts_to_rfc3339(row.get(scan_start_field)),
        scan_end: unix_ts_to_rfc3339(row.get(scan_end_field)),
        severity: row.get(severity_field),
    })
}

pub(crate) fn task_from_row(row: &Row) -> TaskItem {
    let status: String = row.get("status");
    let current_report = if task_has_active_current_report(&status) {
        task_report_reference(
            row,
            "current_report_id",
            "current_report_timestamp",
            "current_report_scan_start",
            "current_report_scan_end",
            "current_report_severity",
        )
    } else {
        None
    };
    TaskItem {
        id: row.get("uuid"),
        name: row.get("name"),
        comment: row.get("comment"),
        status,
        progress: row.get("progress"),
        trend: row.get("trend"),
        usage_type: row.get("usage_type"),
        target: target_reference(row.get("target_id"), row.get("target_name")),
        config: target_reference(row.get("config_id"), row.get("config_name")),
        scanner: target_reference(row.get("scanner_id"), row.get("scanner_name")),
        scanner_type: row.get("scanner_type"),
        schedule: target_reference(row.get("schedule_id"), row.get("schedule_name")),
        report_count: TaskReportCount {
            total: row.get("report_count_total"),
            finished: row.get("report_count_finished"),
        },
        current_report,
        last_report: task_report_reference(
            row,
            "last_report_id",
            "last_report_timestamp",
            "last_report_scan_start",
            "last_report_scan_end",
            "last_report_severity",
        ),
        max_severity: row.get("max_severity"),
        creation_time: unix_ts_to_rfc3339(row.get("creation_time")),
        modification_time: unix_ts_to_rfc3339(row.get("modification_time")),
    }
}

pub(crate) async fn targets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TargetItem>>, ApiError> {
    let params = normalize_collection_query(query, TARGET_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TARGET_SORT_FIELDS)?;
    let sql = target_sql(
        "($1 = ''\n\
            OR lower(uuid) = lower($1)\n\
            OR lower(name) LIKE '%' || lower($1) || '%'\n\
            OR lower(comment) LIKE '%' || lower($1) || '%'\n\
            OR lower(coalesce(port_list_name, '')) LIKE '%' || lower($1) || '%'\n\
            OR lower(hosts) LIKE '%' || lower($1) || '%')",
        &sort_sql,
        "LIMIT $2 OFFSET $3",
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "target list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(target_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn target_detail(
    State(state): State<AppState>,
    Path(target_id): Path<String>,
) -> Result<Json<TargetItem>, ApiError> {
    parse_uuid(&target_id)?;
    let sql = target_sql("lower(uuid) = lower($1)", "name ASC", "");
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(&sql, &[&target_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "target detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(target_from_row(&row)))
}

fn target_sql(filtered_predicate: &str, sort_sql: &str, limit_clause: &str) -> String {
    format!(
        r#"WITH base AS (
             SELECT t.id AS target_pk,
                    t.uuid,
                    t.name,
                    coalesce(t.comment, '') AS comment,
                    coalesce(t.hosts, '') AS hosts,
                    coalesce(t.exclude_hosts, '') AS exclude_hosts,
                    coalesce(t.alive_test, 0)::bigint AS alive_test,
                    coalesce(t.allow_simultaneous_ips, 0)::int AS allow_simultaneous_ips,
                    coalesce(t.reverse_lookup_only, 0)::int AS reverse_lookup_only,
                    coalesce(t.reverse_lookup_unify, 0)::int AS reverse_lookup_unify,
                    pl.uuid AS port_list_id,
                    pl.name AS port_list_name,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'ssh' LIMIT 1) AS ssh_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'ssh' LIMIT 1) AS ssh_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'ssh' LIMIT 1) AS ssh_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'ssh' LIMIT 1) AS ssh_credential_port,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'elevate' LIMIT 1) AS ssh_elevate_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'elevate' LIMIT 1) AS ssh_elevate_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'elevate' LIMIT 1) AS ssh_elevate_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'elevate' LIMIT 1) AS ssh_elevate_credential_port,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'smb' LIMIT 1) AS smb_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'smb' LIMIT 1) AS smb_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'smb' LIMIT 1) AS smb_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'smb' LIMIT 1) AS smb_credential_port,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'esxi' LIMIT 1) AS esxi_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'esxi' LIMIT 1) AS esxi_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'esxi' LIMIT 1) AS esxi_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'esxi' LIMIT 1) AS esxi_credential_port,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'snmp' LIMIT 1) AS snmp_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'snmp' LIMIT 1) AS snmp_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'snmp' LIMIT 1) AS snmp_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'snmp' LIMIT 1) AS snmp_credential_port,
                    (SELECT c.uuid FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'krb5' LIMIT 1) AS krb5_credential_id,
                    (SELECT c.name FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'krb5' LIMIT 1) AS krb5_credential_name,
                    (SELECT c.type FROM targets_login_data tld JOIN credentials c ON c.id = tld.credential
                      WHERE tld.target = t.id AND tld.type = 'krb5' LIMIT 1) AS krb5_credential_type,
                    (SELECT NULLIF(tld.port, 0)::bigint FROM targets_login_data tld
                      WHERE tld.target = t.id AND tld.type = 'krb5' LIMIT 1) AS krb5_credential_port,
                    coalesce(t.creation_time, 0)::bigint AS creation_time,
                    coalesce(t.modification_time, 0)::bigint AS modification_time,
                    CASE WHEN coalesce(t.hosts, '') = '' THEN 0::bigint
                         ELSE cardinality(string_to_array(t.hosts, ','))::bigint END AS host_entry_count,
                    count(task.id)::bigint AS task_count,
                    coalesce(array_agg(task.uuid ORDER BY task.name) FILTER (WHERE task.id IS NOT NULL), ARRAY[]::text[]) AS task_ids,
                    coalesce(array_agg(task.name ORDER BY task.name) FILTER (WHERE task.id IS NOT NULL), ARRAY[]::text[]) AS task_names
               FROM targets t
               LEFT JOIN port_lists pl ON pl.id = t.port_list
               LEFT JOIN tasks task
                 ON task.target = t.id
                AND coalesce(task.hidden, 0) = 0
                AND coalesce(task.usage_type, 'scan') = 'scan'
              GROUP BY t.id, t.uuid, t.name, t.comment, t.hosts, t.exclude_hosts,
                       t.alive_test, t.allow_simultaneous_ips, t.reverse_lookup_only,
                       t.reverse_lookup_unify, pl.uuid, pl.name,
                       t.creation_time, t.modification_time
         ),
         filtered AS (
             SELECT * FROM base WHERE {filtered_predicate}
         )
         SELECT count(*) OVER()::bigint AS total, *
           FROM filtered
          ORDER BY {sort_sql}, name ASC {limit_clause};"#
    )
}

pub(crate) async fn tasks(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TaskItem>>, ApiError> {
    let params = normalize_collection_query(query, TASK_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TASK_SORT_FIELDS)?;
    let sql = task_sql(
        "($1 = ''\n\
            OR lower(uuid) = lower($1)\n\
            OR lower(name) LIKE '%' || lower($1) || '%'\n\
            OR lower(comment) LIKE '%' || lower($1) || '%'\n\
            OR lower(status) LIKE '%' || lower($1) || '%'\n\
            OR lower(coalesce(target_name, '')) LIKE '%' || lower($1) || '%'\n\
            OR lower(coalesce(config_name, '')) LIKE '%' || lower($1) || '%'\n\
            OR lower(coalesce(scanner_name, '')) LIKE '%' || lower($1) || '%')",
        &sort_sql,
        "LIMIT $2 OFFSET $3",
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "task list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(task_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn task_detail(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
) -> Result<Json<TaskItem>, ApiError> {
    parse_uuid(&task_id)?;
    let sql = task_sql("lower(uuid) = lower($1)", "name ASC", "");
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(&sql, &[&task_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "task detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(task_from_row(&row)))
}

fn task_sql(filtered_predicate: &str, sort_sql: &str, limit_clause: &str) -> String {
    format!(
        r#"WITH report_rollup AS (
             SELECT r.task,
                    count(DISTINCT r.id)::bigint AS report_count_total,
                    count(DISTINCT r.id) FILTER (WHERE run_status_name(coalesce(r.scan_run_status, 0)) = 'Done')::bigint AS report_count_finished,
                    coalesce(max(res.severity) FILTER (WHERE coalesce(res.severity, 0) > 0), 0)::double precision AS max_severity
               FROM reports r
               LEFT JOIN results res ON res.report = r.id
              GROUP BY r.task
         ),
         report_rows AS (
             SELECT r.task,
                    r.id AS report_pk,
                    r.uuid,
                    coalesce(r.creation_time, 0)::bigint AS timestamp,
                    coalesce(r.start_time, 0)::bigint AS scan_start,
                    coalesce(r.end_time, 0)::bigint AS scan_end,
                    coalesce(max(res.severity) FILTER (WHERE coalesce(res.severity, 0) > 0), 0)::double precision AS severity,
                    count(*) FILTER (WHERE coalesce(res.severity, 0) >= 9.0)::bigint AS critical_count,
                    count(*) FILTER (WHERE coalesce(res.severity, 0) >= 7.0 AND coalesce(res.severity, 0) < 9.0)::bigint AS high_count,
                    count(*) FILTER (WHERE coalesce(res.severity, 0) >= 4.0 AND coalesce(res.severity, 0) < 7.0)::bigint AS medium_count,
                    count(*) FILTER (WHERE coalesce(res.severity, 0) > 0 AND coalesce(res.severity, 0) < 4.0)::bigint AS low_count,
                    run_status_name(coalesce(r.scan_run_status, 0)) AS status,
                    row_number() OVER (PARTITION BY r.task ORDER BY coalesce(nullif(r.end_time, 0), nullif(r.start_time, 0), nullif(r.creation_time, 0), 0) DESC, r.id DESC) AS latest_rank,
                    CASE WHEN run_status_name(coalesce(r.scan_run_status, 0)) = 'Done' THEN 1 ELSE 0 END AS is_finished
               FROM reports r
               LEFT JOIN results res ON res.report = r.id
              GROUP BY r.task, r.id, r.uuid, r.creation_time, r.start_time, r.end_time, r.scan_run_status
         ),
         finished_report_rows AS (
             SELECT *, row_number() OVER (PARTITION BY task ORDER BY coalesce(nullif(scan_end, 0), nullif(scan_start, 0), nullif(timestamp, 0), 0) DESC, report_pk DESC) AS finished_rank
               FROM report_rows
              WHERE is_finished = 1
         ),
         latest_report AS (
             SELECT * FROM report_rows WHERE latest_rank = 1
         ),
         latest_finished_report AS (
             SELECT * FROM finished_report_rows WHERE finished_rank = 1
         ),
         second_latest_finished_report AS (
             SELECT * FROM finished_report_rows WHERE finished_rank = 2
         ),
         base AS (
             SELECT task.id AS task_pk,
                    task.uuid,
                    task.name,
                    coalesce(task.comment, '') AS comment,
                    run_status_name(coalesce(task.run_status, 0)) AS status,
                    CASE WHEN run_status_name(coalesce(task.run_status, 0)) = 'Done' THEN 100::bigint
                         WHEN latest_report.report_pk IS NOT NULL THEN coalesce(report_progress(latest_report.report_pk), 0)::bigint
                         ELSE 0::bigint END AS progress,
                    CASE
                      WHEN coalesce(report_rollup.report_count_finished, 0) <= 1 THEN ''
                      WHEN run_status_name(coalesce(task.run_status, 0)) = 'Running' OR target.id IS NULL THEN ''
                      WHEN latest_finished_report.severity > second_latest_finished_report.severity THEN 'up'
                      WHEN second_latest_finished_report.severity > latest_finished_report.severity THEN 'down'
                      WHEN (CASE WHEN latest_finished_report.critical_count > 0 THEN 5
                                 WHEN latest_finished_report.high_count > 0 THEN 4
                                 WHEN latest_finished_report.medium_count > 0 THEN 3
                                 WHEN latest_finished_report.low_count > 0 THEN 2
                                 ELSE 1 END)
                         > (CASE WHEN second_latest_finished_report.critical_count > 0 THEN 5
                                 WHEN second_latest_finished_report.high_count > 0 THEN 4
                                 WHEN second_latest_finished_report.medium_count > 0 THEN 3
                                 WHEN second_latest_finished_report.low_count > 0 THEN 2
                                 ELSE 1 END) THEN 'up'
                      WHEN (CASE WHEN second_latest_finished_report.critical_count > 0 THEN 5
                                 WHEN second_latest_finished_report.high_count > 0 THEN 4
                                 WHEN second_latest_finished_report.medium_count > 0 THEN 3
                                 WHEN second_latest_finished_report.low_count > 0 THEN 2
                                 ELSE 1 END)
                         > (CASE WHEN latest_finished_report.critical_count > 0 THEN 5
                                 WHEN latest_finished_report.high_count > 0 THEN 4
                                 WHEN latest_finished_report.medium_count > 0 THEN 3
                                 WHEN latest_finished_report.low_count > 0 THEN 2
                                 ELSE 1 END) THEN 'down'
                      WHEN latest_finished_report.critical_count > 0 THEN
                        CASE WHEN latest_finished_report.critical_count > second_latest_finished_report.critical_count THEN 'more'
                             WHEN latest_finished_report.critical_count < second_latest_finished_report.critical_count THEN 'less'
                             ELSE 'same' END
                      WHEN latest_finished_report.high_count > 0 THEN
                        CASE WHEN latest_finished_report.high_count > second_latest_finished_report.high_count THEN 'more'
                             WHEN latest_finished_report.high_count < second_latest_finished_report.high_count THEN 'less'
                             ELSE 'same' END
                      WHEN latest_finished_report.medium_count > 0 THEN
                        CASE WHEN latest_finished_report.medium_count > second_latest_finished_report.medium_count THEN 'more'
                             WHEN latest_finished_report.medium_count < second_latest_finished_report.medium_count THEN 'less'
                             ELSE 'same' END
                      WHEN latest_finished_report.low_count > 0 THEN
                        CASE WHEN latest_finished_report.low_count > second_latest_finished_report.low_count THEN 'more'
                             WHEN latest_finished_report.low_count < second_latest_finished_report.low_count THEN 'less'
                             ELSE 'same' END
                      ELSE 'same'
                    END AS trend,
                    coalesce(task.usage_type, 'scan') AS usage_type,
                    target.uuid AS target_id,
                    target.name AS target_name,
                    config.uuid AS config_id,
                    config.name AS config_name,
                    scanner.uuid AS scanner_id,
                    scanner.name AS scanner_name,
                    scanner.type AS scanner_type,
                    schedule.uuid AS schedule_id,
                    schedule.name AS schedule_name,
                    coalesce(report_rollup.report_count_total, 0)::bigint AS report_count_total,
                    coalesce(report_rollup.report_count_finished, 0)::bigint AS report_count_finished,
                    latest_report.uuid AS current_report_id,
                    latest_report.timestamp AS current_report_timestamp,
                    latest_report.scan_start AS current_report_scan_start,
                    latest_report.scan_end AS current_report_scan_end,
                    latest_report.severity AS current_report_severity,
                    latest_finished_report.uuid AS last_report_id,
                    latest_finished_report.timestamp AS last_report_timestamp,
                    latest_finished_report.scan_start AS last_report_scan_start,
                    latest_finished_report.scan_end AS last_report_scan_end,
                    latest_finished_report.severity AS last_report_severity,
                    coalesce(report_rollup.max_severity, 0)::double precision AS max_severity,
                    coalesce(task.creation_time, 0)::bigint AS creation_time,
                    coalesce(task.modification_time, 0)::bigint AS modification_time
               FROM tasks task
               LEFT JOIN targets target ON target.id = task.target
               LEFT JOIN configs config ON config.id = task.config
               LEFT JOIN scanners scanner ON scanner.id = task.scanner
               LEFT JOIN schedules schedule ON schedule.id = task.schedule
               LEFT JOIN report_rollup ON report_rollup.task = task.id
               LEFT JOIN latest_report ON latest_report.task = task.id
               LEFT JOIN latest_finished_report ON latest_finished_report.task = task.id
               LEFT JOIN second_latest_finished_report ON second_latest_finished_report.task = task.id
              WHERE coalesce(task.hidden, 0) = 0
                AND coalesce(task.usage_type, 'scan') = 'scan'
         ),
         filtered AS (
             SELECT * FROM base WHERE {filtered_predicate}
         )
         SELECT count(*) OVER()::bigint AS total, *
           FROM filtered
          ORDER BY {sort_sql}, name ASC {limit_clause};"#
    )
}
