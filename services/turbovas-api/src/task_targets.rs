// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{TARGET_DEFAULT_SORT, TARGET_SORT_FIELDS, TASK_DEFAULT_SORT, TASK_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    task_target_payloads::{TargetItem, TaskItem, target_from_row, task_from_row},
};

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
