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
    app_state::AppState, errors::ApiError, formatters::normalize_authentication_state,
    path_ids::parse_uuid,
};

#[derive(Debug, Serialize)]
pub(crate) struct MetricsSummary {
    total_system_cvss_load: f64,
    average_system_cvss_load: f64,
    authenticated_scan_coverage_percent: f64,
    alive_system_count: i64,
    vulnerability_count: i64,
    authenticated_system_count: i64,
    authentication_failed_system_count: i64,
    no_credential_path_system_count: i64,
    unknown_authentication_system_count: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct MetricsSystem {
    host: String,
    cvss_load: f64,
    max_cvss: f64,
    vulnerability_count: i64,
    authentication_state: String,
    source_report_count: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct MetricsVulnerability {
    nvt_oid: String,
    name: String,
    cvss_score: f64,
    affected_system_count: i64,
    cvss_load: f64,
    average_contribution: f64,
    source_report_count: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct MetricsPayload {
    pub(crate) id: String,
    pub(crate) summary: MetricsSummary,
    pub(crate) systems: Vec<MetricsSystem>,
    pub(crate) vulnerabilities: Vec<MetricsVulnerability>,
}

pub(crate) fn metrics_summary_from_row(row: &Row) -> MetricsSummary {
    MetricsSummary {
        total_system_cvss_load: row.get(2),
        average_system_cvss_load: row.get(3),
        authenticated_scan_coverage_percent: row.get(4),
        alive_system_count: row.get(5),
        vulnerability_count: row.get(6),
        authenticated_system_count: row.get(7),
        authentication_failed_system_count: row.get(8),
        no_credential_path_system_count: row.get(9),
        unknown_authentication_system_count: row.get(10),
    }
}

pub(crate) fn metrics_system_from_row(row: &Row) -> MetricsSystem {
    MetricsSystem {
        host: row.get(0),
        cvss_load: row.get(1),
        max_cvss: row.get(2),
        vulnerability_count: row.get(3),
        authentication_state: normalize_authentication_state(&row.get::<_, String>(4)),
        source_report_count: row.get(5),
    }
}

pub(crate) fn metrics_vulnerability_from_row(row: &Row) -> MetricsVulnerability {
    MetricsVulnerability {
        nvt_oid: row.get(0),
        name: row.get(1),
        cvss_score: row.get(2),
        affected_system_count: row.get(3),
        cvss_load: row.get(4),
        average_contribution: row.get(5),
        source_report_count: row.get(6),
    }
}

pub(crate) fn summarize_metrics(
    systems: &[MetricsSystem],
    vulnerability_count: i64,
) -> MetricsSummary {
    let alive_system_count = systems.len() as i64;
    let total_system_cvss_load = systems.iter().map(|system| system.cvss_load).sum::<f64>();
    let authenticated_system_count = systems
        .iter()
        .filter(|system| system.authentication_state == "Authenticated")
        .count() as i64;
    let authentication_failed_system_count = systems
        .iter()
        .filter(|system| system.authentication_state == "Authentication Failed")
        .count() as i64;
    let no_credential_path_system_count = systems
        .iter()
        .filter(|system| system.authentication_state == "No Credential Path")
        .count() as i64;
    let unknown_authentication_system_count = systems
        .iter()
        .filter(|system| system.authentication_state == "Unknown")
        .count() as i64;
    MetricsSummary {
        total_system_cvss_load,
        average_system_cvss_load: if alive_system_count > 0 {
            total_system_cvss_load / alive_system_count as f64
        } else {
            0.0
        },
        authenticated_scan_coverage_percent: if alive_system_count > 0 {
            (100.0 * authenticated_system_count as f64) / alive_system_count as f64
        } else {
            0.0
        },
        alive_system_count,
        vulnerability_count,
        authenticated_system_count,
        authentication_failed_system_count,
        no_credential_path_system_count,
        unknown_authentication_system_count,
    }
}

pub(crate) async fn scope_report_metrics(
    State(state): State<AppState>,
    Path((scope_id, scope_report_id)): Path<(String, String)>,
) -> Result<Json<MetricsPayload>, ApiError> {
    parse_uuid(&scope_id)?;
    parse_uuid(&scope_report_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let summary_row = client
        .query_opt(
            "SELECT sr.id, sr.uuid,\n\
                    coalesce(sr.metric_total_system_cvss_load, 0)::double precision AS total_system_cvss_load,\n\
                    coalesce(sr.metric_average_system_cvss_load, 0)::double precision AS average_system_cvss_load,\n\
                    coalesce(sr.metric_authenticated_scan_coverage, 0)::double precision AS authenticated_scan_coverage_percent,\n\
                    coalesce(sr.metric_alive_system_count, 0)::bigint AS alive_system_count,\n\
                    (SELECT count(*) FROM scope_report_vulnerability_metrics srvm WHERE srvm.scope_report = sr.id)::bigint AS vulnerability_count,\n\
                    coalesce(sr.metric_authenticated_system_count, 0)::bigint AS authenticated_system_count,\n\
                    coalesce(sr.metric_auth_failed_system_count, 0)::bigint AS authentication_failed_system_count,\n\
                    coalesce(sr.metric_no_credential_path_system_count, 0)::bigint AS no_credential_path_system_count,\n\
                    coalesce(sr.metric_unknown_authentication_system_count, 0)::bigint AS unknown_authentication_system_count\n\
               FROM scope_reports sr\n\
              WHERE sr.uuid = $1 AND sr.scope_uuid = $2;",
            &[&scope_report_id, &scope_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report metrics summary query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = summary_row.get(0);
    let systems_rows = client
        .query(
            "SELECT host, cvss_load, max_cvss, vulnerability_count::bigint, authentication_state, source_report_count::bigint\n\
               FROM scope_report_system_metrics\n\
              WHERE scope_report = $1\n\
              ORDER BY cvss_load DESC, host ASC;",
            &[&internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report metrics systems query failed");
            ApiError::Database
        })?;
    let vulnerability_rows = client
        .query(
            "SELECT nvt_oid, nvt_name, cvss_score, affected_system_count::bigint, cvss_load, average_contribution, source_report_count::bigint\n\
               FROM scope_report_vulnerability_metrics\n\
              WHERE scope_report = $1\n\
              ORDER BY cvss_load DESC, cvss_score DESC, nvt_name ASC;",
            &[&internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "scope report metrics vulnerabilities query failed");
            ApiError::Database
        })?;
    Ok(Json(MetricsPayload {
        id: summary_row.get(1),
        summary: metrics_summary_from_row(&summary_row),
        systems: systems_rows.iter().map(metrics_system_from_row).collect(),
        vulnerabilities: vulnerability_rows
            .iter()
            .map(metrics_vulnerability_from_row)
            .collect(),
    }))
}

pub(crate) async fn report_metrics(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
) -> Result<Json<MetricsPayload>, ApiError> {
    parse_uuid(&report_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let report_row = client
        .query_opt(
            "SELECT id, uuid FROM reports WHERE uuid = $1;",
            &[&report_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report metrics report lookup failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = report_row.get(0);

    let system_rows = client
        .query(
            "WITH source_reports AS (\n\
                 SELECT r.id AS source_report, t.target AS target\n\
                   FROM reports r JOIN tasks t ON t.id = r.task\n\
                  WHERE r.id = $1\n\
             ),\n\
             alive AS (\n\
                 SELECT lower(coalesce(nullif(rh.host, ''), rh.hostname, '')) AS host_key,\n\
                        min(coalesce(nullif(rh.host, ''), rh.hostname, '')) AS host,\n\
                        count(DISTINCT rh.report)::bigint AS source_report_count,\n\
                        bool_or(EXISTS (SELECT 1 FROM targets_login_data tld\n\
                                         WHERE tld.target = sr.target\n\
                                           AND coalesce(tld.credential, 0) > 0)) AS has_credential_path,\n\
                        bool_or(EXISTS (\n\
                          SELECT 1 FROM report_host_details rhd\n\
                           WHERE rhd.report_host = rh.id\n\
                             AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%auth%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%credential%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%login%')\n\
                             AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%success%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%succeeded%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%logged in%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%valid credential%')\n\
                        )) AS auth_success,\n\
                        bool_or(EXISTS (\n\
                          SELECT 1 FROM report_host_details rhd\n\
                           WHERE rhd.report_host = rh.id\n\
                             AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%auth%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%credential%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%login%')\n\
                             AND (lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%fail%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%denied%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%invalid%'\n\
                                  OR lower(coalesce(rhd.name, '') || ' ' || coalesce(rhd.value, '') || ' ' || coalesce(rhd.source_name, '')) LIKE '%refused%')\n\
                        )) AS auth_failure\n\
                   FROM report_hosts rh\n\
                   JOIN source_reports sr ON sr.source_report = rh.report\n\
                  WHERE coalesce(nullif(rh.host, ''), rh.hostname, '') <> ''\n\
                  GROUP BY lower(coalesce(nullif(rh.host, ''), rh.hostname, ''))\n\
             ),\n\
             vuln_by_system AS (\n\
                 SELECT lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,\n\
                        coalesce(nullif(r.nvt, ''), 'unknown') AS nvt_oid,\n\
                        max(coalesce(r.severity, 0))::double precision AS cvss_score\n\
                   FROM results r\n\
                   JOIN source_reports sr ON sr.source_report = r.report\n\
                  WHERE coalesce(r.severity, 0) > 0\n\
                    AND coalesce(r.severity, 0) != -3.0\n\
                    AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
                  GROUP BY lower(coalesce(nullif(r.host, ''), r.hostname, '')),\n\
                           coalesce(nullif(r.nvt, ''), 'unknown')\n\
             ),\n\
             system_load AS (\n\
                 SELECT host_key, sum(cvss_score)::double precision AS cvss_load,\n\
                        max(cvss_score)::double precision AS max_cvss,\n\
                        count(*)::bigint AS vulnerability_count\n\
                   FROM vuln_by_system GROUP BY host_key\n\
             )\n\
             SELECT alive.host::text,\n\
                    coalesce(system_load.cvss_load, 0)::double precision,\n\
                    coalesce(system_load.max_cvss, 0)::double precision,\n\
                    coalesce(system_load.vulnerability_count, 0)::bigint,\n\
                    CASE WHEN alive.auth_success THEN 'authenticated'\n\
                         WHEN alive.auth_failure THEN 'authentication_failed'\n\
                         WHEN alive.has_credential_path THEN 'unknown'\n\
                         ELSE 'no_credential_path' END::text,\n\
                    alive.source_report_count::bigint\n\
               FROM alive LEFT JOIN system_load USING (host_key)\n\
              ORDER BY coalesce(system_load.cvss_load, 0) DESC, alive.host ASC;",
            &[&internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report metrics systems query failed");
            ApiError::Database
        })?;
    let systems: Vec<MetricsSystem> = system_rows.iter().map(metrics_system_from_row).collect();
    let alive_system_count = systems.len() as i64;

    let vulnerability_rows = client
        .query(
            "WITH source_reports AS (\n\
                 SELECT r.id AS source_report, t.target AS target\n\
                   FROM reports r JOIN tasks t ON t.id = r.task\n\
                  WHERE r.id = $1\n\
             ),\n\
             deduped_results AS (\n\
                 SELECT lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host_key,\n\
                        coalesce(nullif(r.nvt, ''), 'unknown') AS nvt_oid,\n\
                        max(coalesce(n.name, r.nvt, 'Unknown vulnerability')) AS nvt_name,\n\
                        max(coalesce(r.severity, 0))::double precision AS cvss_score,\n\
                        r.report AS source_report\n\
                   FROM results r\n\
                   JOIN source_reports sr ON sr.source_report = r.report\n\
                   LEFT JOIN nvts n ON n.oid = r.nvt\n\
                  WHERE coalesce(r.severity, 0) > 0\n\
                    AND coalesce(r.severity, 0) != -3.0\n\
                    AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
                  GROUP BY lower(coalesce(nullif(r.host, ''), r.hostname, '')),\n\
                           coalesce(nullif(r.nvt, ''), 'unknown'), r.report\n\
             ),\n\
             vuln_by_system AS (\n\
                 SELECT host_key, nvt_oid, max(nvt_name) AS nvt_name,\n\
                        max(cvss_score)::double precision AS cvss_score\n\
                   FROM deduped_results\n\
                  GROUP BY host_key, nvt_oid\n\
             ),\n\
             vuln_sources AS (\n\
                 SELECT nvt_oid, count(DISTINCT source_report)::bigint AS source_report_count\n\
                   FROM deduped_results\n\
                  GROUP BY nvt_oid\n\
             )\n\
             SELECT v.nvt_oid::text, max(v.nvt_name)::text,\n\
                    max(v.cvss_score)::double precision,\n\
                    count(DISTINCT v.host_key)::bigint,\n\
                    (max(v.cvss_score) * count(DISTINCT v.host_key))::double precision,\n\
                    CASE WHEN $2::bigint > 0\n\
                         THEN ((max(v.cvss_score) * count(DISTINCT v.host_key)) / $2::double precision)::double precision\n\
                         ELSE 0::double precision END,\n\
                    coalesce(max(vs.source_report_count), 0)::bigint\n\
               FROM vuln_by_system v\n\
               LEFT JOIN vuln_sources vs ON vs.nvt_oid = v.nvt_oid\n\
              GROUP BY v.nvt_oid\n\
              ORDER BY (max(v.cvss_score) * count(DISTINCT v.host_key)) DESC,\n\
                       max(v.cvss_score) DESC, max(v.nvt_name) ASC;",
            &[&internal_id, &alive_system_count],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report metrics vulnerabilities query failed");
            ApiError::Database
        })?;
    let vulnerabilities: Vec<MetricsVulnerability> = vulnerability_rows
        .iter()
        .map(metrics_vulnerability_from_row)
        .collect();
    Ok(Json(MetricsPayload {
        id: report_row.get(1),
        summary: summarize_metrics(&systems, vulnerabilities.len() as i64),
        systems,
        vulnerabilities,
    }))
}
