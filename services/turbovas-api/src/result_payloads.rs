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
    collections::{
        REPORT_RESULT_DEFAULT_SORT, REPORT_RESULT_SORT_FIELDS, RESULT_DEFAULT_SORT,
        RESULT_SORT_FIELDS,
    },
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    nvt_payloads::{NvtEpssItem, nvt_epss_from_row, nvt_max_severity_from_row},
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
    report_helpers::raw_report_exists,
    report_payloads::{ReportReference, report_reference},
    row_helpers::{optional_row_string, optional_row_strings},
    user_tags::ReportUserTag,
};

#[derive(Debug, Serialize)]
struct ResultOverrideNvtReference {
    id: String,
    name: String,
    #[serde(rename = "type")]
    nvt_type: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ResultOverrideItem {
    id: String,
    nvt: ResultOverrideNvtReference,
    text: String,
    text_excerpt: bool,
    hosts: String,
    port: String,
    severity: Option<f64>,
    new_severity: Option<f64>,
    active: bool,
    end_time: Option<String>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ResultItem {
    id: String,
    host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_asset_id: Option<String>,
    hostname: Option<String>,
    port: String,
    nvt_oid: String,
    name: String,
    nvt_family: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cves: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cert_refs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    xrefs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_epss: Option<NvtEpssItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_severity: Option<NvtEpssItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    description_excerpt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    insight: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    affected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    impact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    solution_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    solution: Option<String>,
    severity: f64,
    qod: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    scan_nvt_version: Option<String>,
    created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<ReportReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<ReportReference>,
    source_report_id: String,
    raw_evidence_href: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) overrides: Vec<ResultOverrideItem>,
}

pub(crate) fn result_from_row(row: &Row) -> ResultItem {
    let id: String = row.get("id");
    let source_report_id: String = row.get("source_report_id");
    ResultItem {
        raw_evidence_href: format!("/result/{id}"),
        id,
        host: row.get("host"),
        host_asset_id: optional_row_string(row, "host_asset_id"),
        hostname: row.get("hostname"),
        port: row.get("port"),
        nvt_oid: row.get("nvt_oid"),
        name: row.get("name"),
        nvt_family: row.get("nvt_family"),
        cves: optional_row_strings(row, "cves"),
        cert_refs: optional_row_strings(row, "cert_refs"),
        xrefs: optional_row_strings(row, "xrefs"),
        max_epss: nvt_epss_from_row(row),
        max_severity: nvt_max_severity_from_row(row),
        description: optional_row_string(row, "description"),
        description_excerpt: row.get("description_excerpt"),
        summary: optional_row_string(row, "summary"),
        insight: optional_row_string(row, "insight"),
        affected: optional_row_string(row, "affected"),
        impact: optional_row_string(row, "impact"),
        detection: optional_row_string(row, "detection"),
        solution_type: optional_row_string(row, "solution_type"),
        solution: optional_row_string(row, "solution"),
        severity: row.get("severity"),
        qod: row.get("qod"),
        scan_nvt_version: optional_row_string(row, "scan_nvt_version"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        report: report_reference(
            optional_row_string(row, "source_report_id"),
            optional_row_string(row, "source_report_name"),
        ),
        task: report_reference(
            optional_row_string(row, "task_id"),
            optional_row_string(row, "task_name"),
        ),
        source_report_id,
        user_tags: Vec::new(),
        overrides: result_overrides_from_row(row),
    }
}

fn result_overrides_from_row(row: &Row) -> Vec<ResultOverrideItem> {
    let ids = optional_row_strings(row, "override_ids");
    let nvt_ids = optional_row_strings(row, "override_nvt_ids");
    let nvt_names = optional_row_strings(row, "override_nvt_names");
    let nvt_types = optional_row_strings(row, "override_nvt_types");
    let texts = optional_row_strings(row, "override_texts");
    let hosts = optional_row_strings(row, "override_hosts");
    let ports = optional_row_strings(row, "override_ports");
    let severities = row
        .try_get::<_, Vec<Option<f64>>>("override_severities")
        .unwrap_or_default();
    let new_severities = row
        .try_get::<_, Vec<Option<f64>>>("override_new_severities")
        .unwrap_or_default();
    let created_at = row
        .try_get::<_, Vec<i64>>("override_created_at_unix")
        .unwrap_or_default();
    let modified_at = row
        .try_get::<_, Vec<i64>>("override_modified_at_unix")
        .unwrap_or_default();
    let end_times = row
        .try_get::<_, Vec<i64>>("override_end_time_unix")
        .unwrap_or_default();
    let active_ints = row
        .try_get::<_, Vec<i32>>("override_active_ints")
        .unwrap_or_default();

    ids.into_iter()
        .enumerate()
        .map(|(index, id)| ResultOverrideItem {
            id,
            nvt: ResultOverrideNvtReference {
                id: nvt_ids.get(index).cloned().unwrap_or_default(),
                name: nvt_names.get(index).cloned().unwrap_or_default(),
                nvt_type: nvt_types
                    .get(index)
                    .cloned()
                    .unwrap_or_else(|| "nvt".to_string()),
            },
            text: texts.get(index).cloned().unwrap_or_default(),
            text_excerpt: false,
            hosts: hosts.get(index).cloned().unwrap_or_default(),
            port: ports.get(index).cloned().unwrap_or_default(),
            severity: severities.get(index).copied().unwrap_or(None),
            new_severity: new_severities.get(index).copied().unwrap_or(None),
            active: active_ints.get(index).copied().unwrap_or_default() != 0,
            end_time: unix_ts_to_rfc3339(end_times.get(index).copied().unwrap_or_default()),
            created_at: unix_ts_to_rfc3339(created_at.get(index).copied().unwrap_or_default()),
            modified_at: unix_ts_to_rfc3339(modified_at.get(index).copied().unwrap_or_default()),
        })
        .collect()
}

pub(crate) fn result_override_from_row(row: &Row) -> ResultOverrideItem {
    ResultOverrideItem {
        id: row.get("id"),
        nvt: ResultOverrideNvtReference {
            id: row.get("nvt_id"),
            name: row.get("nvt_name"),
            nvt_type: row.get("nvt_type"),
        },
        text: row.get("text"),
        text_excerpt: false,
        hosts: row.get("hosts"),
        port: row.get("port"),
        severity: row.get("severity"),
        new_severity: row.get("new_severity"),
        active: row.get::<_, i32>("active_int") != 0,
        end_time: unix_ts_to_rfc3339(row.get("end_time_unix")),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) async fn results(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ResultItem>>, ApiError> {
    let params = normalize_collection_query(query, RESULT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, RESULT_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH result_rows AS (
             SELECT r.uuid AS id,
                    r.id AS result_internal_id,
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,
                    h.uuid AS host_asset_id,
                    nullif(r.hostname, '') AS hostname,
                    coalesce(r.port, '') AS port,
                    coalesce(r.nvt, '') AS nvt_oid,
                    coalesce(n.name, r.nvt, '') AS name,
                    nullif(n.family, '') AS nvt_family,
                    n.cve AS cve_text,
                    n.epss_score::double precision AS epss_score,
                    n.epss_percentile::double precision AS epss_percentile,
                    n.epss_cve AS epss_cve,
                    n.epss_severity::double precision AS epss_severity,
                    n.max_epss_score::double precision AS max_epss_score,
                    n.max_epss_percentile::double precision AS max_epss_percentile,
                    n.max_epss_cve AS max_epss_cve,
                    n.max_epss_severity::double precision AS max_epss_severity,
                    nullif(left(coalesce(r.description, ''), 240), '') AS description_excerpt,
                    nullif(n.solution_type, '') AS solution_type,
                    nullif(n.solution, '') AS solution,
                    coalesce(r.severity, 0)::double precision AS severity,
                    coalesce(r.qod, 0)::bigint AS qod,
                    nullif(r.nvt_version, '') AS scan_nvt_version,
                    coalesce(r.date, 0)::bigint AS created_at_unix,
                    rep.uuid AS source_report_id,
                    coalesce(nullif(t.name, ''), rep.uuid) AS source_report_name,
                    t.uuid AS task_id,
                    t.name AS task_name
               FROM results r
               JOIN reports rep ON rep.id = r.report
               LEFT JOIN tasks t ON t.id = coalesce(r.task, rep.task)
               LEFT JOIN hosts h ON lower(h.name) = lower(coalesce(nullif(r.host, ''), r.hostname, ''))
               LEFT JOIN nvts n ON n.oid = r.nvt
              WHERE coalesce(r.severity, 0) != -3.0
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''
                AND (t.id IS NULL OR coalesce(t.usage_type, 'scan') = 'scan')
         ),
         filtered AS (
             SELECT * FROM result_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(host) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(hostname, '')) LIKE '%' || lower($1) || '%'
                     OR lower(port) LIKE '%' || lower($1) || '%'
                     OR lower(nvt_oid) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(coalesce(task_name, '')) LIKE '%' || lower($1) || '%'
                     OR lower(source_report_name) LIKE '%' || lower($1) || '%')
         ),
         page_rows AS (
             SELECT count(*) OVER()::bigint AS total, * FROM filtered
              ORDER BY {sort_sql}, created_at_unix DESC, id ASC LIMIT $2 OFFSET $3
         ),
         page_with_refs AS (
             SELECT p.*,
                    CASE
                      WHEN cardinality(coalesce(refs.cves, ARRAY[]::text[])) > 0
                      THEN refs.cves
                      WHEN coalesce(p.cve_text, '') <> ''
                      THEN regexp_split_to_array(p.cve_text, '\\s*,\\s*')
                      ELSE ARRAY[]::text[]
                    END AS cves,
                    coalesce(refs.cert_refs, ARRAY[]::text[]) AS cert_refs,
                    coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs,
                    coalesce(active_overrides.override_ids, ARRAY[]::text[]) AS override_ids,
                    coalesce(active_overrides.override_nvt_ids, ARRAY[]::text[]) AS override_nvt_ids,
                    coalesce(active_overrides.override_nvt_names, ARRAY[]::text[]) AS override_nvt_names,
                    coalesce(active_overrides.override_nvt_types, ARRAY[]::text[]) AS override_nvt_types,
                    coalesce(active_overrides.override_texts, ARRAY[]::text[]) AS override_texts,
                    coalesce(active_overrides.override_hosts, ARRAY[]::text[]) AS override_hosts,
                    coalesce(active_overrides.override_ports, ARRAY[]::text[]) AS override_ports,
                    coalesce(active_overrides.override_severities, ARRAY[]::double precision[]) AS override_severities,
                    coalesce(active_overrides.override_new_severities, ARRAY[]::double precision[]) AS override_new_severities,
                    coalesce(active_overrides.override_created_at_unix, ARRAY[]::bigint[]) AS override_created_at_unix,
                    coalesce(active_overrides.override_modified_at_unix, ARRAY[]::bigint[]) AS override_modified_at_unix,
                    coalesce(active_overrides.override_end_time_unix, ARRAY[]::bigint[]) AS override_end_time_unix,
                    coalesce(active_overrides.override_active_ints, ARRAY[]::integer[]) AS override_active_ints
               FROM page_rows p
               LEFT JOIN LATERAL (
                   SELECT array_agg(vr.ref_id::text ORDER BY vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) IN ('cve', 'cve_id')) AS cves,
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) IN ('dfn-cert', 'cert-bund')) AS cert_refs,
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                            FILTER (WHERE vr.ref_id IS NOT NULL
                                    AND lower(vr.type) NOT IN ('cve', 'cve_id', 'dfn-cert', 'cert-bund')) AS xrefs
                     FROM vt_refs vr
                    WHERE vr.vt_oid = p.nvt_oid
               ) refs ON true
               LEFT JOIN LATERAL (
                   SELECT array_agg(m.id ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_ids,
                          array_agg(m.nvt_id ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_nvt_ids,
                          array_agg(m.nvt_name ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_nvt_names,
                          array_agg(m.nvt_type ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_nvt_types,
                          array_agg(m.text ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_texts,
                          array_agg(m.hosts ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_hosts,
                          array_agg(m.port ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_ports,
                          array_agg(m.severity ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_severities,
                          array_agg(m.new_severity ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_new_severities,
                          array_agg(m.created_at_unix ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_created_at_unix,
                          array_agg(m.modified_at_unix ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_modified_at_unix,
                          array_agg(m.end_time_unix ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_end_time_unix,
                          array_agg(m.active_int ORDER BY m.modified_at_unix DESC, m.created_at_unix DESC, m.id ASC) AS override_active_ints
                     FROM (
                         SELECT DISTINCT ON (o.id)
                                o.uuid AS id,
                                coalesce(o.nvt, '') AS nvt_id,
                                CASE
                                  WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN coalesce(o.nvt, '')
                                  ELSE coalesce(n.name, o.nvt, '')
                                END AS nvt_name,
                                CASE
                                  WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN 'cve'
                                  ELSE 'nvt'
                                END AS nvt_type,
                                coalesce(o.text, '') AS text,
                                coalesce(o.hosts, '') AS hosts,
                                coalesce(o.port, '') AS port,
                                o.severity::double precision AS severity,
                                o.new_severity::double precision AS new_severity,
                                coalesce(o.creation_time, 0)::bigint AS created_at_unix,
                                coalesce(o.modification_time, 0)::bigint AS modified_at_unix,
                                coalesce(o.end_time, 0)::bigint AS end_time_unix,
                                CAST (((coalesce(o.end_time, 0) = 0) OR (coalesce(o.end_time, 0) >= m_now())) AS integer) AS active_int
                           FROM result_overrides ro
                           JOIN overrides o ON o.id = ro.override
                      LEFT JOIN nvts n ON n.oid = o.nvt
                          WHERE ro.result = p.result_internal_id
                          ORDER BY o.id, coalesce(o.modification_time, o.creation_time, 0) DESC, o.uuid ASC
                     ) m
               ) active_overrides ON true
         )
         SELECT * FROM page_with_refs;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "result list query failed");
            ApiError::Database
        })?;
    let total =
        collection_total_with_empty_page_probe(&client, &rows, &sql, &params, "result list")
            .await?;
    let items = rows.iter().map(result_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn result_detail(
    State(state): State<AppState>,
    Path(result_id): Path<String>,
) -> Result<Json<ResultItem>, ApiError> {
    parse_uuid(&result_id)?;
    let sql = r#"SELECT r.uuid AS id,
                         lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,
                         h.uuid AS host_asset_id,
                         nullif(r.hostname, '') AS hostname,
                         coalesce(r.port, '') AS port,
                         coalesce(r.nvt, '') AS nvt_oid,
                         coalesce(n.name, r.nvt, '') AS name,
                         nullif(n.family, '') AS nvt_family,
                         n.epss_score::double precision AS epss_score,
                         n.epss_percentile::double precision AS epss_percentile,
                         n.epss_cve AS epss_cve,
                         n.epss_severity::double precision AS epss_severity,
                         n.max_epss_score::double precision AS max_epss_score,
                         n.max_epss_percentile::double precision AS max_epss_percentile,
                         n.max_epss_cve AS max_epss_cve,
                         n.max_epss_severity::double precision AS max_epss_severity,
                         CASE
                           WHEN cardinality(coalesce(refs.cves, ARRAY[]::text[])) > 0
                           THEN refs.cves
                           WHEN coalesce(n.cve, '') <> ''
                           THEN regexp_split_to_array(n.cve, '\\s*,\\s*')
                           ELSE ARRAY[]::text[]
                         END AS cves,
                         coalesce(refs.cert_refs, ARRAY[]::text[]) AS cert_refs,
                         coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs,
                         nullif(r.description, '') AS description,
                         nullif(left(coalesce(r.description, ''), 240), '') AS description_excerpt,
                         nullif(n.summary, '') AS summary,
                         nullif(n.insight, '') AS insight,
                         nullif(n.affected, '') AS affected,
                         nullif(n.impact, '') AS impact,
                         nullif(n.detection, '') AS detection,
                         nullif(n.solution_type, '') AS solution_type,
                         nullif(n.solution, '') AS solution,
                         coalesce(r.severity, 0)::double precision AS severity,
                         coalesce(r.qod, 0)::bigint AS qod,
                         nullif(r.nvt_version, '') AS scan_nvt_version,
                         coalesce(r.date, 0)::bigint AS created_at_unix,
                         rep.uuid AS source_report_id,
                         coalesce(nullif(t.name, ''), rep.uuid) AS source_report_name,
                         t.uuid AS task_id,
                         t.name AS task_name
                    FROM results r
                    JOIN reports rep ON rep.id = r.report
                    LEFT JOIN tasks t ON t.id = coalesce(r.task, rep.task)
                    LEFT JOIN hosts h ON lower(h.name) = lower(coalesce(nullif(r.host, ''), r.hostname, ''))
                    LEFT JOIN nvts n ON n.oid = r.nvt
                    LEFT JOIN LATERAL (
                        SELECT array_agg(vr.ref_id::text ORDER BY vr.ref_id)
                                 FILTER (WHERE vr.ref_id IS NOT NULL
                                         AND lower(vr.type) IN ('cve', 'cve_id')) AS cves,
                               array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                                 FILTER (WHERE vr.ref_id IS NOT NULL
                                         AND lower(vr.type) IN ('dfn-cert', 'cert-bund')) AS cert_refs,
                               array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)
                                 FILTER (WHERE vr.ref_id IS NOT NULL
                                         AND lower(vr.type) NOT IN ('cve', 'cve_id', 'dfn-cert', 'cert-bund')) AS xrefs
                          FROM vt_refs vr
                         WHERE vr.vt_oid = r.nvt
                    ) refs ON true
                   WHERE lower(r.uuid) = lower($1)
                     AND coalesce(r.severity, 0) != -3.0
                     AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''
                     AND (t.id IS NULL OR coalesce(t.usage_type, 'scan') = 'scan')
                   LIMIT 1;"#;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(sql, &[&result_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "result detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let mut item = result_from_row(&row);
    item.user_tags = result_user_tags(&client, &result_id).await?;
    item.overrides = result_effective_overrides(&client, &result_id).await?;
    Ok(Json(item))
}

async fn result_user_tags(
    client: &tokio_postgres::Client,
    result_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(
            r#"SELECT t.uuid AS id,
                      coalesce(t.name, '') AS name,
                      coalesce(t.value, '') AS value,
                      coalesce(t.comment, '') AS comment
                 FROM tags t
                 JOIN tag_resources tr ON tr.tag = t.id
                 JOIN results r ON r.id = tr.resource
                WHERE lower(r.uuid) = lower($1)
                  AND tr.resource_type = 'result'
                  AND tr.resource_location = 0
                  AND coalesce(t.active, 0) = 1
                ORDER BY t.name ASC, t.uuid ASC;"#,
            &[&result_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "result user-tag query failed");
            ApiError::Database
        })?;
    Ok(rows
        .iter()
        .map(|row| ReportUserTag {
            id: row.get("id"),
            name: row.get("name"),
            value: row.get("value"),
            comment: row.get("comment"),
        })
        .collect())
}

async fn result_effective_overrides(
    client: &tokio_postgres::Client,
    result_id: &str,
) -> Result<Vec<ResultOverrideItem>, ApiError> {
    let rows = client
        .query(
            r#"WITH matched AS (
                 SELECT DISTINCT ON (o.id)
                        o.uuid AS id,
                        coalesce(o.nvt, '') AS nvt_id,
                        CASE
                          WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN coalesce(o.nvt, '')
                          ELSE coalesce(n.name, o.nvt, '')
                        END AS nvt_name,
                        CASE
                          WHEN coalesce(o.nvt, '') LIKE 'CVE-%' THEN 'cve'
                          ELSE 'nvt'
                        END AS nvt_type,
                        coalesce(o.text, '') AS text,
                        coalesce(o.hosts, '') AS hosts,
                        coalesce(o.port, '') AS port,
                        o.severity::double precision AS severity,
                        o.new_severity::double precision AS new_severity,
                        coalesce(o.creation_time, 0)::bigint AS created_at_unix,
                        coalesce(o.modification_time, 0)::bigint AS modified_at_unix,
                        coalesce(o.end_time, 0)::bigint AS end_time_unix,
                        CAST (((coalesce(o.end_time, 0) = 0) OR (coalesce(o.end_time, 0) >= m_now())) AS integer) AS active_int
                   FROM result_overrides ro
                   JOIN results r ON r.id = ro.result
                   JOIN overrides o ON o.id = ro.override
              LEFT JOIN nvts n ON n.oid = o.nvt
                  WHERE lower(r.uuid) = lower($1)
                  ORDER BY o.id, coalesce(o.modification_time, o.creation_time, 0) DESC, o.uuid ASC
             )
             SELECT * FROM matched
              ORDER BY modified_at_unix DESC, created_at_unix DESC, id ASC;"#,
            &[&result_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "result effective-override query failed");
            ApiError::Database
        })?;
    Ok(rows.iter().map(result_override_from_row).collect())
}

pub(crate) async fn report_results(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ResultItem>>, ApiError> {
    parse_uuid(&report_id)?;
    let params = normalize_collection_query(query, REPORT_RESULT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_RESULT_SORT_FIELDS)?;
    let sql = format!(
        "WITH selected_report AS (\n\
             SELECT id, uuid FROM reports WHERE lower(uuid) = lower($1)\n\
         ),\n\
         result_rows AS (\n\
             SELECT r.uuid AS id,\n\
                    lower(coalesce(nullif(r.host, ''), r.hostname, '')) AS host,\n\
                    nullif(r.hostname, '') AS hostname,\n\
                    coalesce(r.port, '') AS port,\n\
                    coalesce(r.nvt, '') AS nvt_oid,\n\
                    coalesce(n.name, r.nvt, '') AS name,\n\
                    nullif(n.family, '') AS nvt_family,\n\
                    n.cve AS cve_text,\n\
                    n.epss_score::double precision AS epss_score,\n\
                    n.epss_percentile::double precision AS epss_percentile,\n\
                    n.epss_cve AS epss_cve,\n\
                    n.epss_severity::double precision AS epss_severity,\n\
                    n.max_epss_score::double precision AS max_epss_score,\n\
                    n.max_epss_percentile::double precision AS max_epss_percentile,\n\
                    n.max_epss_cve AS max_epss_cve,\n\
                    n.max_epss_severity::double precision AS max_epss_severity,\n\
                    nullif(left(coalesce(r.description, ''), 240), '') AS description_excerpt,\n\
                    coalesce(r.severity, 0)::double precision AS severity,\n\
                    coalesce(r.qod, 0)::bigint AS qod,\n\
                    coalesce(r.date, 0)::bigint AS created_at_unix,\n\
                    sr.uuid AS source_report_id\n\
               FROM selected_report sr\n\
               JOIN results r ON r.report = sr.id\n\
               LEFT JOIN nvts n ON n.oid = r.nvt\n\
              WHERE coalesce(r.severity, 0) != -3.0\n\
                AND coalesce(nullif(r.host, ''), r.hostname, '') <> ''\n\
         ),\n\
         filtered AS (\n\
             SELECT * FROM result_rows\n\
              WHERE ($2 = ''\n\
                     OR lower(id) LIKE '%' || lower($2) || '%'\n\
                     OR lower(host) LIKE '%' || lower($2) || '%'\n\
                     OR lower(port) LIKE '%' || lower($2) || '%'\n\
                     OR lower(nvt_oid) LIKE '%' || lower($2) || '%'\n\
                     OR lower(name) LIKE '%' || lower($2) || '%')\n\
         ),\n\
         page_rows AS (\n\
             SELECT count(*) OVER()::bigint AS total, * FROM filtered\n\
              ORDER BY {sort_sql}, created_at_unix DESC, id ASC LIMIT $3 OFFSET $4\n\
         ),\n\
         page_with_refs AS (\n\
             SELECT p.*,\n\
                    CASE\n\
                      WHEN cardinality(coalesce(refs.cves, ARRAY[]::text[])) > 0\n\
                      THEN refs.cves\n\
                      WHEN coalesce(p.cve_text, '') <> ''\n\
                      THEN regexp_split_to_array(p.cve_text, '\\s*,\\s*')\n\
                      ELSE ARRAY[]::text[]\n\
                    END AS cves,\n\
                    coalesce(refs.cert_refs, ARRAY[]::text[]) AS cert_refs,\n\
                    coalesce(refs.xrefs, ARRAY[]::text[]) AS xrefs\n\
               FROM page_rows p\n\
               LEFT JOIN LATERAL (\n\
                   SELECT array_agg(vr.ref_id::text ORDER BY vr.ref_id)\n\
                            FILTER (WHERE vr.ref_id IS NOT NULL\n\
                                    AND lower(vr.type) IN ('cve', 'cve_id')) AS cves,\n\
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)\n\
                            FILTER (WHERE vr.ref_id IS NOT NULL\n\
                                    AND lower(vr.type) IN ('dfn-cert', 'cert-bund')) AS cert_refs,\n\
                          array_agg(lower(vr.type) || ':' || vr.ref_id::text ORDER BY lower(vr.type), vr.ref_id)\n\
                            FILTER (WHERE vr.ref_id IS NOT NULL\n\
                                    AND lower(vr.type) NOT IN ('cve', 'cve_id', 'dfn-cert', 'cert-bund')) AS xrefs\n\
                     FROM vt_refs vr\n\
                    WHERE vr.vt_oid = p.nvt_oid\n\
               ) refs ON true\n\
         )\n\
         SELECT * FROM page_with_refs;"
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &report_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "raw report result query failed");
            ApiError::Database
        })?;
    if rows.is_empty() && !raw_report_exists(&client, &report_id).await? {
        return Err(ApiError::NotFound);
    }
    let total = rows.first().map(|row| row.get::<_, i64>(0)).unwrap_or(0);
    let items = rows.iter().map(result_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}
