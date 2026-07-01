// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{REPORT_FORMAT_DEFAULT_SORT, REPORT_FORMAT_SORT_FIELDS},
    errors::ApiError,
    path_ids::parse_uuid,
    query::{
        ApiQuery, Collection, CollectionQuery, collection_total_with_empty_page_probe,
        normalize_collection_query, sort_clause,
    },
    report_format_payloads::{
        ReportFormatAssetItem, report_format_asset_from_row, report_format_param_from_row,
        report_format_param_option_from_row, report_format_reference_from_row,
    },
};

pub(crate) async fn report_format_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ReportFormatAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, REPORT_FORMAT_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, REPORT_FORMAT_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH report_format_rows AS (
             SELECT rf.id AS internal_id,
                    rf.uuid AS id,
                    coalesce(rf.name, '') AS name,
                    coalesce(rf.summary, '') AS summary,
                    coalesce(rf.description, '') AS description,
                    coalesce(rf.extension, '') AS extension,
                    coalesce(rf.content_type, '') AS content_type,
                    coalesce(rf.report_type, '') AS report_type,
                    coalesce(rf.trust, 3)::integer AS trust_int,
                    coalesce(rf.trust_time, 0)::bigint AS trust_time_unix,
                    coalesce(rf.flags & 1, 0)::integer AS active_int,
                    coalesce(rf.predefined, 0)::integer AS predefined_int,
                    (SELECT count(*) > 0 FROM report_format_params rfp WHERE rfp.report_format = rf.id)::integer AS configurable_int,
                    (SELECT count(*) FROM deprecated_feed_data dfd WHERE dfd.type = 'report_format' AND dfd.uuid = rf.uuid)::integer AS deprecated_int,
                    coalesce((SELECT count(DISTINCT a.id)::bigint
                                FROM alerts a
                                JOIN alert_method_data amd ON amd.alert = a.id
                               WHERE amd.data = rf.uuid), 0)::bigint AS alert_count,
                    coalesce((SELECT count(DISTINCT rc.id)::bigint
                                FROM report_configs rc
                               WHERE rc.report_format_id = rf.uuid), 0)::bigint AS report_config_count,
                    coalesce(rf.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(rf.modification_time, 0)::bigint AS modified_at_unix
               FROM report_formats rf
         ),
         filtered AS (
             SELECT * FROM report_format_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(summary) LIKE '%' || lower($1) || '%'
                     OR lower(extension) LIKE '%' || lower($1) || '%'
                     OR lower(content_type) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format asset list query failed");
            ApiError::Database
        })?;
    let total = collection_total_with_empty_page_probe(
        &client,
        &rows,
        &sql,
        &params,
        "report format asset list",
    )
    .await?;
    let items = rows
        .iter()
        .map(|row| report_format_asset_from_row(row, Vec::new(), Vec::new(), Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn report_format_asset_detail(
    State(state): State<AppState>,
    Path(report_format_id): Path<String>,
) -> Result<Json<ReportFormatAssetItem>, ApiError> {
    parse_uuid(&report_format_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT rf.id AS internal_id,
                      rf.uuid AS id,
                      coalesce(rf.name, '') AS name,
                      coalesce(rf.summary, '') AS summary,
                      coalesce(rf.description, '') AS description,
                      coalesce(rf.extension, '') AS extension,
                      coalesce(rf.content_type, '') AS content_type,
                      coalesce(rf.report_type, '') AS report_type,
                      coalesce(rf.trust, 3)::integer AS trust_int,
                      coalesce(rf.trust_time, 0)::bigint AS trust_time_unix,
                      coalesce(rf.flags & 1, 0)::integer AS active_int,
                      coalesce(rf.predefined, 0)::integer AS predefined_int,
                      (SELECT count(*) > 0 FROM report_format_params rfp WHERE rfp.report_format = rf.id)::integer AS configurable_int,
                      (SELECT count(*) FROM deprecated_feed_data dfd WHERE dfd.type = 'report_format' AND dfd.uuid = rf.uuid)::integer AS deprecated_int,
                      coalesce((SELECT count(DISTINCT a.id)::bigint
                                  FROM alerts a
                                  JOIN alert_method_data amd ON amd.alert = a.id
                                 WHERE amd.data = rf.uuid), 0)::bigint AS alert_count,
                      coalesce((SELECT count(DISTINCT rc.id)::bigint
                                  FROM report_configs rc
                                 WHERE rc.report_format_id = rf.uuid), 0)::bigint AS report_config_count,
                      coalesce(rf.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(rf.modification_time, 0)::bigint AS modified_at_unix
                 FROM report_formats rf
                WHERE rf.uuid = $1
                LIMIT 1;"#,
            &[&report_format_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = row.get("internal_id");
    let alerts = client
        .query(
            r#"SELECT a.uuid AS id,
                      coalesce(a.name, '') AS name
                 FROM alerts a
                 JOIN alert_method_data amd ON amd.alert = a.id
                WHERE amd.data = $1
                ORDER BY name ASC, id ASC;"#,
            &[&report_format_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format alert backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(report_format_reference_from_row)
        .collect();
    let report_configs = client
        .query(
            r#"SELECT rc.uuid AS id,
                      coalesce(rc.name, '') AS name
                 FROM report_configs rc
                WHERE rc.report_format_id = $1
                ORDER BY name ASC, id ASC;"#,
            &[&report_format_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format config backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(report_format_reference_from_row)
        .collect();
    let mut params = Vec::new();
    for param_row in client
        .query(
            r#"SELECT rfp.id AS internal_id,
                      coalesce(rfp.name, '') AS name,
                      coalesce(rfp.type, 100)::integer AS type_int,
                      coalesce(rfp.value, '') AS value,
                      coalesce(rfp.fallback, '') AS fallback,
                      rfp.type_min AS min,
                      rfp.type_max AS max
                 FROM report_format_params rfp
                WHERE rfp.report_format = $1
                ORDER BY name ASC, internal_id ASC;"#,
            &[&internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "report format params query failed");
            ApiError::Database
        })?
    {
        let param_id: i32 = param_row.get("internal_id");
        let options = client
            .query(
                r#"SELECT coalesce(value, '') AS value
                     FROM report_format_param_options
                    WHERE report_format_param = $1
                    ORDER BY value ASC;"#,
                &[&param_id],
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "report format param options query failed");
                ApiError::Database
            })?
            .iter()
            .map(report_format_param_option_from_row)
            .collect();
        params.push(report_format_param_from_row(&param_row, options));
    }

    Ok(Json(report_format_asset_from_row(
        &row,
        alerts,
        report_configs,
        params,
    )))
}

pub(crate) async fn export_report_format_metadata(
    state: State<AppState>,
    path: Path<String>,
) -> Result<Json<ReportFormatAssetItem>, ApiError> {
    report_format_asset_detail(state, path).await
}
