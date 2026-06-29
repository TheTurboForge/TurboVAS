// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use axum::{
    Json,
    extract::{Path, State},
};

use crate::{
    app_state::AppState,
    collections::{SCHEDULE_DEFAULT_SORT, SCHEDULE_SORT_FIELDS},
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    user_tags::ReportUserTag,
};

#[derive(Serialize)]
pub(crate) struct ScheduleTaskReference {
    id: String,
    name: String,
    usage_type: String,
}

#[derive(Serialize)]
pub(crate) struct ScheduleAssetItem {
    id: String,
    name: String,
    comment: String,
    icalendar: String,
    timezone: String,
    timezone_abbrev: Option<String>,
    task_count: i64,
    tasks: Vec<ScheduleTaskReference>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct ScheduleAssetDetail {
    #[serde(flatten)]
    asset: ScheduleAssetItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_tags: Vec<ReportUserTag>,
}

pub(crate) fn schedule_task_from_row(row: &Row) -> ScheduleTaskReference {
    ScheduleTaskReference {
        id: row.get("id"),
        name: row.get("name"),
        usage_type: row.get("usage_type"),
    }
}

pub(crate) fn schedule_asset_from_row(
    row: &Row,
    tasks: Vec<ScheduleTaskReference>,
) -> ScheduleAssetItem {
    ScheduleAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        icalendar: row.get("icalendar"),
        timezone: row.get("timezone"),
        timezone_abbrev: None,
        task_count: row.get("task_count"),
        tasks,
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn schedule_asset_detail_payload(
    asset: ScheduleAssetItem,
    user_tags: Vec<ReportUserTag>,
) -> ScheduleAssetDetail {
    ScheduleAssetDetail { asset, user_tags }
}

pub(crate) async fn schedule_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<ScheduleAssetItem>>, ApiError> {
    let params = normalize_collection_query(query, SCHEDULE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, SCHEDULE_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH schedule_rows AS (
             SELECT s.id AS internal_id,
                    s.uuid AS id,
                    coalesce(s.name, '') AS name,
                    coalesce(s.comment, '') AS comment,
                    coalesce(s.icalendar, '') AS icalendar,
                    coalesce(s.timezone, 'UTC') AS timezone,
                    coalesce(s.first_time, 0)::bigint AS first_run_unix,
                    coalesce(next_time_ical(s.icalendar, m_now()::bigint, coalesce(s.timezone, 'UTC')), 0)::bigint AS next_run_unix,
                    coalesce(s.period, 0)::bigint AS period_seconds,
                    coalesce(s.duration, 0)::bigint AS duration_seconds,
                    coalesce(s.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(s.modification_time, 0)::bigint AS modified_at_unix,
                    coalesce((
                      SELECT count(*)::bigint
                        FROM tasks t
                       WHERE t.schedule = s.id
                         AND t.hidden = 0
                    ), 0)::bigint AS task_count
               FROM schedules s
         ),
         filtered AS (
             SELECT * FROM schedule_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(timezone) LIKE '%' || lower($1) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(&sql, &[&params.filter, &params.page_size, &params.offset])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "schedule asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows
        .iter()
        .map(|row| schedule_asset_from_row(row, Vec::new()))
        .collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn schedule_asset_detail(
    State(state): State<AppState>,
    Path(schedule_id): Path<String>,
) -> Result<Json<ScheduleAssetDetail>, ApiError> {
    parse_uuid(&schedule_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT s.id AS internal_id,
                      s.uuid AS id,
                      coalesce(s.name, '') AS name,
                      coalesce(s.comment, '') AS comment,
                      coalesce(s.icalendar, '') AS icalendar,
                      coalesce(s.timezone, 'UTC') AS timezone,
                      coalesce(s.first_time, 0)::bigint AS first_run_unix,
                      coalesce(next_time_ical(s.icalendar, m_now()::bigint, coalesce(s.timezone, 'UTC')), 0)::bigint AS next_run_unix,
                      coalesce(s.period, 0)::bigint AS period_seconds,
                      coalesce(s.duration, 0)::bigint AS duration_seconds,
                      coalesce(s.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(s.modification_time, 0)::bigint AS modified_at_unix,
                      coalesce((
                        SELECT count(*)::bigint
                          FROM tasks t
                         WHERE t.schedule = s.id
                           AND t.hidden = 0
                      ), 0)::bigint AS task_count
                 FROM schedules s
                WHERE s.uuid = $1
                LIMIT 1;"#,
            &[&schedule_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "schedule asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let internal_id: i32 = row.get("internal_id");
    let tasks = client
        .query(
            r#"SELECT t.uuid AS id,
                      coalesce(t.name, '') AS name,
                      coalesce(t.usage_type, 'scan') AS usage_type
                 FROM tasks t
                WHERE t.schedule = $1
                  AND t.hidden = 0
                ORDER BY name ASC, id ASC;"#,
            &[&internal_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "schedule task backlink query failed");
            ApiError::Database
        })?
        .iter()
        .map(schedule_task_from_row)
        .collect();
    let user_tags = schedule_user_tags(&client, &schedule_id).await?;
    Ok(Json(schedule_asset_detail_payload(
        schedule_asset_from_row(&row, tasks),
        user_tags,
    )))
}

pub(crate) fn schedule_user_tags_sql() -> &'static str {
    r#"SELECT t.uuid AS id,
              coalesce(t.name, '') AS name,
              coalesce(t.value, '') AS value,
              coalesce(t.comment, '') AS comment
         FROM tags t
         JOIN tag_resources tr ON tr.tag = t.id
         JOIN schedules s ON s.id = tr.resource
        WHERE lower(s.uuid) = lower($1)
          AND tr.resource_type = 'schedule'
          AND tr.resource_location = 0
          AND coalesce(t.active, 0) = 1
        ORDER BY t.name ASC, t.uuid ASC;"#
}

async fn schedule_user_tags(
    client: &tokio_postgres::Client,
    schedule_id: &str,
) -> Result<Vec<ReportUserTag>, ApiError> {
    let rows = client
        .query(schedule_user_tags_sql(), &[&schedule_id])
        .await
        .map_err(|error| {
            tracing::warn!(%error, "schedule user-tag query failed");
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
