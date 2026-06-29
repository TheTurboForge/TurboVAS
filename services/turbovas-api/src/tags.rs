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
    PageInfo,
    app_state::AppState,
    collections::{
        TAG_DEFAULT_SORT, TAG_RESOURCE_DEFAULT_SORT, TAG_RESOURCE_NAME_MAX_PAGE_SIZE,
        TAG_RESOURCE_SORT_FIELDS, TAG_SORT_FIELDS,
    },
    errors::ApiError,
    formatters::unix_ts_to_rfc3339,
    path_ids::parse_uuid,
    query::{ApiQuery, Collection, CollectionQuery, normalize_collection_query, sort_clause},
    tag_resource_helpers::{
        normalize_tag_resource_type, tag_resource_collection_sql, tag_resource_name_collection_sql,
        tag_resource_name_filter,
    },
};

#[derive(Serialize)]
pub(crate) struct TagOwner {
    name: String,
}

#[derive(Serialize)]
pub(crate) struct TagResourceCount {
    total: i64,
}

#[derive(Serialize)]
pub(crate) struct TagResourcesSummary {
    #[serde(rename = "type")]
    resource_type: String,
    count: TagResourceCount,
}

#[derive(Serialize)]
pub(crate) struct TagAssetItem {
    id: String,
    name: String,
    comment: String,
    owner: TagOwner,
    resource_type: String,
    resource_count: i64,
    resources: TagResourcesSummary,
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    writable: bool,
    in_use: bool,
    orphan: bool,
    trash: bool,
    permissions: Vec<String>,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct TagResourceItem {
    id: String,
    #[serde(rename = "type")]
    resource_type: String,
    name: String,
}

#[derive(Serialize)]
pub(crate) struct TagResourceCollection {
    pub(crate) tag_id: String,
    pub(crate) resource_type: String,
    pub(crate) page: PageInfo,
    pub(crate) items: Vec<TagResourceItem>,
}

pub(crate) fn tag_asset_from_row(row: &Row) -> TagAssetItem {
    let resource_type: String = row.get("resource_type");
    let resource_count: i64 = row.get("resource_count");
    let raw_value: String = row.get("value");
    let value = if raw_value.trim().is_empty() {
        None
    } else {
        Some(raw_value)
    };
    TagAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        owner: TagOwner {
            name: row.get("owner_name"),
        },
        resource_type: resource_type.clone(),
        resource_count,
        resources: TagResourcesSummary {
            resource_type,
            count: TagResourceCount {
                total: resource_count,
            },
        },
        active: row.get::<_, i32>("active_int") != 0,
        value,
        writable: true,
        in_use: false,
        orphan: false,
        trash: false,
        permissions: vec![
            "get_tags".to_string(),
            "modify_tag".to_string(),
            "delete_tag".to_string(),
            "create_tag".to_string(),
        ],
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}

pub(crate) fn tag_resource_from_row(row: &Row) -> TagResourceItem {
    TagResourceItem {
        id: row.get("id"),
        resource_type: row.get("resource_type"),
        name: row.get("name"),
    }
}

pub(crate) async fn tag_assets(
    State(state): State<AppState>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TagAssetItem>>, ApiError> {
    let active_filter = query.active.clone().unwrap_or_default();
    let resource_type_filter = query.resource_type.clone().unwrap_or_default();
    let value_filter = query.value.clone().unwrap_or_default();
    let params = normalize_collection_query(query, TAG_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TAG_SORT_FIELDS)?;
    let sql = format!(
        r#"WITH tag_rows AS (
             SELECT t.uuid AS id,
                    coalesce(t.name, '') AS name,
                    coalesce(t.comment, '') AS comment,
                    coalesce(u.name, '') AS owner_name,
                    coalesce(t.resource_type, '') AS resource_type,
                    coalesce(tag_resources_count(t.id, t.resource_type), 0)::bigint AS resource_count,
                    coalesce(t.active, 0)::integer AS active_int,
                    coalesce(t.value, '') AS value,
                    coalesce(t.creation_time, 0)::bigint AS created_at_unix,
                    coalesce(t.modification_time, 0)::bigint AS modified_at_unix
               FROM tags t
          LEFT JOIN users u ON u.id = t.owner
         ),
         filtered AS (
             SELECT * FROM tag_rows
              WHERE ($1 = ''
                     OR lower(id) LIKE '%' || lower($1) || '%'
                     OR lower(name) LIKE '%' || lower($1) || '%'
                     OR lower(comment) LIKE '%' || lower($1) || '%'
                     OR lower(owner_name) LIKE '%' || lower($1) || '%'
                     OR lower(resource_type) LIKE '%' || lower($1) || '%'
                     OR lower(value) LIKE '%' || lower($1) || '%')
                AND ($4 = ''
                     OR ($4 = '1' AND active_int = 1)
                     OR ($4 = '0' AND active_int = 0))
                AND ($5 = '' OR lower(resource_type) = lower($5))
                AND ($6 = '' OR lower(value) LIKE '%' || lower($6) || '%')
         )
         SELECT count(*) OVER()::bigint AS total, * FROM filtered
          ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    );
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[
                &params.filter,
                &params.page_size,
                &params.offset,
                &active_filter,
                &resource_type_filter,
                &value_filter,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "tag asset list query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(tag_asset_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn tag_asset_detail(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
) -> Result<Json<TagAssetItem>, ApiError> {
    parse_uuid(&tag_id)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let row = client
        .query_opt(
            r#"SELECT t.uuid AS id,
                      coalesce(t.name, '') AS name,
                      coalesce(t.comment, '') AS comment,
                      coalesce(u.name, '') AS owner_name,
                      coalesce(t.resource_type, '') AS resource_type,
                      coalesce(tag_resources_count(t.id, t.resource_type), 0)::bigint AS resource_count,
                      coalesce(t.active, 0)::integer AS active_int,
                      coalesce(t.value, '') AS value,
                      coalesce(t.creation_time, 0)::bigint AS created_at_unix,
                      coalesce(t.modification_time, 0)::bigint AS modified_at_unix
                 FROM tags t
            LEFT JOIN users u ON u.id = t.owner
                WHERE t.uuid = $1
                LIMIT 1;"#,
            &[&tag_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "tag asset detail query failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(tag_asset_from_row(&row)))
}

pub(crate) async fn tag_asset_resources(
    State(state): State<AppState>,
    Path(tag_id): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<TagResourceCollection>, ApiError> {
    let tag_id = parse_uuid(&tag_id)?.to_string();
    let params = normalize_collection_query(query, TAG_RESOURCE_DEFAULT_SORT)?;
    let sort_sql = sort_clause(&params.sort, TAG_RESOURCE_SORT_FIELDS)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let tag_row = client
        .query_opt(
            r#"SELECT id, uuid, coalesce(resource_type, '') AS resource_type
                 FROM tags
                WHERE uuid = $1
                LIMIT 1;"#,
            &[&tag_id],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, "tag lookup for resource expansion failed");
            ApiError::Database
        })?
        .ok_or(ApiError::NotFound)?;
    let tag_internal_id: i32 = tag_row.get("id");
    let resource_type = normalize_tag_resource_type(tag_row.get("resource_type"));
    let sql = tag_resource_collection_sql(&resource_type, &sort_sql)?;
    let rows = client
        .query(
            &sql,
            &[
                &tag_internal_id,
                &params.filter,
                &params.page_size,
                &params.offset,
            ],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, %resource_type, "tag resource query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(tag_resource_from_row).collect();
    Ok(Json(TagResourceCollection {
        tag_id,
        resource_type,
        page: params.page_info(total),
        items,
    }))
}

pub(crate) async fn tag_resource_names(
    State(state): State<AppState>,
    Path(resource_type): Path<String>,
    ApiQuery(query): ApiQuery<CollectionQuery>,
) -> Result<Json<Collection<TagResourceItem>>, ApiError> {
    let resource_type = normalize_tag_resource_type(resource_type);
    let params = normalize_collection_query(query, TAG_RESOURCE_DEFAULT_SORT)?;
    if params.page_size > TAG_RESOURCE_NAME_MAX_PAGE_SIZE {
        return Err(ApiError::BadRequest(format!(
            "page_size must be between 1 and {TAG_RESOURCE_NAME_MAX_PAGE_SIZE}"
        )));
    }
    let sort_sql = sort_clause(&params.sort, TAG_RESOURCE_SORT_FIELDS)?;
    let (filter, exact_id_filter) = tag_resource_name_filter(&params.filter);
    let sql = tag_resource_name_collection_sql(&resource_type, &sort_sql)?;
    let client = state.pool.get().await.map_err(|_| ApiError::Database)?;
    let rows = client
        .query(
            &sql,
            &[&filter, &exact_id_filter, &params.page_size, &params.offset],
        )
        .await
        .map_err(|error| {
            tracing::warn!(%error, %resource_type, "tag resource-name query failed");
            ApiError::Database
        })?;
    let total = rows
        .first()
        .map(|row| row.get::<_, i64>("total"))
        .unwrap_or(0);
    let items = rows.iter().map(tag_resource_from_row).collect();
    Ok(Json(Collection {
        page: params.page_info(total),
        items,
    }))
}
