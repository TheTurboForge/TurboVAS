// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn report_config_assets_sql(sort_sql: &str) -> String {
    format!(
        r#"SELECT count(*) OVER()::bigint AS total,
                  rc.id::integer AS internal_id,
                  rc.uuid AS id,
                  coalesce(rc.name, '') AS name,
                  coalesce(rc.comment, '') AS comment,
                  coalesce(u.name, '') AS owner_name,
                  coalesce(rc.report_format_id, '') AS report_format_id,
                  coalesce(rf.id, 0)::integer AS report_format_rowid,
                  coalesce(rf.name, '') AS report_format_name,
                  CASE WHEN coalesce(rf.name, '') = '' THEN 1 ELSE 0 END AS orphan,
                  coalesce(rc.creation_time, 0)::bigint AS created_at_unix,
                  coalesce(rc.modification_time, 0)::bigint AS modified_at_unix
             FROM report_configs rc
        LEFT JOIN users u ON u.id = rc.owner
        LEFT JOIN report_formats rf ON rf.uuid = rc.report_format_id
            WHERE ($1 = ''
                   OR lower(rc.uuid) LIKE '%' || lower($1) || '%'
                   OR lower(rc.name) LIKE '%' || lower($1) || '%'
                   OR lower(rc.comment) LIKE '%' || lower($1) || '%'
                   OR lower(rf.name) LIKE '%' || lower($1) || '%')
         ORDER BY {sort_sql}, name ASC, id ASC LIMIT $2 OFFSET $3;"#,
    )
}

pub(crate) fn report_config_asset_detail_sql() -> &'static str {
    r#"SELECT rc.id::integer AS internal_id,
              rc.uuid AS id,
              coalesce(rc.name, '') AS name,
              coalesce(rc.comment, '') AS comment,
              coalesce(u.name, '') AS owner_name,
              coalesce(rc.report_format_id, '') AS report_format_id,
              coalesce(rf.id, 0)::integer AS report_format_rowid,
              coalesce(rf.name, '') AS report_format_name,
              CASE WHEN coalesce(rf.name, '') = '' THEN 1 ELSE 0 END AS orphan,
              coalesce(rc.creation_time, 0)::bigint AS created_at_unix,
              coalesce(rc.modification_time, 0)::bigint AS modified_at_unix
         FROM report_configs rc
    LEFT JOIN users u ON u.id = rc.owner
    LEFT JOIN report_formats rf ON rf.uuid = rc.report_format_id
        WHERE rc.uuid = $1
        LIMIT 1;"#
}
