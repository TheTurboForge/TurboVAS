// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn scan_config_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn scan_config_write_state_sql() -> &'static str {
    "SELECT id::integer, coalesce(predefined, 0)::integer
       FROM configs
      WHERE uuid = $1
        AND coalesce(usage_type, 'scan') = 'scan';"
}

pub(crate) fn scan_config_unique_name_sql() -> &'static str {
    "SELECT (
        (SELECT count(*) FROM configs WHERE name = $1 AND id != $2)
        + (SELECT count(*) FROM configs_trash WHERE name = $1)
      )::bigint;"
}

pub(crate) fn scan_config_update_metadata_sql() -> &'static str {
    "UPDATE configs
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            modification_time = m_now()
      WHERE id = $1
      RETURNING uuid::text;"
}
