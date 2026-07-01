// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn task_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn task_write_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer
       FROM tasks
      WHERE uuid = $1
        AND coalesce(hidden, 0) = 0
        AND coalesce(usage_type, 'scan') = 'scan';"
}

pub(crate) fn task_unique_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM tasks
      WHERE name = $1
        AND id != $2
        AND owner = $3
        AND coalesce(hidden, 0) = 0
        AND coalesce(usage_type, 'scan') = 'scan';"
}

pub(crate) fn task_update_metadata_sql() -> &'static str {
    "UPDATE tasks
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            modification_time = m_now()
      WHERE id = $1
        AND coalesce(hidden, 0) = 0
        AND coalesce(usage_type, 'scan') = 'scan'
      RETURNING uuid::text;"
}
