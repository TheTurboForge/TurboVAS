// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub(crate) fn target_write_operator_owner_sql() -> &'static str {
    "SELECT id::integer FROM users WHERE uuid = $1;"
}

pub(crate) fn target_write_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer
       FROM targets
      WHERE uuid = $1;"
}

pub(crate) fn target_source_port_list_is_assignable_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM targets t
       JOIN port_lists pl ON pl.id = t.port_list
      WHERE t.id = $1
        AND NOT (coalesce(pl.predefined, 0) != 0 OR pl.owner = $2);"
}

pub(crate) fn target_source_unassignable_credential_count_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM targets_login_data tld
       JOIN credentials c ON c.id = tld.credential
      WHERE tld.target = $1
        AND c.owner != $2;"
}

pub(crate) fn target_unique_name_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM targets
      WHERE name = $1
        AND id != $2
        AND owner = $3;"
}

pub(crate) fn target_in_use_sql() -> &'static str {
    "SELECT count(*)::bigint
       FROM tasks
      WHERE target = $1
        AND target_location = 0
        AND hidden = 0;"
}

pub(crate) fn target_assignable_port_list_state_sql() -> &'static str {
    "SELECT id::integer,
            owner::integer,
            coalesce(predefined, 0)::integer
       FROM port_lists
      WHERE uuid = $1;"
}

pub(crate) fn target_update_metadata_sql() -> &'static str {
    "UPDATE targets
        SET name = coalesce($2, name),
            comment = coalesce($3, comment),
            alive_test = coalesce($4, alive_test),
            allow_simultaneous_ips = coalesce($5, allow_simultaneous_ips),
            reverse_lookup_only = coalesce($6, reverse_lookup_only),
            reverse_lookup_unify = coalesce($7, reverse_lookup_unify),
            port_list = coalesce($8, port_list),
            hosts = coalesce($9, hosts),
            exclude_hosts = coalesce($10, exclude_hosts),
            modification_time = m_now()
      WHERE id = $1
      RETURNING uuid::text;"
}

pub(crate) fn target_clone_metadata_sql() -> &'static str {
    "INSERT INTO targets
        (uuid, owner, name, hosts, exclude_hosts, reverse_lookup_only,
         reverse_lookup_unify, comment, port_list, alive_test, creation_time,
         modification_time, allow_simultaneous_ips)
     SELECT make_uuid(),
            $2,
            coalesce($3, uniquify('target', name, $2, ' Clone')),
            hosts,
            exclude_hosts,
            reverse_lookup_only,
            reverse_lookup_unify,
            coalesce($4, comment),
            port_list,
            alive_test,
            m_now(),
            m_now(),
            allow_simultaneous_ips
       FROM targets
      WHERE id = $1
      RETURNING id::integer, uuid::text;"
}

pub(crate) fn target_clone_login_data_sql() -> &'static str {
    "INSERT INTO targets_login_data (target, type, credential, port)
     SELECT $2, type, credential, port
       FROM targets_login_data
      WHERE target = $1;"
}

pub(crate) fn target_clone_tags_sql() -> &'static str {
    "INSERT INTO tag_resources (tag, resource_type, resource, resource_uuid, resource_location)
     SELECT tag, resource_type, $2, $3, resource_location
       FROM tag_resources
      WHERE resource_type = 'target'
        AND resource = $1
        AND resource_location = 0;"
}
