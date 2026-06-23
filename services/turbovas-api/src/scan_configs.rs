// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::{formatters::unix_ts_to_rfc3339, user_tags::ReportUserTag};

#[derive(Serialize)]
struct ScanConfigOwner {
    name: String,
}

#[derive(Serialize)]
struct ScanConfigTrendCount {
    total: i64,
    trend: i32,
}

#[derive(Serialize)]
pub(crate) struct ScanConfigTaskReference {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) usage_type: String,
}

#[derive(Serialize)]
pub(crate) struct ScanConfigAssetItem {
    id: String,
    name: String,
    comment: String,
    owner: ScanConfigOwner,
    family_count: i64,
    families_growing: i32,
    nvt_count: i64,
    nvts_growing: i32,
    families: ScanConfigTrendCount,
    nvts: ScanConfigTrendCount,
    predefined: bool,
    deprecated: bool,
    writable: bool,
    in_use: bool,
    orphan: bool,
    trash: bool,
    usage_type: String,
    created_at: Option<String>,
    modified_at: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct ScanConfigAssetDetail {
    #[serde(flatten)]
    pub(crate) asset: ScanConfigAssetItem,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) tasks: Vec<ScanConfigTaskReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

pub(crate) fn scan_config_asset_from_row(row: &Row) -> ScanConfigAssetItem {
    let family_count = row.get("family_count");
    let families_growing = row.get("families_growing");
    let nvt_count = row.get("nvt_count");
    let nvts_growing = row.get("nvts_growing");

    ScanConfigAssetItem {
        id: row.get("id"),
        name: row.get("name"),
        comment: row.get("comment"),
        owner: ScanConfigOwner {
            name: row.get("owner_name"),
        },
        family_count,
        families_growing,
        nvt_count,
        nvts_growing,
        families: ScanConfigTrendCount {
            total: family_count,
            trend: families_growing,
        },
        nvts: ScanConfigTrendCount {
            total: nvt_count,
            trend: nvts_growing,
        },
        predefined: row.get::<_, i32>("predefined_int") != 0,
        deprecated: row.get::<_, i32>("deprecated_int") != 0,
        writable: row.get::<_, i32>("predefined_int") == 0,
        in_use: row.get::<_, i32>("in_use_int") != 0,
        orphan: false,
        trash: false,
        usage_type: row.get("usage_type"),
        created_at: unix_ts_to_rfc3339(row.get("created_at_unix")),
        modified_at: unix_ts_to_rfc3339(row.get("modified_at_unix")),
    }
}
