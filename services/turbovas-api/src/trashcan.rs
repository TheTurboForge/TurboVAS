// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

#[derive(Serialize)]
struct TrashcanSummaryItem {
    resource_type: String,
    title: String,
    count: i64,
}

#[derive(Serialize)]
pub(crate) struct TrashcanSummary {
    items: Vec<TrashcanSummaryItem>,
    total: i64,
}

pub(crate) fn trashcan_summary_from_rows(rows: &[Row]) -> TrashcanSummary {
    let items: Vec<TrashcanSummaryItem> = rows
        .iter()
        .map(|row| TrashcanSummaryItem {
            resource_type: row.get("resource_type"),
            title: row.get("title"),
            count: row.get("item_count"),
        })
        .collect();
    let total = items.iter().map(|item| item.count).sum();
    TrashcanSummary { items, total }
}
