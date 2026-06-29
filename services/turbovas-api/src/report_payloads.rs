// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Serialize;
use tokio_postgres::Row;

use crate::{
    formatters::unix_ts_to_rfc3339, report_evidence_payloads::ReportSeverityCounts,
    user_tags::ReportUserTag,
};

#[derive(Debug, Serialize)]
pub(crate) struct ReportReference {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct ReportOwner {
    name: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReportItem {
    id: String,
    name: String,
    owner: ReportOwner,
    status: String,
    task: Option<ReportReference>,
    target: Option<ReportReference>,
    scan_start: Option<String>,
    scan_end: Option<String>,
    creation_time: Option<String>,
    modification_time: Option<String>,
    result_count: i64,
    vulnerability_count: i64,
    host_count: i64,
    cve_count: i64,
    severity: ReportSeverityCounts,
    max_severity: f64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) user_tags: Vec<ReportUserTag>,
}

pub(crate) fn report_reference(
    id: Option<String>,
    name: Option<String>,
) -> Option<ReportReference> {
    let id = id?;
    let name = name.unwrap_or_else(|| id.clone());
    Some(ReportReference { id, name })
}

pub(crate) fn report_from_row(row: &Row) -> ReportItem {
    ReportItem {
        id: row.get(1),
        name: row.get(2),
        owner: ReportOwner { name: row.get(3) },
        task: report_reference(row.get(4), row.get(5)),
        target: report_reference(row.get(6), row.get(7)),
        status: row.get(8),
        creation_time: unix_ts_to_rfc3339(row.get(9)),
        scan_start: unix_ts_to_rfc3339(row.get(10)),
        scan_end: unix_ts_to_rfc3339(row.get(11)),
        modification_time: unix_ts_to_rfc3339(row.get(12)),
        result_count: row.get(13),
        vulnerability_count: row.get(14),
        host_count: row.get(15),
        cve_count: row.get(16),
        max_severity: row.get(17),
        severity: ReportSeverityCounts {
            critical: row.get(18),
            high: row.get(19),
            medium: row.get(20),
            low: row.get(21),
            log: row.get(22),
            false_positive: row.get(23),
        },
        user_tags: Vec::new(),
    }
}
