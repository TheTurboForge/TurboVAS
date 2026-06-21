// SPDX-FileCopyrightText: 2026 TurboVAS contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

use tokio_postgres::Row;

pub(crate) fn optional_row_string(row: &Row, name: &str) -> Option<String> {
    row.try_get::<_, Option<String>>(name).ok().flatten()
}

pub(crate) fn optional_row_strings(row: &Row, name: &str) -> Vec<String> {
    row.try_get::<_, Vec<String>>(name).unwrap_or_default()
}

pub(crate) fn csv_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

pub(crate) fn boolean_int(value: i32) -> bool {
    value != 0
}

pub(crate) fn task_has_active_current_report(status: &str) -> bool {
    matches!(
        status,
        "Requested" | "Queued" | "Running" | "Processing" | "Stop Requested"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_values_trims_and_drops_empty_entries() {
        assert_eq!(
            csv_values(" 192.0.2.1, ,example.test,, 198.51.100.2 "),
            vec!["192.0.2.1", "example.test", "198.51.100.2"]
        );
        assert!(csv_values(" , , ").is_empty());
    }

    #[test]
    fn boolean_int_matches_nonzero_database_flags() {
        assert!(!boolean_int(0));
        assert!(boolean_int(1));
        assert!(boolean_int(-1));
    }

    #[test]
    fn task_active_current_report_statuses_are_explicit() {
        for status in [
            "Requested",
            "Queued",
            "Running",
            "Processing",
            "Stop Requested",
        ] {
            assert!(task_has_active_current_report(status), "{status}");
        }
        for status in ["Done", "Stopped", "Interrupted", "New"] {
            assert!(!task_has_active_current_report(status), "{status}");
        }
    }
}
