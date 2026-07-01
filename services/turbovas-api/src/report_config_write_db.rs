// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#[path = "report_config_write_checks.rs"]
mod checks;
#[path = "report_config_write_transactions.rs"]
mod transactions;

pub(crate) use checks::*;
pub(crate) use transactions::*;

use crate::errors::ApiError;

pub(crate) fn map_report_config_write_db_error(
    error: tokio_postgres::Error,
    action: &'static str,
) -> ApiError {
    tracing::warn!(%error, action, "report config write database operation failed");
    ApiError::Database
}
