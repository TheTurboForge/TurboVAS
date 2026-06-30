// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#[test]
fn collection_handlers_use_api_query_contract_extractor() {
    let source = [
        include_str!("main.rs"),
        include_str!("alerts.rs"),
        include_str!("nvt_catalog.rs"),
        include_str!("cpe_catalog.rs"),
        include_str!("cve_catalog.rs"),
        include_str!("cert_advisories.rs"),
        include_str!("filters.rs"),
        include_str!("host_asset_payloads.rs"),
        include_str!("host_assets.rs"),
        include_str!("operating_systems.rs"),
        include_str!("overrides.rs"),
        include_str!("port_lists.rs"),
        include_str!("report_applications.rs"),
        include_str!("report_configs.rs"),
        include_str!("report_cves.rs"),
        include_str!("report_errors.rs"),
        include_str!("report_format_payloads.rs"),
        include_str!("report_formats.rs"),
        include_str!("report_hosts.rs"),
        include_str!("report_operating_systems.rs"),
        include_str!("report_payloads.rs"),
        include_str!("report_ports.rs"),
        include_str!("report_tls_certificates.rs"),
        include_str!("result_payloads.rs"),
        include_str!("scan_config_payloads.rs"),
        include_str!("scan_configs.rs"),
        include_str!("scope_payloads.rs"),
        include_str!("scope_report_applications.rs"),
        include_str!("scope_report_cves.rs"),
        include_str!("scope_report_errors.rs"),
        include_str!("scope_reports.rs"),
        include_str!("scope_report_hosts.rs"),
        include_str!("scope_report_operating_systems.rs"),
        include_str!("scope_report_ports.rs"),
        include_str!("scope_report_retention.rs"),
        include_str!("scope_report_results.rs"),
        include_str!("scope_report_tls_certificates.rs"),
        include_str!("scanner_assets.rs"),
        include_str!("schedules.rs"),
        include_str!("tags.rs"),
        include_str!("target_handlers.rs"),
        include_str!("task_handlers.rs"),
        include_str!("task_target_payloads.rs"),
        include_str!("tls_certificates.rs"),
        include_str!("vulnerability_payloads.rs"),
    ]
    .join("\n");
    let raw_axum_query = concat!("Query", "(query): Query", "<CollectionQuery>");
    let api_query = concat!("ApiQuery", "(query): ApiQuery", "<CollectionQuery>");

    assert_eq!(
        source.matches(raw_axum_query).count(),
        0,
        "collection handlers must not use Axum Query directly"
    );
    assert_eq!(
        source.matches(api_query).count(),
        43,
        "every checked collection contract should use ApiQuery"
    );
}
