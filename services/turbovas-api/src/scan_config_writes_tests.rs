// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::errors::ApiError;
use crate::scan_config_write_sql::*;
use crate::scan_config_write_validation::*;

fn patch_request(name: Option<&str>, comment: Option<&str>) -> ScanConfigPatchRequest {
    ScanConfigPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

#[test]
fn scan_config_patch_request_trims_metadata_fields() {
    let validated = validate_scan_config_patch_request(patch_request(
        Some("  web config  "),
        Some("  comment  "),
    ))
    .expect("valid scan-config patch");
    assert_eq!(validated.name.as_deref(), Some("web config"));
    assert_eq!(validated.comment.as_deref(), Some("comment"));
}

#[test]
fn scan_config_patch_request_requires_at_least_one_field() {
    assert!(matches!(
        validate_scan_config_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn scan_config_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_scan_config_patch_request(patch_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn scan_config_patch_request_allows_blank_comment_to_clear_comment() {
    let validated = validate_scan_config_patch_request(patch_request(None, Some("   ")))
        .expect("blank comment clears comment");
    assert_eq!(validated.comment.as_deref(), Some(""));
}

#[test]
fn scan_config_patch_request_rejects_control_characters_and_unknown_fields() {
    assert!(matches!(
        validate_scan_config_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_scan_config_patch_request(patch_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
    let request = serde_json::json!({"name": "Scan", "nvt_selector": "changed"});
    assert!(serde_json::from_value::<ScanConfigPatchRequest>(request).is_err());
}

#[test]
fn scan_config_patch_request_rejects_oversized_metadata_fields() {
    assert!(matches!(
        validate_scan_config_patch_request(ScanConfigPatchRequest {
            name: Some("x".repeat(MAX_SCAN_CONFIG_TEXT_BYTES + 1)),
            comment: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn scan_config_patch_sql_is_metadata_only() {
    let sql = scan_config_update_metadata_sql();
    assert!(sql.contains("UPDATE configs"));
    assert!(sql.contains("name = coalesce($2, name)"));
    assert!(sql.contains("comment = coalesce($3, comment)"));
    assert!(sql.contains("modification_time = m_now()"));
    for forbidden in [
        "nvt_selector",
        "family_count",
        "nvt_count",
        "families_growing",
        "nvts_growing",
        "config_preferences",
        "nvt_selectors",
        "tasks",
        "configs_trash",
    ] {
        assert!(
            !sql.contains(forbidden),
            "scan-config patch SQL must not touch {forbidden}"
        );
    }
}

#[test]
fn scan_config_patch_state_blocks_predefined_and_non_scan_configs() {
    let state = scan_config_write_state_sql();
    assert!(state.contains("coalesce(predefined, 0)::integer"));
    assert!(state.contains("coalesce(usage_type, 'scan') = 'scan'"));
}

#[test]
fn scan_config_patch_uniqueness_checks_live_and_trash_names() {
    let sql = scan_config_unique_name_sql();
    assert!(sql.contains("FROM configs WHERE name = $1 AND id != $2"));
    assert!(sql.contains("FROM configs_trash WHERE name = $1"));
}
