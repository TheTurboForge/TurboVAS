// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::port_list_write_validation::MAX_PORT_LIST_TEXT_BYTES;

fn patch_request(name: Option<&str>, comment: Option<&str>) -> PortListPatchRequest {
    PortListPatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

#[test]
fn port_list_create_plan_validates_ranges_before_insert() {
    assert_eq!(
        port_list_create_transaction_plan().steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::ValidatePortRanges,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::InsertPortList,
            PortListWriteStep::ReplacePortRanges,
        ]
    );
}

#[test]
fn port_list_patch_request_trims_metadata_fields() {
    assert_eq!(
        validate_port_list_patch_request(patch_request(
            Some("  Web ports  "),
            Some("  operator-visible note  "),
        ))
        .unwrap(),
        ValidatedPortListPatch {
            name: Some("Web ports".to_string()),
            comment: Some("operator-visible note".to_string()),
        }
    );
}

#[test]
fn port_list_patch_request_requires_at_least_one_field() {
    assert!(matches!(
        validate_port_list_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn port_list_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_port_list_patch_request(patch_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn port_list_patch_request_allows_blank_comment_to_clear_comment() {
    assert_eq!(
        validate_port_list_patch_request(patch_request(None, Some("   "))).unwrap(),
        ValidatedPortListPatch {
            name: None,
            comment: Some(String::new()),
        }
    );
}

#[test]
fn port_list_patch_request_rejects_control_characters() {
    assert!(matches!(
        validate_port_list_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_port_list_patch_request(patch_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn port_list_patch_request_rejects_unknown_fields() {
    let request = serde_json::json!({"name": "Web ports", "predefined": false});
    assert!(serde_json::from_value::<PortListPatchRequest>(request).is_err());
}

#[test]
fn port_list_patch_request_rejects_oversized_metadata_fields() {
    let oversized = "a".repeat(MAX_PORT_LIST_TEXT_BYTES + 1);
    assert!(matches!(
        validate_port_list_patch_request(PortListPatchRequest {
            name: Some(oversized),
            comment: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn port_list_patch_sql_is_metadata_only() {
    let sql = port_list_update_metadata_sql();
    assert!(sql.contains("UPDATE port_lists"));
    assert!(sql.contains("name = coalesce"));
    assert!(sql.contains("comment = coalesce"));
    assert!(sql.contains("modification_time = m_now()"));
    assert!(!sql.contains("port_ranges"));
    assert!(!sql.contains("predefined"));
}

#[test]
fn port_list_delete_sql_moves_metadata_ranges_targets_and_tags_to_trash() {
    let target_guard = port_list_live_target_count_sql();
    assert!(target_guard.contains("FROM targets"));
    assert!(target_guard.contains("WHERE port_list = $1"));

    let trash = port_list_trash_insert_sql();
    assert!(trash.contains("INSERT INTO port_lists_trash"));
    assert!(trash.contains("FROM port_lists"));
    assert!(trash.contains("WHERE id = $1"));
    assert!(trash.contains("RETURNING id::integer, uuid::text"));

    let ranges = port_list_trash_ranges_insert_sql();
    assert!(ranges.contains("INSERT INTO port_ranges_trash"));
    assert!(ranges.contains("SELECT uuid, $1, type, start"));
    assert!(ranges.contains("FROM port_ranges"));
    assert!(ranges.contains("WHERE port_list = $2"));

    let targets = port_list_trash_target_relink_sql();
    assert!(targets.contains("UPDATE targets_trash"));
    assert!(targets.contains("port_list_location = 1"));
    assert!(targets.contains("WHERE port_list = $2"));
    assert!(targets.contains("port_list_location = 0"));

    let live_tags = port_list_tag_locations_to_trash_sql();
    assert!(live_tags.contains("UPDATE tag_resources"));
    assert!(live_tags.contains("resource_type = 'port_list'"));
    assert!(live_tags.contains("resource_location = 1"));

    let trash_tags = port_list_trash_tag_locations_to_trash_sql();
    assert!(trash_tags.contains("UPDATE tag_resources_trash"));
    assert!(trash_tags.contains("resource_type = 'port_list'"));
    assert!(trash_tags.contains("resource_location = 1"));

    assert!(port_list_delete_ranges_sql().contains("DELETE FROM port_ranges"));
    assert!(port_list_delete_metadata_sql().contains("DELETE FROM port_lists"));
}

#[test]
fn port_list_restore_sql_moves_metadata_ranges_targets_and_tags_to_live() {
    let state = port_list_trash_state_sql();
    assert!(state.contains("FROM port_lists_trash"));
    assert!(state.contains("owner::integer"));

    let name_conflict = port_list_unique_live_owner_name_sql();
    assert!(name_conflict.contains("FROM port_lists"));
    assert!(name_conflict.contains("name = $1"));
    assert!(name_conflict.contains("owner = $2"));

    let uuid_conflict = port_list_live_uuid_conflict_sql();
    assert!(uuid_conflict.contains("FROM port_lists"));
    assert!(uuid_conflict.contains("uuid = $1"));

    let restore = port_list_restore_metadata_sql();
    assert!(restore.contains("INSERT INTO port_lists"));
    assert!(restore.contains("FROM port_lists_trash"));
    assert!(restore.contains("WHERE id = $1"));
    assert!(restore.contains("RETURNING id::integer, uuid::text"));

    let ranges = port_list_restore_ranges_sql();
    assert!(ranges.contains("INSERT INTO port_ranges"));
    assert!(ranges.contains("SELECT uuid, $2, type, start"));
    assert!(ranges.contains("FROM port_ranges_trash"));
    assert!(ranges.contains("WHERE port_list = $1"));

    let targets = port_list_restore_target_relink_sql();
    assert!(targets.contains("UPDATE targets_trash"));
    assert!(targets.contains("port_list = $2"));
    assert!(targets.contains("port_list_location = 0"));
    assert!(targets.contains("WHERE port_list = $1"));
    assert!(targets.contains("port_list_location = 1"));

    let live_tags = port_list_tag_locations_to_live_sql();
    assert!(live_tags.contains("UPDATE tag_resources"));
    assert!(live_tags.contains("resource_type = 'port_list'"));
    assert!(live_tags.contains("resource_location = 0"));

    let trash_tags = port_list_trash_tag_locations_to_live_sql();
    assert!(trash_tags.contains("UPDATE tag_resources_trash"));
    assert!(trash_tags.contains("resource_type = 'port_list'"));
    assert!(trash_tags.contains("resource_location = 0"));

    assert!(port_list_delete_trash_ranges_sql().contains("DELETE FROM port_ranges_trash"));
    assert!(port_list_delete_trash_metadata_sql().contains("DELETE FROM port_lists_trash"));
}

#[test]
fn port_list_patch_name_uniqueness_checks_live_and_trash_names() {
    let sql = port_list_unique_name_sql();
    assert!(sql.contains("FROM port_lists WHERE name = $1 AND id != $2"));
    assert!(sql.contains("FROM port_lists_trash WHERE name = $1"));
}

#[test]
fn port_list_patch_plan_stays_metadata_only_and_blocks_predefined_lists() {
    assert_eq!(
        port_list_patch_transaction_plan().steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingPortListMutable,
            PortListWriteStep::VerifyNotPredefined,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::UpdatePortListMetadata,
        ]
    );
}

#[test]
fn port_list_delete_plan_keeps_range_target_and_tag_side_effects_explicit() {
    assert_eq!(
        port_list_delete_transaction_plan().steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingPortListMutable,
            PortListWriteStep::VerifyTargetDeleteSafety,
            PortListWriteStep::MovePortListToTrash,
            PortListWriteStep::MovePortRangesToTrash,
            PortListWriteStep::RelocateTargets,
            PortListWriteStep::RelocatePermissionsAndTags,
        ]
    );
}

#[test]
fn port_list_restore_plan_keeps_range_target_and_tag_side_effects_explicit() {
    assert_eq!(
        port_list_restore_transaction_plan().steps,
        vec![
            PortListWriteStep::ResolveOperatorOwner,
            PortListWriteStep::VerifyExistingTrashedPortListRestorable,
            PortListWriteStep::VerifyUniqueLiveAndTrashName,
            PortListWriteStep::RestorePortListFromTrash,
            PortListWriteStep::RestorePortRangesFromTrash,
            PortListWriteStep::RelocateTargets,
            PortListWriteStep::RelocatePermissionsAndTags,
        ]
    );
}
