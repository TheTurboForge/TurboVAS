// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::errors::ApiError;

fn patch_request(name: Option<&str>, comment: Option<&str>) -> SchedulePatchRequest {
    SchedulePatchRequest {
        name: name.map(str::to_string),
        comment: comment.map(str::to_string),
    }
}

#[test]
fn schedule_create_plan_keeps_calendar_validation_before_insert() {
    assert_eq!(
        schedule_create_transaction_plan().steps,
        vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::ResolveTimezone,
            ScheduleWriteStep::ValidateTimezone,
            ScheduleWriteStep::ParseICalendar,
            ScheduleWriteStep::DeriveScheduleFields,
            ScheduleWriteStep::VerifyUniqueLiveName,
            ScheduleWriteStep::InsertSchedule,
        ]
    );
}

#[test]
fn schedule_patch_request_trims_metadata_fields() {
    assert_eq!(
        validate_schedule_patch_request(patch_request(
            Some("  Weekday scan  "),
            Some("  operator-visible note  "),
        ))
        .unwrap(),
        ValidatedSchedulePatch {
            name: Some("Weekday scan".to_string()),
            comment: Some("operator-visible note".to_string()),
        }
    );
}

#[test]
fn schedule_patch_request_requires_at_least_one_field() {
    assert!(matches!(
        validate_schedule_patch_request(patch_request(None, None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn schedule_patch_request_rejects_blank_name() {
    assert!(matches!(
        validate_schedule_patch_request(patch_request(Some("   "), None)),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn schedule_patch_request_allows_blank_comment_to_clear_comment() {
    assert_eq!(
        validate_schedule_patch_request(patch_request(None, Some("   "))).unwrap(),
        ValidatedSchedulePatch {
            name: None,
            comment: Some(String::new()),
        }
    );
}

#[test]
fn schedule_patch_request_rejects_control_characters() {
    assert!(matches!(
        validate_schedule_patch_request(patch_request(Some("bad\nname"), None)),
        Err(ApiError::BadRequest(_))
    ));
    assert!(matches!(
        validate_schedule_patch_request(patch_request(None, Some("bad\u{0}comment"))),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn schedule_patch_request_rejects_unknown_calendar_fields() {
    let request = serde_json::json!({
        "name": "Weekday scan",
        "icalendar": "BEGIN:VCALENDAR\nEND:VCALENDAR",
    });
    assert!(serde_json::from_value::<SchedulePatchRequest>(request).is_err());
}

#[test]
fn schedule_patch_request_rejects_oversized_metadata_fields() {
    let oversized = "a".repeat(MAX_SCHEDULE_TEXT_BYTES + 1);
    assert!(matches!(
        validate_schedule_patch_request(SchedulePatchRequest {
            name: Some(oversized),
            comment: None,
        }),
        Err(ApiError::BadRequest(_))
    ));
}

#[test]
fn schedule_patch_plan_refreshes_tasks_only_for_calendar_changes() {
    assert_eq!(
        schedule_patch_transaction_plan(false).steps,
        vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::VerifyUniqueLiveName,
            ScheduleWriteStep::UpdateScheduleMetadata,
        ]
    );
    assert_eq!(
        schedule_patch_transaction_plan(true).steps,
        vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::ResolveTimezone,
            ScheduleWriteStep::ValidateTimezone,
            ScheduleWriteStep::ParseICalendar,
            ScheduleWriteStep::DeriveScheduleFields,
            ScheduleWriteStep::VerifyUniqueLiveName,
            ScheduleWriteStep::UpdateScheduleMetadata,
            ScheduleWriteStep::RefreshTaskNextTimes,
        ]
    );
}

#[test]
fn schedule_delete_plan_keeps_task_and_trash_side_effects_explicit() {
    assert_eq!(
        schedule_delete_transaction_plan().steps,
        vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::VerifyTaskDeleteSafety,
            ScheduleWriteStep::MoveScheduleToTrash,
            ScheduleWriteStep::RelocateTasks,
            ScheduleWriteStep::RelocatePermissionsAndTags,
        ]
    );
}
