// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

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
