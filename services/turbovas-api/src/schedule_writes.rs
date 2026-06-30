// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScheduleWriteOperation {
    Create,
    Patch,
    Delete,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScheduleWriteStep {
    ResolveOperatorOwner,
    VerifyExistingScheduleMutable,
    ResolveTimezone,
    ValidateTimezone,
    ParseICalendar,
    DeriveScheduleFields,
    VerifyUniqueLiveName,
    VerifyTaskDeleteSafety,
    InsertSchedule,
    UpdateScheduleMetadata,
    RefreshTaskNextTimes,
    MoveScheduleToTrash,
    RelocateTasks,
    RelocatePermissionsAndTags,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ScheduleWriteTransactionPlan {
    pub(crate) operation: ScheduleWriteOperation,
    pub(crate) steps: Vec<ScheduleWriteStep>,
}

#[cfg(test)]
pub(crate) fn schedule_create_transaction_plan() -> ScheduleWriteTransactionPlan {
    ScheduleWriteTransactionPlan {
        operation: ScheduleWriteOperation::Create,
        steps: vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::ResolveTimezone,
            ScheduleWriteStep::ValidateTimezone,
            ScheduleWriteStep::ParseICalendar,
            ScheduleWriteStep::DeriveScheduleFields,
            ScheduleWriteStep::VerifyUniqueLiveName,
            ScheduleWriteStep::InsertSchedule,
        ],
    }
}

#[cfg(test)]
pub(crate) fn schedule_patch_transaction_plan(
    changes_calendar: bool,
) -> ScheduleWriteTransactionPlan {
    let mut steps = vec![
        ScheduleWriteStep::ResolveOperatorOwner,
        ScheduleWriteStep::VerifyExistingScheduleMutable,
    ];
    if changes_calendar {
        steps.extend([
            ScheduleWriteStep::ResolveTimezone,
            ScheduleWriteStep::ValidateTimezone,
            ScheduleWriteStep::ParseICalendar,
            ScheduleWriteStep::DeriveScheduleFields,
        ]);
    }
    steps.extend([
        ScheduleWriteStep::VerifyUniqueLiveName,
        ScheduleWriteStep::UpdateScheduleMetadata,
    ]);
    if changes_calendar {
        steps.push(ScheduleWriteStep::RefreshTaskNextTimes);
    }
    ScheduleWriteTransactionPlan {
        operation: ScheduleWriteOperation::Patch,
        steps,
    }
}

#[cfg(test)]
pub(crate) fn schedule_delete_transaction_plan() -> ScheduleWriteTransactionPlan {
    ScheduleWriteTransactionPlan {
        operation: ScheduleWriteOperation::Delete,
        steps: vec![
            ScheduleWriteStep::ResolveOperatorOwner,
            ScheduleWriteStep::VerifyExistingScheduleMutable,
            ScheduleWriteStep::VerifyTaskDeleteSafety,
            ScheduleWriteStep::MoveScheduleToTrash,
            ScheduleWriteStep::RelocateTasks,
            ScheduleWriteStep::RelocatePermissionsAndTags,
        ],
    }
}

#[cfg(test)]
#[path = "schedule_writes_tests.rs"]
mod schedule_writes_tests;
