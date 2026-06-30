// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(test)]
use serde::Deserialize;

#[cfg(test)]
use crate::errors::ApiError;

#[cfg(test)]
const MAX_SCHEDULE_TEXT_BYTES: usize = 4096;

#[cfg(test)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SchedulePatchRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    comment: Option<String>,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedSchedulePatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
}

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
pub(crate) fn validate_schedule_patch_request(
    request: SchedulePatchRequest,
) -> Result<ValidatedSchedulePatch, ApiError> {
    let validated = ValidatedSchedulePatch {
        name: normalize_optional_required_schedule_text(request.name, "name")?,
        comment: normalize_optional_schedule_text(request.comment, "comment")?,
    };
    if validated.name.is_none() && validated.comment.is_none() {
        return Err(ApiError::BadRequest(
            "schedule patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

#[cfg(test)]
fn normalize_optional_required_schedule_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_schedule_text(value, field_name))
        .transpose()
}

#[cfg(test)]
fn normalize_required_schedule_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_schedule_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

#[cfg(test)]
fn normalize_optional_schedule_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_schedule_text_value(value, field_name))
        .transpose()
}

#[cfg(test)]
fn normalize_schedule_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_SCHEDULE_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_SCHEDULE_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
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
