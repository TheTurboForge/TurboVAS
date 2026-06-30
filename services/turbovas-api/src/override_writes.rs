// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OverrideWriteOperation {
    Create,
    Patch,
    Delete,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OverrideWriteStep {
    ResolveOperatorOwner,
    VerifyExistingOverrideMutable,
    ValidateNvtExists,
    ValidatePortScope,
    ValidateSeverityBounds,
    ResolveTaskScope,
    ResolveResultScope,
    ResolveResultNvt,
    ComputeAffectedReports,
    InsertOverride,
    UpdateOverrideMetadata,
    MoveOverrideToTrash,
    RelocatePermissionsAndTags,
    RebuildReportCaches,
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OverrideWriteTransactionPlan {
    pub(crate) operation: OverrideWriteOperation,
    pub(crate) steps: Vec<OverrideWriteStep>,
}

#[cfg(test)]
pub(crate) fn override_create_transaction_plan() -> OverrideWriteTransactionPlan {
    OverrideWriteTransactionPlan {
        operation: OverrideWriteOperation::Create,
        steps: vec![
            OverrideWriteStep::ResolveOperatorOwner,
            OverrideWriteStep::ValidateNvtExists,
            OverrideWriteStep::ValidatePortScope,
            OverrideWriteStep::ValidateSeverityBounds,
            OverrideWriteStep::ResolveTaskScope,
            OverrideWriteStep::ResolveResultScope,
            OverrideWriteStep::ResolveResultNvt,
            OverrideWriteStep::InsertOverride,
            OverrideWriteStep::ComputeAffectedReports,
            OverrideWriteStep::RebuildReportCaches,
        ],
    }
}

#[cfg(test)]
pub(crate) fn override_patch_transaction_plan() -> OverrideWriteTransactionPlan {
    OverrideWriteTransactionPlan {
        operation: OverrideWriteOperation::Patch,
        steps: vec![
            OverrideWriteStep::ResolveOperatorOwner,
            OverrideWriteStep::VerifyExistingOverrideMutable,
            OverrideWriteStep::ValidateNvtExists,
            OverrideWriteStep::ValidatePortScope,
            OverrideWriteStep::ValidateSeverityBounds,
            OverrideWriteStep::ResolveTaskScope,
            OverrideWriteStep::ResolveResultScope,
            OverrideWriteStep::ResolveResultNvt,
            OverrideWriteStep::ComputeAffectedReports,
            OverrideWriteStep::UpdateOverrideMetadata,
            OverrideWriteStep::RebuildReportCaches,
        ],
    }
}

#[cfg(test)]
pub(crate) fn override_delete_transaction_plan() -> OverrideWriteTransactionPlan {
    OverrideWriteTransactionPlan {
        operation: OverrideWriteOperation::Delete,
        steps: vec![
            OverrideWriteStep::ResolveOperatorOwner,
            OverrideWriteStep::VerifyExistingOverrideMutable,
            OverrideWriteStep::ComputeAffectedReports,
            OverrideWriteStep::MoveOverrideToTrash,
            OverrideWriteStep::RelocatePermissionsAndTags,
            OverrideWriteStep::RebuildReportCaches,
        ],
    }
}

#[cfg(test)]
#[path = "override_writes_tests.rs"]
mod override_writes_tests;
