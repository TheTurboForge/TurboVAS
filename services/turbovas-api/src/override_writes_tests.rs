// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
fn override_create_plan_keeps_scope_validation_before_insert_and_cache_rebuild() {
    assert_eq!(
        override_create_transaction_plan().steps,
        vec![
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
        ]
    );
}

#[test]
fn override_patch_plan_keeps_existing_permission_and_cache_invalidation_explicit() {
    assert_eq!(
        override_patch_transaction_plan().steps,
        vec![
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
        ]
    );
}

#[test]
fn override_delete_plan_keeps_trash_permissions_tags_and_cache_rebuild_explicit() {
    assert_eq!(
        override_delete_transaction_plan().steps,
        vec![
            OverrideWriteStep::ResolveOperatorOwner,
            OverrideWriteStep::VerifyExistingOverrideMutable,
            OverrideWriteStep::ComputeAffectedReports,
            OverrideWriteStep::MoveOverrideToTrash,
            OverrideWriteStep::RelocatePermissionsAndTags,
            OverrideWriteStep::RebuildReportCaches,
        ]
    );
}
