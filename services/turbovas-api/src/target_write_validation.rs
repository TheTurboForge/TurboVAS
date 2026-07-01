// SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use serde::Deserialize;

use crate::errors::ApiError;

pub(crate) const MAX_TARGET_TEXT_BYTES: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetPatchRequest {
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    #[serde(default)]
    pub(crate) alive_tests: Option<Vec<String>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ValidatedTargetPatch {
    pub(crate) name: Option<String>,
    pub(crate) comment: Option<String>,
    pub(crate) alive_test: Option<i32>,
}

pub(crate) fn validate_target_patch_request(
    request: TargetPatchRequest,
) -> Result<ValidatedTargetPatch, ApiError> {
    let validated = ValidatedTargetPatch {
        name: normalize_optional_required_target_text(request.name, "name")?,
        comment: normalize_optional_target_text(request.comment, "comment")?,
        alive_test: validate_alive_tests(request.alive_tests)?,
    };
    if validated.name.is_none() && validated.comment.is_none() && validated.alive_test.is_none() {
        return Err(ApiError::BadRequest(
            "target patch request must include at least one field".to_string(),
        ));
    }
    Ok(validated)
}

fn normalize_optional_required_target_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_required_target_text(value, field_name))
        .transpose()
}

fn normalize_required_target_text(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = normalize_target_text_value(value, field_name)?;
    if value.is_empty() {
        Err(ApiError::BadRequest(format!("{field_name} is required")))
    } else {
        Ok(value)
    }
}

fn normalize_optional_target_text(
    value: Option<String>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    value
        .map(|value| normalize_target_text_value(value, field_name))
        .transpose()
}

fn normalize_target_text_value(value: String, field_name: &str) -> Result<String, ApiError> {
    let value = value.trim().to_string();
    if value.len() > MAX_TARGET_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(ApiError::BadRequest(format!(
            "{field_name} must be printable text up to {MAX_TARGET_TEXT_BYTES} bytes"
        )));
    }
    Ok(value)
}

pub(crate) fn validate_alive_tests(value: Option<Vec<String>>) -> Result<Option<i32>, ApiError> {
    let Some(values) = value else {
        return Ok(None);
    };
    if values.is_empty() {
        return Ok(Some(0));
    }
    let mut bitfield = 0;
    let mut saw_default = false;
    let mut saw_consider_alive = false;
    for value in values {
        match value.as_str() {
            "Scan Config Default" => saw_default = true,
            "Consider Alive" => saw_consider_alive = true,
            "TCP-ACK Service Ping" => bitfield |= 1,
            "ICMP Ping" => bitfield |= 2,
            "ARP Ping" => bitfield |= 4,
            "TCP-SYN Service Ping" => bitfield |= 16,
            _ => {
                return Err(ApiError::BadRequest(format!(
                    "unsupported alive_tests value: {value}"
                )));
            }
        }
    }
    if saw_default && (saw_consider_alive || bitfield != 0) {
        return Err(ApiError::BadRequest(
            "Scan Config Default cannot be combined with other alive_tests values".to_string(),
        ));
    }
    if saw_consider_alive && bitfield != 0 {
        return Err(ApiError::BadRequest(
            "Consider Alive cannot be combined with probe alive_tests values".to_string(),
        ));
    }
    if saw_default {
        Ok(Some(0))
    } else if saw_consider_alive {
        Ok(Some(8))
    } else {
        Ok(Some(bitfield))
    }
}
