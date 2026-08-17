#![forbid(unsafe_code)]

//! Strict validation for the exact `SessionReport` bytes accepted by the
//! Rescue vault. JSON Schemas in `packages/schemas` are the normative shape;
//! this crate adds transport framing, duplicate-key rejection and the one
//! cross-field binding JSON Schema cannot express.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Largest raw `SessionReport` JSON document the vault accepts.
pub const MAX_SESSION_REPORT_BYTES: usize = 1024 * 1024;
const MAX_SAFE_INTEGER_DECIMAL: &[u8] = b"9007199254740991";

/// Sanitized failure returned for an untrusted report document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionReportValidationError {
    /// The raw document is larger than the IPC and signing contract permits.
    InputTooLarge,
    /// The document is not one exact, schema-valid `SessionReport`.
    InvalidReport,
}

impl fmt::Display for SessionReportValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => formatter.write_str("session report exceeds the size limit"),
            Self::InvalidReport => formatter.write_str("invalid session report"),
        }
    }
}

impl Error for SessionReportValidationError {}

/// A schema- and semantics-validated report that retains the exact input bytes.
///
/// The bytes are deliberately never parsed and reserialized for signing. The
/// binding copies owned here are scrubbed on drop; `raw` remains borrowed, so
/// its owner remains responsible for scrubbing that input allocation.
pub struct ValidatedSessionReport<'a> {
    raw: &'a [u8],
    session_id: Zeroizing<String>,
    target_fingerprint: Zeroizing<String>,
}

impl ValidatedSessionReport<'_> {
    /// Exact validated bytes to hash, sign and persist.
    #[must_use]
    pub fn raw_json(&self) -> &[u8] {
        self.raw
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn target_fingerprint(&self) -> &str {
        &self.target_fingerprint
    }
}

impl fmt::Debug for ValidatedSessionReport<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedSessionReport")
            .field("raw_len", &self.raw.len())
            .finish_non_exhaustive()
    }
}

impl Zeroize for ValidatedSessionReport<'_> {
    fn zeroize(&mut self) {
        self.session_id.zeroize();
        self.target_fingerprint.zeroize();
    }
}

impl ZeroizeOnDrop for ValidatedSessionReport<'_> {}

/// Validate one raw JSON document without changing the bytes that will be
/// signed. Duplicate object keys are rejected recursively before schema
/// validation.
pub fn validate_session_report_json(
    raw: &[u8],
) -> Result<ValidatedSessionReport<'_>, SessionReportValidationError> {
    if raw.len() > MAX_SESSION_REPORT_BYTES {
        return Err(SessionReportValidationError::InputTooLarge);
    }
    let Ok(raw_text) = std::str::from_utf8(raw) else {
        return Err(SessionReportValidationError::InvalidReport);
    };
    if raw.contains(&0) {
        return Err(SessionReportValidationError::InvalidReport);
    }

    let sensitive = SensitiveJsonParser::parse_document(raw_text)
        .ok_or(SessionReportValidationError::InvalidReport)?;
    let binding =
        validate_session_report(&sensitive).ok_or(SessionReportValidationError::InvalidReport)?;
    Ok(ValidatedSessionReport {
        raw,
        session_id: protected_copy(binding.session_id),
        target_fingerprint: protected_copy(binding.target_fingerprint),
    })
}

fn protected_copy(value: &str) -> Zeroizing<String> {
    // Wrap the allocation before customer bytes are copied into it so every
    // return and unwind path scrubs the initialized buffer.
    let mut protected = Zeroizing::new(String::with_capacity(value.len()));
    protected.push_str(value);
    protected
}

struct SensitiveString(Zeroizing<String>);

impl SensitiveString {
    fn new(value: Zeroizing<String>) -> Self {
        Self(value)
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Borrow<str> for SensitiveString {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for SensitiveString {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for SensitiveString {}

impl PartialOrd for SensitiveString {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SensitiveString {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl Zeroize for SensitiveString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for SensitiveString {}

impl fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveString")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

type SensitiveObject = BTreeMap<SensitiveString, SensitiveValue>;

enum SensitiveValue {
    Null,
    Bool(bool),
    Number(SensitiveString),
    String(SensitiveString),
    Array(Zeroizing<Vec<Self>>),
    Object(SensitiveObject),
}

impl SensitiveValue {
    fn as_object(&self) -> Option<&SensitiveObject> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }

    fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(value) => Some(value.as_slice()),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value.as_str()),
            _ => None,
        }
    }

    fn as_number(&self) -> Option<&str> {
        match self {
            Self::Number(value) => Some(value.as_str()),
            _ => None,
        }
    }

    fn as_f64(&self) -> Option<f64> {
        self.as_number()?.parse().ok()
    }

    #[cfg(test)]
    fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }
}

impl Zeroize for SensitiveValue {
    fn zeroize(&mut self) {
        match self {
            Self::Null => {}
            Self::Bool(value) => value.zeroize(),
            Self::Number(value) => value.zeroize(),
            Self::String(value) => value.zeroize(),
            Self::Array(values) => values.zeroize(),
            Self::Object(values) => drop(std::mem::take(values)),
        }
    }
}

impl Drop for SensitiveValue {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SensitiveValue {}

impl fmt::Debug for SensitiveValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Null => "null",
            Self::Bool(_) => "bool",
            Self::Number(_) => "number",
            Self::String(_) => "string",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        };
        formatter
            .debug_struct("SensitiveValue")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

struct ReportBinding<'a> {
    session_id: &'a str,
    target_fingerprint: &'a str,
}

fn validate_session_report(value: &SensitiveValue) -> Option<ReportBinding<'_>> {
    let report = exact_object(
        value,
        &[
            "schemaVersion",
            "sessionId",
            "targetFingerprint",
            "facts",
            "inferences",
            "decisions",
            "events",
            "verification",
            "unresolvedRisks",
        ],
        &[],
    )?;
    if string(report, "schemaVersion")? != "1.0" {
        return None;
    }
    let session_id = string(report, "sessionId")?;
    if !prefixed_id(session_id, "S-", 128) {
        return None;
    }
    let target_fingerprint = string(report, "targetFingerprint")?;
    if !fingerprint(target_fingerprint) {
        return None;
    }

    let facts = array(report, "facts", 128)?;
    if !facts.iter().all(validate_evidence) {
        return None;
    }
    let inferences = array(report, "inferences", 128)?;
    if !inferences.iter().all(validate_diagnosis) {
        return None;
    }
    let decisions = array(report, "decisions", 128)?;
    if !decisions.iter().all(validate_approval) {
        return None;
    }
    let events = array(report, "events", 1024)?;
    if !events.iter().all(validate_execution_event) {
        return None;
    }
    if !matches!(
        string(report, "verification")?,
        "not-run" | "passed" | "failed"
    ) {
        return None;
    }
    if !unique_string_array(report.get("unresolvedRisks")?, 0, 128, 8192, |_| true) {
        return None;
    }

    Some(ReportBinding {
        session_id,
        target_fingerprint,
    })
}

fn validate_evidence(value: &SensitiveValue) -> bool {
    let Some(evidence) = exact_object(
        value,
        &[
            "schemaVersion",
            "id",
            "collector",
            "target",
            "capturedAt",
            "contentType",
            "sha256",
            "sensitivity",
            "trust",
            "summary",
            "blobRef",
        ],
        &[],
    ) else {
        return false;
    };
    let Some(digest) = string(evidence, "sha256") else {
        return false;
    };
    string(evidence, "schemaVersion") == Some("1.0")
        && string(evidence, "id").is_some_and(|value| prefixed_id(value, "E-", 128))
        && bounded_string(evidence, "collector", 1, 256)
        && bounded_string(evidence, "target", 1, 512)
        && string(evidence, "capturedAt").is_some_and(valid_rfc3339)
        && bounded_string(evidence, "contentType", 1, 256)
        && hash(digest)
        && matches!(
            string(evidence, "sensitivity"),
            Some("public" | "system" | "sensitive")
        )
        && string(evidence, "trust") == Some("observed-untrusted")
        && bounded_string(evidence, "summary", 0, 8192)
        && string(evidence, "blobRef")
            .is_some_and(|blob_ref| blob_ref.strip_prefix("sha256:") == Some(digest))
}

fn validate_diagnosis(value: &SensitiveValue) -> bool {
    let Some(diagnosis) = exact_object(
        value,
        &[
            "schemaVersion",
            "diagnosis",
            "confidence",
            "evidenceIds",
            "requestedEvidence",
        ],
        &[],
    ) else {
        return false;
    };
    string(diagnosis, "schemaVersion") == Some("1.0")
        && bounded_string(diagnosis, "diagnosis", 1, 16_384)
        && diagnosis
            .get("confidence")
            .and_then(SensitiveValue::as_f64)
            .is_some_and(|confidence| confidence.is_finite() && (0.0..=1.0).contains(&confidence))
        && unique_string_array(
            diagnosis
                .get("evidenceIds")
                .unwrap_or(&SensitiveValue::Null),
            1,
            128,
            128,
            |item| prefixed_id(item, "E-", 128),
        )
        && unique_string_array(
            diagnosis
                .get("requestedEvidence")
                .unwrap_or(&SensitiveValue::Null),
            0,
            128,
            256,
            |_| true,
        )
}

fn validate_approval(value: &SensitiveValue) -> bool {
    let Some(approval) = exact_object(
        value,
        &[
            "schemaVersion",
            "approvalId",
            "planId",
            "targetFingerprint",
            "approvedAt",
            "approvedBy",
        ],
        &["typedConfirmation"],
    ) else {
        return false;
    };
    string(approval, "schemaVersion") == Some("1.0")
        && string(approval, "approvalId").is_some_and(|value| prefixed_id(value, "A-", 128))
        && string(approval, "planId").is_some_and(|value| prefixed_id(value, "P-", 128))
        && string(approval, "targetFingerprint").is_some_and(fingerprint)
        && string(approval, "approvedAt").is_some_and(valid_rfc3339)
        && bounded_string(approval, "approvedBy", 1, 256)
        && approval
            .get("typedConfirmation")
            .is_none_or(|_| bounded_string(approval, "typedConfirmation", 1, 256))
}

fn validate_execution_event(value: &SensitiveValue) -> bool {
    let Some(event) = exact_object(
        value,
        &[
            "schemaVersion",
            "planId",
            "sequence",
            "status",
            "action",
            "message",
            "capturedAt",
        ],
        &[],
    ) else {
        return false;
    };
    string(event, "schemaVersion") == Some("1.0")
        && string(event, "planId").is_some_and(|value| prefixed_id(value, "P-", 128))
        && event.get("sequence").is_some_and(safe_positive_integer)
        && matches!(
            string(event, "status"),
            Some("started" | "succeeded" | "failed" | "rolled-back")
        )
        && string(event, "action").is_some_and(action_id)
        && bounded_string(event, "message", 0, 8192)
        && string(event, "capturedAt").is_some_and(valid_rfc3339)
}

fn exact_object<'a>(
    value: &'a SensitiveValue,
    required: &[&str],
    optional: &[&str],
) -> Option<&'a SensitiveObject> {
    let object = value.as_object()?;
    if required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return None;
    }
    Some(object)
}

fn string<'a>(object: &'a SensitiveObject, key: &str) -> Option<&'a str> {
    object.get(key)?.as_str()
}

fn bounded_string(object: &SensitiveObject, key: &str, minimum: usize, maximum: usize) -> bool {
    string(object, key).is_some_and(|value| {
        let length = value.chars().count();
        (minimum..=maximum).contains(&length)
    })
}

fn array<'a>(
    object: &'a SensitiveObject,
    key: &str,
    maximum: usize,
) -> Option<&'a [SensitiveValue]> {
    let values = object.get(key)?.as_array()?;
    (values.len() <= maximum).then_some(values)
}

fn unique_string_array<F>(
    value: &SensitiveValue,
    minimum_items: usize,
    maximum_items: usize,
    maximum_string_length: usize,
    validate: F,
) -> bool
where
    F: Fn(&str) -> bool,
{
    let Some(items) = value.as_array() else {
        return false;
    };
    if !(minimum_items..=maximum_items).contains(&items.len()) {
        return false;
    }
    let mut unique = BTreeSet::new();
    items.iter().all(|item| {
        item.as_str().is_some_and(|item| {
            item.chars().count() <= maximum_string_length && validate(item) && unique.insert(item)
        })
    })
}

fn prefixed_id(value: &str, prefix: &str, maximum: usize) -> bool {
    value.len() <= maximum
        && value
            .strip_prefix(prefix)
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(is_identifier_byte))
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn fingerprint(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(hash)
}

fn action_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

fn safe_positive_integer(value: &SensitiveValue) -> bool {
    value
        .as_number()
        .is_some_and(|number| exact_positive_safe_integer(number.as_bytes()))
}

fn valid_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || !matches!(bytes.get(10), Some(b'T' | b't'))
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || decimal(bytes, 17, 2).is_none()
    {
        return false;
    }

    let Some(year) = decimal(bytes, 0, 4) else {
        return false;
    };
    let Some(month) = decimal(bytes, 5, 2) else {
        return false;
    };
    let Some(day) = decimal(bytes, 8, 2) else {
        return false;
    };
    let Some(hour) = decimal(bytes, 11, 2) else {
        return false;
    };
    let Some(minute) = decimal(bytes, 14, 2) else {
        return false;
    };
    let mut offset = 19;
    if bytes.get(offset) == Some(&b'.') {
        offset += 1;
        let fraction_start = offset;
        while bytes.get(offset).is_some_and(u8::is_ascii_digit) {
            offset += 1;
        }
        if offset == fraction_start {
            return false;
        }
    }
    let Ok(second) = value[17..offset].parse::<f64>() else {
        return false;
    };

    let (timezone_sign, timezone_hour, timezone_minute) = match bytes.get(offset) {
        Some(b'Z' | b'z') if offset + 1 == bytes.len() => (1_i32, 0_i32, 0_i32),
        Some(sign @ (b'+' | b'-'))
            if offset + 6 == bytes.len() && bytes.get(offset + 3) == Some(&b':') =>
        {
            let Some(timezone_hour) = decimal(bytes, offset + 1, 2) else {
                return false;
            };
            let Some(timezone_minute) = decimal(bytes, offset + 4, 2) else {
                return false;
            };
            (
                if *sign == b'-' { -1 } else { 1 },
                timezone_hour as i32,
                timezone_minute as i32,
            )
        }
        _ => return false,
    };

    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year(year) => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0
        || day > days_in_month
        || hour > 23
        || minute > 59
        || timezone_hour > 23
        || timezone_minute > 59
    {
        return false;
    }
    if second < 60.0 {
        return true;
    }
    if second >= 61.0 {
        return false;
    }

    let utc_minute = minute as i32 - timezone_minute * timezone_sign;
    let utc_hour = hour as i32 - timezone_hour * timezone_sign - i32::from(utc_minute < 0);
    matches!(utc_hour, 23 | -1) && matches!(utc_minute, 59 | -1)
}

fn decimal(bytes: &[u8], offset: usize, length: usize) -> Option<u32> {
    let digits = bytes.get(offset..offset.checked_add(length)?)?;
    digits.iter().try_fold(0_u32, |value, digit| {
        digit
            .is_ascii_digit()
            .then_some(value * 10 + u32::from(*digit - b'0'))
    })
}

fn leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

#[derive(Clone, Copy)]
enum ReportJsonContext {
    Root,
    Events,
    Event,
    Sequence,
    Inferences,
    Inference,
    Confidence,
    Other,
}

impl ReportJsonContext {
    fn object_value(self, key: &str) -> Self {
        match (self, key) {
            (Self::Root, "events") => Self::Events,
            (Self::Root, "inferences") => Self::Inferences,
            (Self::Event, "sequence") => Self::Sequence,
            (Self::Inference, "confidence") => Self::Confidence,
            _ => Self::Other,
        }
    }

    fn array_item(self) -> Self {
        match self {
            Self::Events => Self::Event,
            Self::Inferences => Self::Inference,
            _ => Self::Other,
        }
    }
}

struct ExactDecimal {
    negative: bool,
    coefficient: Zeroizing<Vec<u8>>,
    scale: i64,
}

fn exact_decimal(token: &[u8]) -> Option<ExactDecimal> {
    let (negative, unsigned) = match token.first() {
        Some(b'-') => (true, token.get(1..)?),
        Some(_) => (false, token),
        None => return None,
    };
    let (significand, exponent) = token_partition(unsigned, b'e', b'E');
    let exponent = exponent.map_or(Some(0), bounded_exponent)?;
    let (integer, fraction) = token_partition(significand, b'.', b'.');
    let fraction = fraction.unwrap_or_default();
    if integer.is_empty()
        || !integer.iter().all(u8::is_ascii_digit)
        || (!fraction.is_empty() && !fraction.iter().all(u8::is_ascii_digit))
    {
        return None;
    }
    let capacity = integer.len().checked_add(fraction.len())?;
    let mut coefficient = Zeroizing::new(Vec::with_capacity(capacity));
    coefficient.extend(
        integer
            .iter()
            .chain(fraction)
            .copied()
            .skip_while(|digit| *digit == b'0'),
    );
    Some(ExactDecimal {
        negative,
        coefficient,
        scale: exponent.checked_sub(i64::try_from(fraction.len()).ok()?)?,
    })
}

fn token_partition(token: &[u8], first: u8, second: u8) -> (&[u8], Option<&[u8]>) {
    token
        .iter()
        .position(|byte| *byte == first || *byte == second)
        .map_or((token, None), |offset| {
            (&token[..offset], token.get(offset + 1..))
        })
}

fn bounded_exponent(exponent: &[u8]) -> Option<i64> {
    let (negative, digits) = match exponent.first() {
        Some(b'-') => (true, exponent.get(1..)?),
        Some(b'+') => (false, exponent.get(1..)?),
        Some(_) => (false, exponent),
        None => return None,
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let cap = i64::try_from(MAX_SESSION_REPORT_BYTES)
        .ok()?
        .checked_add(1)?;
    let mut magnitude = 0_i64;
    for digit in digits {
        let digit = i64::from(*digit - b'0');
        magnitude = magnitude
            .checked_mul(10)
            .and_then(|value| value.checked_add(digit))
            .unwrap_or(cap)
            .min(cap);
    }
    Some(if negative { -magnitude } else { magnitude })
}

fn exact_positive_safe_integer(token: &[u8]) -> bool {
    let Some(decimal) = exact_decimal(token) else {
        return false;
    };
    if decimal.negative || decimal.coefficient.is_empty() {
        return false;
    }

    let integer = if decimal.scale >= 0 {
        let Some(scale) = usize::try_from(decimal.scale).ok() else {
            return false;
        };
        let Some(length) = decimal.coefficient.len().checked_add(scale) else {
            return false;
        };
        if length > MAX_SAFE_INTEGER_DECIMAL.len() {
            return false;
        }
        let mut integer = Zeroizing::new(Vec::with_capacity(length));
        integer.extend_from_slice(&decimal.coefficient);
        integer.resize(length, b'0');
        integer
    } else {
        let Some(decimal_places) = usize::try_from(-decimal.scale).ok() else {
            return false;
        };
        if decimal_places >= decimal.coefficient.len() {
            return false;
        }
        let integer_length = decimal.coefficient.len() - decimal_places;
        if !decimal.coefficient[integer_length..]
            .iter()
            .all(|digit| *digit == b'0')
        {
            return false;
        }
        let mut integer = Zeroizing::new(Vec::with_capacity(integer_length));
        integer.extend_from_slice(&decimal.coefficient[..integer_length]);
        integer
    };
    integer.len() < MAX_SAFE_INTEGER_DECIMAL.len()
        || (integer.len() == MAX_SAFE_INTEGER_DECIMAL.len()
            && integer.as_slice() <= MAX_SAFE_INTEGER_DECIMAL)
}

fn exact_confidence(token: &[u8]) -> bool {
    let Some(decimal) = exact_decimal(token) else {
        return false;
    };
    if decimal.coefficient.is_empty() {
        return true;
    }
    if decimal.negative {
        return false;
    }
    let Some(integer_digits) = i64::try_from(decimal.coefficient.len())
        .ok()
        .and_then(|length| length.checked_add(decimal.scale))
    else {
        return false;
    };
    if integer_digits <= 0 {
        return true;
    }
    integer_digits == 1
        && decimal.coefficient[0] == b'1'
        && decimal.coefficient[1..].iter().all(|digit| *digit == b'0')
}

/// Narrow JSON parser for the customer-data-bearing report. It never asks
/// serde_json to decode a string, so escaped customer bytes cannot enter
/// serde_json's ordinary scratch allocation. Every decoded string is
/// written directly into an already-`Zeroizing` allocation.
struct SensitiveJsonParser<'a> {
    raw: &'a str,
    offset: usize,
}

impl<'a> SensitiveJsonParser<'a> {
    fn parse_document(raw: &'a str) -> Option<SensitiveValue> {
        let mut parser = Self { raw, offset: 0 };
        let value = parser.parse_value(0, ReportJsonContext::Root)?;
        parser.skip_whitespace();
        (parser.offset == raw.len()).then_some(value)
    }

    fn parse_value(&mut self, depth: usize, context: ReportJsonContext) -> Option<SensitiveValue> {
        if depth > 64 {
            return None;
        }
        self.skip_whitespace();
        match self.byte()? {
            b'{' => self.parse_object(depth + 1, context),
            b'[' => self.parse_array(depth + 1, context),
            b'"' => self.parse_string().map(SensitiveValue::String),
            b'-' | b'0'..=b'9' => self.parse_number(context),
            b't' => {
                self.consume_literal(b"true")?;
                Some(SensitiveValue::Bool(true))
            }
            b'f' => {
                self.consume_literal(b"false")?;
                Some(SensitiveValue::Bool(false))
            }
            b'n' => {
                self.consume_literal(b"null")?;
                Some(SensitiveValue::Null)
            }
            _ => None,
        }
    }

    fn parse_object(&mut self, depth: usize, context: ReportJsonContext) -> Option<SensitiveValue> {
        self.consume_byte(b'{')?;
        self.skip_whitespace();
        let mut values = SensitiveObject::new();
        if self.byte() == Some(b'}') {
            self.offset += 1;
            return Some(SensitiveValue::Object(values));
        }

        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            if values.contains_key(key.as_str()) {
                return None;
            }
            self.skip_whitespace();
            self.consume_byte(b':')?;
            let value = self.parse_value(depth, context.object_value(key.as_str()))?;
            if values.insert(key, value).is_some() {
                return None;
            }
            self.skip_whitespace();
            match self.byte()? {
                b'}' => {
                    self.offset += 1;
                    return Some(SensitiveValue::Object(values));
                }
                b',' => self.offset += 1,
                _ => return None,
            }
        }
    }

    fn parse_array(&mut self, depth: usize, context: ReportJsonContext) -> Option<SensitiveValue> {
        self.consume_byte(b'[')?;
        self.skip_whitespace();
        let mut values = Zeroizing::new(Vec::new());
        if self.byte() == Some(b']') {
            self.offset += 1;
            return Some(SensitiveValue::Array(values));
        }

        loop {
            values.push(self.parse_value(depth, context.array_item())?);
            self.skip_whitespace();
            match self.byte()? {
                b']' => {
                    self.offset += 1;
                    return Some(SensitiveValue::Array(values));
                }
                b',' => self.offset += 1,
                _ => return None,
            }
        }
    }

    fn parse_string(&mut self) -> Option<SensitiveString> {
        let opening = self.offset;
        self.consume_byte(b'"')?;
        let closing = self.string_closing_quote(opening)?;
        let raw_content_len = closing.checked_sub(self.offset)?;
        let mut decoded = Zeroizing::new(String::with_capacity(raw_content_len));

        while self.offset < closing {
            match self.byte()? {
                b'\\' => {
                    self.offset += 1;
                    match self.byte()? {
                        b'"' => decoded.push('"'),
                        b'\\' => decoded.push('\\'),
                        b'/' => decoded.push('/'),
                        b'b' => decoded.push('\u{0008}'),
                        b'f' => decoded.push('\u{000c}'),
                        b'n' => decoded.push('\n'),
                        b'r' => decoded.push('\r'),
                        b't' => decoded.push('\t'),
                        b'u' => {
                            self.offset += 1;
                            let first = self.parse_hex_quad()?;
                            let codepoint = if (0xd800..=0xdbff).contains(&first) {
                                self.consume_byte(b'\\')?;
                                self.consume_byte(b'u')?;
                                let second = self.parse_hex_quad()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return None;
                                }
                                0x1_0000
                                    + ((u32::from(first) - 0xd800) << 10)
                                    + (u32::from(second) - 0xdc00)
                            } else if (0xdc00..=0xdfff).contains(&first) {
                                return None;
                            } else {
                                u32::from(first)
                            };
                            decoded.push(char::from_u32(codepoint)?);
                            continue;
                        }
                        _ => return None,
                    }
                    self.offset += 1;
                }
                0..=0x1f => return None,
                _ => {
                    let character = self.raw.get(self.offset..closing)?.chars().next()?;
                    decoded.push(character);
                    self.offset += character.len_utf8();
                }
            }
        }
        self.consume_byte(b'"')?;
        Some(SensitiveString::new(decoded))
    }

    fn string_closing_quote(&self, opening: usize) -> Option<usize> {
        let bytes = self.raw.as_bytes();
        let mut cursor = opening.checked_add(1)?;
        loop {
            match *bytes.get(cursor)? {
                b'"' => return Some(cursor),
                b'\\' => {
                    cursor = cursor.checked_add(1)?;
                    let escaped = *bytes.get(cursor)?;
                    cursor = cursor.checked_add(1)?;
                    if escaped == b'u' {
                        let end = cursor.checked_add(4)?;
                        bytes.get(cursor..end)?;
                        cursor = end;
                    }
                }
                0..=0x1f => return None,
                _ => cursor = cursor.checked_add(1)?,
            }
        }
    }

    fn parse_hex_quad(&mut self) -> Option<u16> {
        let end = self.offset.checked_add(4)?;
        let digits = self.raw.as_bytes().get(self.offset..end)?;
        let mut value = 0_u16;
        for digit in digits {
            value = value.checked_mul(16)?.checked_add(match digit {
                b'0'..=b'9' => u16::from(*digit - b'0'),
                b'a'..=b'f' => u16::from(*digit - b'a' + 10),
                b'A'..=b'F' => u16::from(*digit - b'A' + 10),
                _ => return None,
            })?;
        }
        self.offset = end;
        Some(value)
    }

    fn parse_number(&mut self, context: ReportJsonContext) -> Option<SensitiveValue> {
        let token = self.parse_number_token()?;
        let text = std::str::from_utf8(token).ok()?;
        if !text.parse::<f64>().ok().is_some_and(f64::is_finite) {
            return None;
        }
        match context {
            ReportJsonContext::Sequence if !exact_positive_safe_integer(token) => return None,
            ReportJsonContext::Confidence if !exact_confidence(token) => return None,
            _ => {}
        }
        Some(SensitiveValue::Number(SensitiveString::new(
            protected_copy(text),
        )))
    }

    fn parse_number_token(&mut self) -> Option<&'a [u8]> {
        let start = self.offset;
        if self.byte() == Some(b'-') {
            self.offset += 1;
        }
        match self.byte()? {
            b'0' => self.offset += 1,
            b'1'..=b'9' => {
                self.offset += 1;
                while self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.offset += 1;
                }
            }
            _ => return None,
        }
        if self.byte() == Some(b'.') {
            self.offset += 1;
            let fraction_start = self.offset;
            while self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                self.offset += 1;
            }
            if self.offset == fraction_start {
                return None;
            }
        }
        if matches!(self.byte(), Some(b'e' | b'E')) {
            self.offset += 1;
            if matches!(self.byte(), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            let exponent_start = self.offset;
            while self.byte().is_some_and(|byte| byte.is_ascii_digit()) {
                self.offset += 1;
            }
            if self.offset == exponent_start {
                return None;
            }
        }
        self.raw.as_bytes().get(start..self.offset)
    }

    fn consume_literal(&mut self, literal: &[u8]) -> Option<()> {
        let end = self.offset.checked_add(literal.len())?;
        if self.raw.as_bytes().get(self.offset..end)? != literal {
            return None;
        }
        self.offset = end;
        Some(())
    }

    fn consume_byte(&mut self, expected: u8) -> Option<()> {
        if self.byte() != Some(expected) {
            return None;
        }
        self.offset += 1;
        Some(())
    }

    fn byte(&self) -> Option<u8> {
        self.raw.as_bytes().get(self.offset).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.byte(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.offset += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    const VALID: &[u8] = br#"{
      "schemaVersion":"1.0",
      "sessionId":"S-test",
      "targetFingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "facts":[{
        "schemaVersion":"1.0",
        "id":"E-1",
        "collector":"test",
        "target":"offline-system",
        "capturedAt":"2026-08-17T12:34:56Z",
        "contentType":"text/plain",
        "sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "sensitivity":"system",
        "trust":"observed-untrusted",
        "summary":"observed",
        "blobRef":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      }],
      "inferences":[],
      "decisions":[],
      "events":[],
      "verification":"not-run",
      "unresolvedRisks":[]
    }"#;

    #[test]
    fn exact_raw_bytes_are_retained_without_debugging_content() {
        let mut report = validate_session_report_json(VALID).expect("valid report");
        assert_eq!(report.raw_json(), VALID);
        assert_eq!(report.session_id(), "S-test");
        assert_eq!(
            report.target_fingerprint(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(format!("{report:?}").contains("raw_len"));
        assert!(!format!("{report:?}").contains("S-test"));
        assert!(!format!("{report:?}").contains("observed"));

        report.zeroize();
        assert!(report.session_id().is_empty());
        assert!(report.target_fingerprint().is_empty());
        assert_eq!(
            report.raw_json(),
            VALID,
            "borrowed bytes remain caller-owned"
        );
    }

    #[test]
    fn duplicate_keys_and_trailing_documents_are_rejected() {
        let duplicate = br#"{
          "schemaVersion":"1.0",
          "schema\u0056ersion":"1.0"
        }"#;
        assert_eq!(
            validate_session_report_json(duplicate).expect_err("duplicate must fail"),
            SessionReportValidationError::InvalidReport
        );
        let mut trailing = Zeroizing::new(Vec::with_capacity(VALID.len() + 2));
        trailing.extend_from_slice(VALID);
        trailing.extend_from_slice(b"{}");
        assert_eq!(
            validate_session_report_json(&trailing).expect_err("trailing JSON must fail"),
            SessionReportValidationError::InvalidReport
        );
    }

    #[test]
    fn oversized_input_has_a_sanitized_error() {
        let oversized = vec![b' '; MAX_SESSION_REPORT_BYTES + 1];
        assert_eq!(
            validate_session_report_json(&oversized).expect_err("oversized report must fail"),
            SessionReportValidationError::InputTooLarge
        );
        assert_eq!(
            SessionReportValidationError::InputTooLarge.to_string(),
            "session report exceeds the size limit"
        );
    }

    #[test]
    fn decoded_strings_follow_json_escape_and_surrogate_semantics() {
        let escaped = std::str::from_utf8(VALID)
            .expect("fixture is UTF-8")
            .replace("S-test", r"S-te\u0073t");
        let report = validate_session_report_json(escaped.as_bytes()).expect("escaped id is valid");
        assert_eq!(report.session_id(), "S-test");

        for malformed in [
            br#"{"value":"\ud800"}"#.as_slice(),
            br#"{"value":"\udc00"}"#.as_slice(),
            br#"{"value":"\ud800\u0041"}"#.as_slice(),
            br#"{"value":"\q"}"#.as_slice(),
        ] {
            assert!(
                SensitiveJsonParser::parse_document(
                    std::str::from_utf8(malformed).expect("ASCII fixture")
                )
                .is_none()
            );
        }

        let pair = SensitiveJsonParser::parse_document(r#"{"value":"\ud83d\ude80"}"#)
            .expect("valid surrogate pair");
        assert_eq!(
            pair.as_object()
                .and_then(|object| object.get("value"))
                .and_then(SensitiveValue::as_str),
            Some("🚀")
        );
    }

    #[test]
    fn partial_nested_errors_duplicates_unknown_fields_and_trailing_data_are_sanitized() {
        const SECRET: &str = "MEMORY-HYGIENE-SECRET-71d3";
        let partial_documents: &[&str] = &[
            r#"{"outer":{"secret":"MEMORY-HYGIENE-SECRET-71d3","broken":["array-secret",]}}"#,
            r#"{"outer":{"secret":"MEMORY-HYGIENE-SECRET-71d3","secr\u0065t":"duplicate"}}"#,
            r#"{"outer":{"secret":"MEMORY-HYGIENE-SECRET-71d3","nested":{"later":"nested-secret","bad":]}}}"#,
        ];
        for raw in partial_documents {
            assert!(SensitiveJsonParser::parse_document(raw).is_none());
            let error = validate_session_report_json(raw.as_bytes())
                .expect_err("partial customer tree must fail");
            let diagnostic = format!("{error:?}: {error}");
            assert!(!diagnostic.contains(SECRET));
            assert!(!diagnostic.contains("array-secret"));
            assert!(!diagnostic.contains("nested-secret"));
        }

        let valid = std::str::from_utf8(VALID).expect("fixture is UTF-8");
        let closing = valid.rfind('}').expect("root closing brace");
        let unknown_suffix = format!(r#", "unknownSecret":"{SECRET}""#);
        let mut unknown = Zeroizing::new(String::with_capacity(valid.len() + unknown_suffix.len()));
        unknown.push_str(&valid[..closing]);
        unknown.push_str(&unknown_suffix);
        unknown.push_str(&valid[closing..]);
        let unknown_error = validate_session_report_json(unknown.as_bytes())
            .expect_err("unknown final field must fail");
        assert!(!format!("{unknown_error:?}: {unknown_error}").contains(SECRET));

        let trailing_suffix = format!(r#" {{"trailing":"{SECRET}"}}"#);
        let mut trailing =
            Zeroizing::new(String::with_capacity(valid.len() + trailing_suffix.len()));
        trailing.push_str(valid);
        trailing.push_str(&trailing_suffix);
        let trailing_error = validate_session_report_json(trailing.as_bytes())
            .expect_err("trailing customer tree must fail");
        assert!(!format!("{trailing_error:?}: {trailing_error}").contains(SECRET));
    }

    #[test]
    fn sensitive_tree_debug_and_drop_contracts_are_redacted() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<SensitiveString>();
        assert_zeroize_on_drop::<SensitiveValue>();
        assert_zeroize_on_drop::<ValidatedSessionReport<'static>>();

        let mut parsed = SensitiveJsonParser::parse_document(
            r#"{"secret":"TREE-SECRET-29a1","items":["ARRAY-SECRET",17]}"#,
        )
        .expect("sensitive tree");
        let debug = format!("{parsed:?}");
        assert!(!debug.contains("TREE-SECRET-29a1"));
        assert!(!debug.contains("ARRAY-SECRET"));
        let secret = parsed
            .as_object()
            .and_then(|object| object.get("secret"))
            .expect("secret member");
        assert!(!format!("{secret:?}").contains("TREE-SECRET-29a1"));

        parsed.zeroize();
        assert!(parsed.as_object().is_some_and(BTreeMap::is_empty));
    }

    #[test]
    fn production_parser_has_no_plain_customer_string_or_vec_deserializer_path() {
        let source = include_str!("lib.rs");
        let production = source
            .split_once("\n#[cfg(test)]\nmod tests")
            .expect("test module boundary")
            .0;
        let serde_value = ["serde_json::", "Value"].concat();
        let derived_tree = ["Unique", "Value"].concat();

        for forbidden in [
            serde_value.as_str(),
            derived_tree.as_str(),
            "serde_json::from_slice",
            "serde_json::from_str",
            ".to_owned()",
            ".to_vec()",
            "format!(",
            "Option<String>",
            "Vec<String>",
        ] {
            assert!(
                !production.contains(forbidden),
                "plain customer allocation/deserializer path remains: {forbidden}"
            );
        }
        assert_eq!(
            production.matches("String::with_capacity").count(),
            production
                .matches("Zeroizing::new(String::with_capacity")
                .count(),
            "every owned string must be protected before its first write"
        );
        assert_eq!(
            production.matches("Vec::").count(),
            production.matches("Zeroizing::new(Vec::").count(),
            "every vector allocation must be protected before its first write"
        );
        for line in production.lines().filter(|line| line.contains("Vec<")) {
            assert!(
                line.contains("Zeroizing<Vec<"),
                "plain owned vector field remains: {line}"
            );
        }
        for required in [
            "impl Drop for SensitiveValue",
            "Self::Object(values) => drop(std::mem::take(values))",
            "if values.contains_key(key.as_str())",
            "let mut decoded = Zeroizing::new(String::with_capacity",
            "let mut values = Zeroizing::new(Vec::new())",
            "session_id: protected_copy(binding.session_id)",
            "target_fingerprint: protected_copy(binding.target_fingerprint)",
        ] {
            assert!(
                production.contains(required),
                "missing RAII guard: {required}"
            );
        }
    }

    #[test]
    fn rust_matches_the_shared_golden_corpus() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packages/schemas/testdata/session-report");
        let manifest_bytes = fs::read(root.join("manifest.json")).expect("read golden manifest");
        let manifest_text = std::str::from_utf8(&manifest_bytes).expect("UTF-8 golden manifest");
        let manifest = SensitiveJsonParser::parse_document(manifest_text)
            .expect("parse golden manifest without serde scratch");
        let manifest = exact_object(&manifest, &["schemaVersion", "cases"], &[])
            .expect("exact golden manifest");
        assert_eq!(
            manifest
                .get("schemaVersion")
                .and_then(SensitiveValue::as_number),
            Some("1")
        );
        let cases = manifest
            .get("cases")
            .and_then(SensitiveValue::as_array)
            .expect("golden cases");
        assert_eq!(cases.len(), 115, "all shared corpus cases must run");
        for case in cases {
            let case =
                exact_object(case, &["name", "valid", "file"], &[]).expect("exact golden case");
            let name = string(case, "name").expect("case name");
            let expected = case
                .get("valid")
                .and_then(SensitiveValue::as_bool)
                .expect("case result");
            let file = string(case, "file").expect("case file");
            let raw = fs::read(root.join(file)).expect("read golden case");
            assert_eq!(
                validate_session_report_json(&raw).is_ok(),
                expected,
                "golden case {name}"
            );
        }
    }
}
