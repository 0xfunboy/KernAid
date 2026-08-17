#![forbid(unsafe_code)]

//! Strict validation for the exact `SessionReport` bytes accepted by the
//! Rescue vault. JSON Schemas in `packages/schemas` are the normative shape;
//! this crate adds transport framing, duplicate-key rejection and the one
//! cross-field binding JSON Schema cannot express.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// Largest raw `SessionReport` JSON document the vault accepts.
pub const MAX_SESSION_REPORT_BYTES: usize = 1024 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
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
/// The bytes are deliberately never parsed and reserialized for signing.
pub struct ValidatedSessionReport<'a> {
    raw: &'a [u8],
    session_id: String,
    target_fingerprint: String,
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

/// Validate one raw JSON document without changing the bytes that will be
/// signed. Duplicate object keys are rejected recursively before schema
/// validation.
pub fn validate_session_report_json(
    raw: &[u8],
) -> Result<ValidatedSessionReport<'_>, SessionReportValidationError> {
    if raw.len() > MAX_SESSION_REPORT_BYTES {
        return Err(SessionReportValidationError::InputTooLarge);
    }
    if raw.contains(&0) || std::str::from_utf8(raw).is_err() {
        return Err(SessionReportValidationError::InvalidReport);
    }
    if !exact_report_numbers_are_valid(raw) {
        return Err(SessionReportValidationError::InvalidReport);
    }

    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let unique = UniqueValue::deserialize(&mut deserializer)
        .map_err(|_| SessionReportValidationError::InvalidReport)?;
    deserializer
        .end()
        .map_err(|_| SessionReportValidationError::InvalidReport)?;

    let binding =
        validate_session_report(&unique.0).ok_or(SessionReportValidationError::InvalidReport)?;
    Ok(ValidatedSessionReport {
        raw,
        session_id: binding.session_id.to_owned(),
        target_fingerprint: binding.target_fingerprint.to_owned(),
    })
}

struct ReportBinding<'a> {
    session_id: &'a str,
    target_fingerprint: &'a str,
}

fn validate_session_report(value: &Value) -> Option<ReportBinding<'_>> {
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

fn validate_evidence(value: &Value) -> bool {
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
            .is_some_and(|blob_ref| blob_ref == format!("sha256:{digest}"))
}

fn validate_diagnosis(value: &Value) -> bool {
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
            .and_then(Value::as_f64)
            .is_some_and(|confidence| confidence.is_finite() && (0.0..=1.0).contains(&confidence))
        && unique_string_array(
            diagnosis.get("evidenceIds").unwrap_or(&Value::Null),
            1,
            128,
            128,
            |item| prefixed_id(item, "E-", 128),
        )
        && unique_string_array(
            diagnosis.get("requestedEvidence").unwrap_or(&Value::Null),
            0,
            128,
            256,
            |_| true,
        )
}

fn validate_approval(value: &Value) -> bool {
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

fn validate_execution_event(value: &Value) -> bool {
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
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Option<&'a Map<String, Value>> {
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

fn string<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key)?.as_str()
}

fn bounded_string(object: &Map<String, Value>, key: &str, minimum: usize, maximum: usize) -> bool {
    string(object, key).is_some_and(|value| {
        let length = value.chars().count();
        (minimum..=maximum).contains(&length)
    })
}

fn array<'a>(object: &'a Map<String, Value>, key: &str, maximum: usize) -> Option<&'a Vec<Value>> {
    let values = object.get(key)?.as_array()?;
    (values.len() <= maximum).then_some(values)
}

fn unique_string_array<F>(
    value: &Value,
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

fn safe_positive_integer(value: &Value) -> bool {
    let Some(number) = value.as_number() else {
        return false;
    };
    if let Some(integer) = number.as_u64() {
        return (1..=MAX_SAFE_INTEGER).contains(&integer);
    }
    number.as_f64().is_some_and(|number| {
        number.is_finite()
            && number.fract() == 0.0
            && number >= 1.0
            && number <= MAX_SAFE_INTEGER as f64
    })
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
    coefficient: Vec<u8>,
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
    let coefficient = integer
        .iter()
        .chain(fraction)
        .copied()
        .skip_while(|digit| *digit == b'0')
        .collect();
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
        let mut integer = decimal.coefficient;
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
        decimal.coefficient[..integer_length].to_vec()
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

fn exact_report_numbers_are_valid(raw: &[u8]) -> bool {
    let mut scanner = ReportJsonScanner { raw, offset: 0 };
    if scanner.parse_value(0, ReportJsonContext::Root).is_none() {
        return false;
    }
    scanner.skip_whitespace();
    scanner.offset == raw.len()
}

struct ReportJsonScanner<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> ReportJsonScanner<'a> {
    fn parse_value(&mut self, depth: usize, context: ReportJsonContext) -> Option<()> {
        if depth > 64 {
            return None;
        }
        self.skip_whitespace();
        match self.raw.get(self.offset)? {
            b'{' => self.parse_object(depth + 1, context),
            b'[' => self.parse_array(depth + 1, context),
            b'"' => self.parse_string_token().map(drop),
            b'-' | b'0'..=b'9' => {
                let token = self.parse_number_token()?;
                match context {
                    ReportJsonContext::Sequence if !exact_positive_safe_integer(token) => None,
                    ReportJsonContext::Confidence if !exact_confidence(token) => None,
                    _ => Some(()),
                }
            }
            b't' => self.consume_literal(b"true"),
            b'f' => self.consume_literal(b"false"),
            b'n' => self.consume_literal(b"null"),
            _ => None,
        }
    }

    fn parse_object(&mut self, depth: usize, context: ReportJsonContext) -> Option<()> {
        self.offset += 1;
        self.skip_whitespace();
        if self.raw.get(self.offset) == Some(&b'}') {
            self.offset += 1;
            return Some(());
        }
        loop {
            self.skip_whitespace();
            let key_token = self.parse_string_token()?;
            let key = serde_json::from_slice::<String>(key_token).ok()?;
            self.skip_whitespace();
            self.consume_byte(b':')?;
            self.parse_value(depth, context.object_value(&key))?;
            self.skip_whitespace();
            match self.raw.get(self.offset)? {
                b'}' => {
                    self.offset += 1;
                    return Some(());
                }
                b',' => self.offset += 1,
                _ => return None,
            }
        }
    }

    fn parse_array(&mut self, depth: usize, context: ReportJsonContext) -> Option<()> {
        self.offset += 1;
        self.skip_whitespace();
        if self.raw.get(self.offset) == Some(&b']') {
            self.offset += 1;
            return Some(());
        }
        loop {
            self.parse_value(depth, context.array_item())?;
            self.skip_whitespace();
            match self.raw.get(self.offset)? {
                b']' => {
                    self.offset += 1;
                    return Some(());
                }
                b',' => self.offset += 1,
                _ => return None,
            }
        }
    }

    fn parse_string_token(&mut self) -> Option<&'a [u8]> {
        let start = self.offset;
        self.consume_byte(b'"')?;
        loop {
            let byte = *self.raw.get(self.offset)?;
            match byte {
                b'"' => {
                    self.offset += 1;
                    return self.raw.get(start..self.offset);
                }
                b'\\' => {
                    self.offset += 1;
                    let escaped = *self.raw.get(self.offset)?;
                    self.offset += 1;
                    if escaped == b'u' {
                        let end = self.offset.checked_add(4)?;
                        self.raw.get(self.offset..end)?;
                        self.offset = end;
                    }
                }
                0..=0x1f => return None,
                _ => self.offset += 1,
            }
        }
    }

    fn parse_number_token(&mut self) -> Option<&'a [u8]> {
        let start = self.offset;
        if self.raw.get(self.offset) == Some(&b'-') {
            self.offset += 1;
        }
        match self.raw.get(self.offset)? {
            b'0' => self.offset += 1,
            b'1'..=b'9' => {
                self.offset += 1;
                while self.raw.get(self.offset).is_some_and(u8::is_ascii_digit) {
                    self.offset += 1;
                }
            }
            _ => return None,
        }
        if self.raw.get(self.offset) == Some(&b'.') {
            self.offset += 1;
            let fraction_start = self.offset;
            while self.raw.get(self.offset).is_some_and(u8::is_ascii_digit) {
                self.offset += 1;
            }
            if self.offset == fraction_start {
                return None;
            }
        }
        if matches!(self.raw.get(self.offset), Some(b'e' | b'E')) {
            self.offset += 1;
            if matches!(self.raw.get(self.offset), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            let exponent_start = self.offset;
            while self.raw.get(self.offset).is_some_and(u8::is_ascii_digit) {
                self.offset += 1;
            }
            if self.offset == exponent_start {
                return None;
            }
        }
        self.raw.get(start..self.offset)
    }

    fn consume_literal(&mut self, literal: &[u8]) -> Option<()> {
        let end = self.offset.checked_add(literal.len())?;
        if self.raw.get(self.offset..end)? != literal {
            return None;
        }
        self.offset = end;
        Some(())
    }

    fn consume_byte(&mut self, expected: u8) -> Option<()> {
        if self.raw.get(self.offset) != Some(&expected) {
            return None;
        }
        self.offset += 1;
        Some(())
    }

    fn skip_whitespace(&mut self) {
        while matches!(
            self.raw.get(self.offset),
            Some(b' ' | b'\t' | b'\r' | b'\n')
        ) {
            self.offset += 1;
        }
    }
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let value = map.next_value::<UniqueValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueValue(Value::Object(values)))
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
        let report = validate_session_report_json(VALID).expect("valid report");
        assert_eq!(report.raw_json(), VALID);
        assert_eq!(report.session_id(), "S-test");
        assert!(format!("{report:?}").contains("raw_len"));
        assert!(!format!("{report:?}").contains("S-test"));
        assert!(!format!("{report:?}").contains("observed"));
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
        let mut trailing = VALID.to_vec();
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
    fn rust_matches_the_shared_golden_corpus() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packages/schemas/testdata/session-report");
        let manifest_bytes = fs::read(root.join("manifest.json")).expect("read golden manifest");
        let manifest: Value =
            serde_json::from_slice(&manifest_bytes).expect("parse golden manifest");
        assert_eq!(
            manifest.get("schemaVersion").and_then(Value::as_u64),
            Some(1)
        );
        let cases = manifest
            .get("cases")
            .and_then(Value::as_array)
            .expect("golden cases");
        assert!(!cases.is_empty());
        for case in cases {
            let name = case.get("name").and_then(Value::as_str).expect("case name");
            let expected = case
                .get("valid")
                .and_then(Value::as_bool)
                .expect("case result");
            let file = case.get("file").and_then(Value::as_str).expect("case file");
            let raw = fs::read(root.join(file)).expect("read golden case");
            assert_eq!(
                validate_session_report_json(&raw).is_ok(),
                expected,
                "golden case {name}"
            );
        }
    }
}
