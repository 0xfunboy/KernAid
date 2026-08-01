#![forbid(unsafe_code)]
pub fn redact(input:&str)->String { input.split_whitespace().map(|word| if word.starts_with("sk-") || word.starts_with("Bearer") { "[REDACTED]" } else { word }).collect::<Vec<_>>().join(" ") }
#[cfg(test)] mod tests { use super::*; #[test] fn removes_seeded_secret(){ assert!(!redact("token sk-test-secret").contains("sk-test-secret")); } }
