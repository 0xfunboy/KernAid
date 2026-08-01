#![forbid(unsafe_code)]
//! Append-only journal boundary. Persistence is introduced after encrypted storage is available.
#[derive(Default)]
pub struct MemoryJournal {
    entries: Vec<String>,
}
impl MemoryJournal {
    pub fn append(&mut self, entry: impl Into<String>) {
        self.entries.push(entry.into());
    }
    pub fn entries(&self) -> &[String] {
        &self.entries
    }
}
