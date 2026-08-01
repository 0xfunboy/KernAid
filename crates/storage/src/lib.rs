#![forbid(unsafe_code)]
//! Append-only SQLite audit journal. Confidentiality is supplied by the OS
//! keychain in Resident mode or by the LUKS2 vault in Rescue mode.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::path::Path;

const ZERO_HASH: [u8; 32] = [0; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalEntry {
    pub sequence: u64,
    pub event: Vec<u8>,
    pub previous_hash: [u8; 32],
    pub entry_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalError {
    Database(String),
    CorruptChain,
    SequenceOverflow,
}

impl From<rusqlite::Error> for JournalError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error.to_string())
    }
}

pub struct Journal {
    connection: Connection,
}

impl Journal {
    pub fn open(path: &Path) -> Result<Self, JournalError> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS journal_entries (
               sequence INTEGER PRIMARY KEY NOT NULL,
               event BLOB NOT NULL,
               previous_hash BLOB NOT NULL CHECK(length(previous_hash) = 32),
               entry_hash BLOB NOT NULL CHECK(length(entry_hash) = 32)
             );
             CREATE TRIGGER IF NOT EXISTS journal_entries_no_update
               BEFORE UPDATE ON journal_entries BEGIN SELECT RAISE(ABORT, 'append-only journal'); END;
             CREATE TRIGGER IF NOT EXISTS journal_entries_no_delete
               BEFORE DELETE ON journal_entries BEGIN SELECT RAISE(ABORT, 'append-only journal'); END;",
        )?;
        let journal = Self { connection };
        journal.verify()?;
        Ok(journal)
    }

    pub fn append(&mut self, event: &[u8]) -> Result<JournalEntry, JournalError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous = transaction
            .query_row(
                "SELECT sequence, entry_hash FROM journal_entries ORDER BY sequence DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        let (sequence, previous_hash) = match previous {
            Some((last_sequence, hash)) => {
                let sequence = last_sequence
                    .checked_add(1)
                    .ok_or(JournalError::SequenceOverflow)?;
                (
                    sequence,
                    hash.try_into().map_err(|_| JournalError::CorruptChain)?,
                )
            }
            None => (1, ZERO_HASH),
        };
        let entry_hash = hash_entry(sequence, &previous_hash, event);
        transaction.execute(
            "INSERT INTO journal_entries(sequence, event, previous_hash, entry_hash) VALUES (?1, ?2, ?3, ?4)",
            params![sequence, event, previous_hash.as_slice(), entry_hash.as_slice()],
        )?;
        transaction.commit()?;
        Ok(JournalEntry {
            sequence,
            event: event.to_vec(),
            previous_hash,
            entry_hash,
        })
    }

    pub fn entries(&self) -> Result<Vec<JournalEntry>, JournalError> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, event, previous_hash, entry_hash FROM journal_entries ORDER BY sequence",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, u64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let (sequence, event, previous_hash, entry_hash) = row?;
            entries.push(JournalEntry {
                sequence,
                event,
                previous_hash: previous_hash
                    .try_into()
                    .map_err(|_| JournalError::CorruptChain)?,
                entry_hash: entry_hash
                    .try_into()
                    .map_err(|_| JournalError::CorruptChain)?,
            });
        }
        Ok(entries)
    }

    pub fn verify(&self) -> Result<(), JournalError> {
        let mut expected_sequence = 1_u64;
        let mut expected_previous = ZERO_HASH;
        for entry in self.entries()? {
            if entry.sequence != expected_sequence
                || entry.previous_hash != expected_previous
                || entry.entry_hash
                    != hash_entry(entry.sequence, &entry.previous_hash, &entry.event)
            {
                return Err(JournalError::CorruptChain);
            }
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(JournalError::SequenceOverflow)?;
            expected_previous = entry.entry_hash;
        }
        Ok(())
    }
}

fn hash_entry(sequence: u64, previous_hash: &[u8; 32], event: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"KERNAID-JOURNAL-V1\0");
    hasher.update(sequence.to_be_bytes());
    hasher.update(previous_hash);
    hasher.update((event.len() as u64).to_be_bytes());
    hasher.update(event);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env, fs, process,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn database_path(name: &str) -> std::path::PathBuf {
        env::temp_dir().join(format!(
            "kernaid-journal-{name}-{}-{}.sqlite3",
            process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn remove_database(path: &Path) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{}", path.display(), suffix));
        }
    }

    #[test]
    fn journal_survives_reopen_and_verifies_hash_chain() {
        let path = database_path("roundtrip");
        {
            let mut journal = Journal::open(&path).expect("open journal");
            let first = journal
                .append(br#"{"status":"started"}"#)
                .expect("append first event");
            let second = journal
                .append(br#"{"status":"succeeded"}"#)
                .expect("append second event");
            assert_eq!(first.sequence, 1);
            assert_eq!(second.previous_hash, first.entry_hash);
            journal.verify().expect("verify open journal");
        }
        let reopened = Journal::open(&path).expect("reopen journal");
        assert_eq!(reopened.entries().expect("read entries").len(), 2);
        remove_database(&path);
    }

    #[test]
    fn database_triggers_reject_update_and_delete() {
        let path = database_path("immutable");
        let mut journal = Journal::open(&path).expect("open journal");
        journal.append(b"event").expect("append event");
        assert!(
            journal
                .connection
                .execute("UPDATE journal_entries SET event = X'00'", [])
                .is_err()
        );
        assert!(
            journal
                .connection
                .execute("DELETE FROM journal_entries", [])
                .is_err()
        );
        remove_database(&path);
    }
}
