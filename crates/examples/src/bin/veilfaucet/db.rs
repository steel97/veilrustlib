//! The faucet queue, stored in `db.sqlite`.
//!
//! Port of `ref/veil-faucet/lib/core/db.dart`. The file name, table name, column
//! names, and query semantics all match, so this binary can take over an
//! existing `db.sqlite` from the Dart bot with no migration.
//!
//! The engine is [`turso`], a pure-Rust SQLite implementation. That keeps the
//! file format identical while avoiding a C compiler in the build, which the
//! Dart `sqlite3` package required through its bundled `libsqlite3`.
//!
//! ## Differences from the Dart original, and why
//!
//! - Values are always bound as parameters. The Dart code interpolated
//!   `payoutsPerCycle` and the row ids straight into SQL strings, which happened
//!   to be safe because both were numeric, but the habit is not.
//! - `used` is set in one statement with an `IN` list rather than a chain of
//!   `OR id = '...'` comparisons, and the ids are bound.
//! - The table is created with `IF NOT EXISTS`. The Dart version checked whether
//!   the file existed *after* opening it, by which point it always did, so the
//!   `CREATE TABLE` never ran and a fresh deployment needed the table made by
//!   hand.

use turso::{Builder, Connection};

use crate::error::FaucetError;

/// Database path, matching `db.dart`'s `dbPath`.
pub const DB_PATH: &str = "./db.sqlite";

/// A queued request that is about to be paid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedRequest {
    /// Row id, used to mark the row paid afterwards.
    pub id: i64,
    /// Destination address, as the user typed it.
    pub address: String,
}

/// The faucet queue.
pub struct Queue {
    connection: Connection,
}

impl Queue {
    /// Open `db.sqlite`, creating the table when it is missing.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be opened, or when it can be read but not
    /// written. The second case is worth failing loudly at startup: a faucet that
    /// cannot record a payout would pay the same user on every cycle.
    pub async fn open(path: &str) -> Result<Self, FaucetError> {
        let database = Builder::new_local(path).build().await?;
        let connection = database.connect()?;

        // Matches the Dart schema byte for byte, including the quoted
        // "timestamp" column, which is a keyword in some dialects.
        connection
            .execute(
                r#"CREATE TABLE IF NOT EXISTS faucet_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT,
                    user_id TEXT,
                    "timestamp" INTEGER,
                    used INTEGER DEFAULT (0)
                )"#,
                (),
            )
            .await
            .map_err(|error| explain_open_failure(path, &error))?;

        Ok(Self { connection })
    }

    /// When this user may next request coins, or `None` if they may request now.
    ///
    /// Returns the absolute unix timestamp the user must wait until, mirroring
    /// `checkTimings`: the most recent request plus the configured limit.
    pub async fn next_allowed_request(
        &self,
        user_id: &str,
        limit_secs: i64,
        now: i64,
    ) -> Result<Option<i64>, FaucetError> {
        let mut rows = self
            .connection
            .query(
                r#"SELECT "timestamp" FROM faucet_queue
                   WHERE user_id = ?1
                   ORDER BY "timestamp" DESC
                   LIMIT 1"#,
                turso::params![user_id],
            )
            .await?;

        let Some(row) = rows.next().await? else {
            return Ok(None);
        };

        // A row written by an older version could hold NULL here, so treat an
        // unreadable timestamp as "no recent request" rather than failing.
        let Some(timestamp) = value_as_i64(&row.get_value(0)?) else {
            return Ok(None);
        };

        let ready_at = timestamp.saturating_add(limit_secs);

        Ok((ready_at > now).then_some(ready_at))
    }

    /// Add a request to the queue.
    pub async fn enqueue(
        &self,
        address: &str,
        user_id: &str,
        now: i64,
    ) -> Result<(), FaucetError> {
        self.connection
            .execute(
                r#"INSERT INTO faucet_queue (address, user_id, "timestamp", used)
                   VALUES (?1, ?2, ?3, 0)"#,
                turso::params![address, user_id, now],
            )
            .await?;

        Ok(())
    }

    /// How many requests are waiting to be paid.
    pub async fn pending_count(&self) -> Result<i64, FaucetError> {
        let mut rows = self
            .connection
            .query("SELECT COUNT(*) FROM faucet_queue WHERE used = 0", ())
            .await?;

        let Some(row) = rows.next().await? else {
            return Ok(0);
        };

        Ok(value_as_i64(&row.get_value(0)?).unwrap_or(0))
    }

    /// Take the oldest `limit` unpaid requests, oldest first.
    ///
    /// The rows are not locked or claimed: a single payout loop owns this table,
    /// which is the same assumption the Dart bot made.
    pub async fn oldest_pending(&self, limit: usize) -> Result<Vec<QueuedRequest>, FaucetError> {
        let limit = i64::try_from(limit)
            .map_err(|_| FaucetError::database(format!("payout batch size {limit} is too large")))?;

        let mut rows = self
            .connection
            .query(
                r#"SELECT id, address FROM faucet_queue
                   WHERE used = 0
                   ORDER BY "timestamp" ASC
                   LIMIT ?1"#,
                turso::params![limit],
            )
            .await?;

        let mut requests = Vec::new();

        while let Some(row) = rows.next().await? {
            let Some(id) = value_as_i64(&row.get_value(0)?) else {
                continue;
            };

            let Some(address) = value_as_text(&row.get_value(1)?) else {
                // A row with no address cannot be paid. Leave it queued rather
                // than silently dropping it, so it stays visible.
                eprintln!("Queue row {id} has no address; skipping it");
                continue;
            };

            requests.push(QueuedRequest { id, address });
        }

        Ok(requests)
    }

    /// Mark rows as paid, so they are never paid twice.
    pub async fn mark_used(&self, ids: &[i64]) -> Result<(), FaucetError> {
        if ids.is_empty() {
            return Ok(());
        }

        // Build one placeholder per id so every value stays bound.
        let placeholders = (1..=ids.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(", ");

        let sql = format!("UPDATE faucet_queue SET used = 1 WHERE id IN ({placeholders})");

        let params = turso::params_from_iter(ids.iter().copied());

        self.connection.execute(&sql, params).await?;

        Ok(())
    }
}

/// Turn an open failure into something the operator can act on.
///
/// The one case worth naming is a read-only open, because the message the engine
/// gives is accurate but says nothing about the cause. `turso` refuses to write a
/// database with `auto_vacuum` enabled, opening it read-only instead
/// (`turso_core-0.7.2/lib.rs:1750`). Stock SQLite defaults to
/// `auto_vacuum=NONE`, so a `db.sqlite` written by the Dart bot is unaffected,
/// but a file someone has since compacted with `PRAGMA auto_vacuum=FULL` would
/// stop the faucet dead with no hint as to why.
fn explain_open_failure(path: &str, error: &turso::Error) -> FaucetError {
    let message = error.to_string();

    if message.to_ascii_lowercase().contains("readonly") {
        return FaucetError::database(format!(
            "{path} opened read-only, so payouts could not be recorded: {message}\n\
             The usual cause is auto_vacuum being enabled on the file, which this \
             SQLite engine will not write to.\n\
             Check it with:   sqlite3 {path} \"PRAGMA auto_vacuum;\"\n\
             If it reports 1 or 2, turn it off and rebuild the file with:\n\
             \x20  sqlite3 {path} \"PRAGMA auto_vacuum=NONE; VACUUM;\"\n\
             Take a backup first."
        ));
    }

    FaucetError::database(format!("could not open {path}: {message}"))
}

/// Read an integer column, tolerating a value stored as text.
fn value_as_i64(value: &turso::Value) -> Option<i64> {
    match value {
        turso::Value::Integer(number) => Some(*number),
        turso::Value::Real(number) => Some(*number as i64),
        turso::Value::Text(text) => text.parse().ok(),
        _ => None,
    }
}

/// Read a text column, rejecting an empty or missing value.
fn value_as_text(value: &turso::Value) -> Option<String> {
    match value {
        turso::Value::Text(text) if !text.trim().is_empty() => Some(text.trim().to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Open a fresh in-memory queue.
    ///
    /// `:memory:` keeps each test isolated without touching the filesystem, and
    /// exercises the same schema and statements the real file does.
    async fn queue() -> Queue {
        Queue::open(":memory:").await.unwrap()
    }

    #[tokio::test]
    async fn a_new_database_starts_empty() {
        let queue = queue().await;

        assert_eq!(queue.pending_count().await.unwrap(), 0);
        assert!(queue.oldest_pending(10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn opening_an_existing_database_preserves_its_rows() {
        // The table must be created only when missing, so restarting the bot
        // never discards the queue.
        let queue = queue().await;
        queue.enqueue("sv1example", "user-1", 1_000).await.unwrap();

        // Re-running the same CREATE TABLE IF NOT EXISTS must be a no-op.
        queue
            .connection
            .execute(
                r#"CREATE TABLE IF NOT EXISTS faucet_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT,
                    user_id TEXT,
                    "timestamp" INTEGER,
                    used INTEGER DEFAULT (0)
                )"#,
                (),
            )
            .await
            .unwrap();

        assert_eq!(queue.pending_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn a_first_time_user_may_request_immediately() {
        let queue = queue().await;

        assert_eq!(
            queue
                .next_allowed_request("user-1", 3_600, 1_000)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn a_recent_request_reports_when_the_user_may_return() {
        let queue = queue().await;
        queue.enqueue("sv1example", "user-1", 1_000).await.unwrap();

        // Requested at 1000 with a 3600s limit, so ready at 4600.
        assert_eq!(
            queue
                .next_allowed_request("user-1", 3_600, 1_500)
                .await
                .unwrap(),
            Some(4_600)
        );

        // Exactly at the boundary the user is allowed through.
        assert_eq!(
            queue
                .next_allowed_request("user-1", 3_600, 4_600)
                .await
                .unwrap(),
            None
        );

        // And well after it.
        assert_eq!(
            queue
                .next_allowed_request("user-1", 3_600, 9_999)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn the_rate_limit_uses_the_most_recent_request() {
        let queue = queue().await;
        queue.enqueue("sv1old", "user-1", 1_000).await.unwrap();
        queue.enqueue("sv1new", "user-1", 5_000).await.unwrap();

        // The newest request governs, so ready at 5000 + 3600.
        assert_eq!(
            queue
                .next_allowed_request("user-1", 3_600, 5_100)
                .await
                .unwrap(),
            Some(8_600)
        );
    }

    #[tokio::test]
    async fn the_rate_limit_is_per_user() {
        let queue = queue().await;
        queue.enqueue("sv1example", "user-1", 1_000).await.unwrap();

        // A different user is unaffected.
        assert_eq!(
            queue
                .next_allowed_request("user-2", 3_600, 1_500)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn pending_requests_come_back_oldest_first_and_respect_the_limit() {
        let queue = queue().await;
        queue.enqueue("sv1third", "user-3", 3_000).await.unwrap();
        queue.enqueue("sv1first", "user-1", 1_000).await.unwrap();
        queue.enqueue("sv1second", "user-2", 2_000).await.unwrap();

        let batch = queue.oldest_pending(2).await.unwrap();

        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].address, "sv1first");
        assert_eq!(batch[1].address, "sv1second");

        // A limit larger than the queue returns everything.
        assert_eq!(queue.oldest_pending(100).await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn marking_rows_used_removes_them_from_the_queue() {
        let queue = queue().await;
        queue.enqueue("sv1first", "user-1", 1_000).await.unwrap();
        queue.enqueue("sv1second", "user-2", 2_000).await.unwrap();
        queue.enqueue("sv1third", "user-3", 3_000).await.unwrap();

        let batch = queue.oldest_pending(2).await.unwrap();
        let ids: Vec<i64> = batch.iter().map(|request| request.id).collect();

        queue.mark_used(&ids).await.unwrap();

        // Only the untouched row remains.
        assert_eq!(queue.pending_count().await.unwrap(), 1);

        let remaining = queue.oldest_pending(10).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].address, "sv1third");

        // A paid user is still rate limited, since the row is retained.
        assert_eq!(
            queue
                .next_allowed_request("user-1", 3_600, 1_500)
                .await
                .unwrap(),
            Some(4_600)
        );
    }

    #[tokio::test]
    async fn marking_no_rows_is_a_no_op() {
        let queue = queue().await;
        queue.enqueue("sv1example", "user-1", 1_000).await.unwrap();

        queue.mark_used(&[]).await.unwrap();

        assert_eq!(queue.pending_count().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn a_row_with_no_address_is_skipped_but_left_in_place() {
        let queue = queue().await;

        queue
            .connection
            .execute(
                r#"INSERT INTO faucet_queue (address, user_id, "timestamp", used)
                   VALUES (NULL, 'user-1', 1000, 0)"#,
                (),
            )
            .await
            .unwrap();
        queue.enqueue("sv1good", "user-2", 2_000).await.unwrap();

        // The unusable row is not returned for payment.
        let batch = queue.oldest_pending(10).await.unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].address, "sv1good");

        // But it is still counted as pending, so it stays visible.
        assert_eq!(queue.pending_count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn an_address_containing_quotes_is_stored_verbatim() {
        // Values are bound, not interpolated, so no input can alter the SQL.
        let queue = queue().await;
        let hostile = "sv1'); DROP TABLE faucet_queue; --";

        queue.enqueue(hostile, "user-1", 1_000).await.unwrap();

        let batch = queue.oldest_pending(10).await.unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].address, hostile);

        // The table survived, which is the point.
        assert_eq!(queue.pending_count().await.unwrap(), 1);
    }

    #[test]
    fn integer_columns_tolerate_a_text_value() {
        // A timestamp written as text by another tool must still be readable.
        assert_eq!(value_as_i64(&turso::Value::Integer(42)), Some(42));
        assert_eq!(value_as_i64(&turso::Value::Text("42".into())), Some(42));
        assert_eq!(value_as_i64(&turso::Value::Real(42.9)), Some(42));
        assert_eq!(value_as_i64(&turso::Value::Null), None);
        assert_eq!(value_as_i64(&turso::Value::Text("abc".into())), None);
    }

    #[test]
    fn text_columns_reject_blank_values() {
        assert_eq!(
            value_as_text(&turso::Value::Text(" sv1abc ".into())),
            Some("sv1abc".to_string())
        );
        assert_eq!(value_as_text(&turso::Value::Text("   ".into())), None);
        assert_eq!(value_as_text(&turso::Value::Null), None);
    }
}
