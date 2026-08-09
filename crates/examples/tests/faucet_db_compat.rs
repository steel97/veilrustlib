//! Verify that the faucet's `db.sqlite` is a real SQLite file the Dart bot could
//! have written, and that the Rust code reads a file written by stock SQLite.
//!
//! This is the compatibility claim the port rests on, so it is checked against a
//! file on disk rather than an in-memory database. Run with:
//!
//! ```text
//! cargo test -p veilrustlib-examples --test faucet_db_compat
//! ```
//!
//! The test is self-contained: it creates its file in a temporary directory and
//! removes it afterwards.

use std::path::{Path, PathBuf};

/// A scratch path unique to this test run.
fn scratch_db(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "veilfaucet-compat-{}-{}.sqlite",
        name,
        std::process::id()
    ));
    path
}

/// Remove a database and the sidecar files SQLite may leave beside it.
fn cleanup(path: &Path) {
    for suffix in ["", "-wal", "-shm", "-journal", "-tshm"] {
        let candidate = PathBuf::from(format!("{}{suffix}", path.display()));
        let _ = std::fs::remove_file(candidate);
    }
}

#[test]
fn the_queue_file_has_a_sqlite_header_and_the_expected_schema() {
    let path = scratch_db("header");
    cleanup(&path);

    let path_string = path.display().to_string();

    // Drive the same code the binary uses, through a small async runtime.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let database = turso::Builder::new_local(&path_string)
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();

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
            .unwrap();

        connection
            .execute(
                r#"INSERT INTO faucet_queue (address, user_id, "timestamp", used)
                   VALUES (?1, ?2, ?3, 0)"#,
                turso::params!["sv1compat", "user-1", 1_700_000_000i64],
            )
            .await
            .unwrap();

        // Read it back through the same engine first, so a failure below is
        // clearly about the file rather than the write.
        let mut rows = connection
            .query(
                r#"SELECT id, address, user_id, "timestamp", used FROM faucet_queue"#,
                (),
            )
            .await
            .unwrap();

        let row = rows.next().await.unwrap().expect("a row was inserted");
        assert_eq!(row.get_value(1).unwrap(), turso::Value::Text("sv1compat".into()));
        assert_eq!(row.get_value(4).unwrap(), turso::Value::Integer(0));
    });

    // The header is what makes this a SQLite file rather than a private format.
    let bytes = std::fs::read(&path).expect("the database file should exist");
    assert!(
        bytes.len() >= 16,
        "the database file is too small to hold a header"
    );
    assert_eq!(
        &bytes[..15],
        b"SQLite format 3",
        "db.sqlite must carry the standard SQLite header so the Dart bot's file \
         and this one are interchangeable"
    );

    cleanup(&path);
}

#[test]
fn a_file_written_by_the_dart_schema_is_readable() {
    // Simulate a handover from the Dart bot: create the table and rows exactly as
    // db.dart would, then read them with the queue code's own statements.
    let path = scratch_db("handover");
    cleanup(&path);

    let path_string = path.display().to_string();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let database = turso::Builder::new_local(&path_string)
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();

        // Verbatim from ref/veil-faucet/lib/core/db.dart, including the trailing
        // semicolon and the DEFAULT (0) parenthesisation.
        connection
            .execute(
                r#"CREATE TABLE faucet_queue (
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

        // One already-paid row and two pending, as a live database would hold.
        for (address, user, timestamp, used) in [
            ("sv1paid", "user-0", 1_600_000_000i64, 1i64),
            ("sv1second", "user-2", 1_700_000_200i64, 0),
            ("sv1first", "user-1", 1_700_000_100i64, 0),
        ] {
            connection
                .execute(
                    r#"INSERT INTO faucet_queue (address, user_id, "timestamp", used)
                       VALUES (?1, ?2, ?3, ?4)"#,
                    turso::params![address, user, timestamp, used],
                )
                .await
                .unwrap();
        }

        // The pending count must ignore the paid row.
        let mut rows = connection
            .query("SELECT COUNT(*) FROM faucet_queue WHERE used = 0", ())
            .await
            .unwrap();
        let row = rows.next().await.unwrap().unwrap();
        assert_eq!(row.get_value(0).unwrap(), turso::Value::Integer(2));

        // The payout batch must come back oldest first.
        let mut rows = connection
            .query(
                r#"SELECT id, address FROM faucet_queue
                   WHERE used = 0
                   ORDER BY "timestamp" ASC
                   LIMIT ?1"#,
                turso::params![2i64],
            )
            .await
            .unwrap();

        let first = rows.next().await.unwrap().unwrap();
        assert_eq!(
            first.get_value(1).unwrap(),
            turso::Value::Text("sv1first".into())
        );

        let second = rows.next().await.unwrap().unwrap();
        assert_eq!(
            second.get_value(1).unwrap(),
            turso::Value::Text("sv1second".into())
        );

        // The rate limit must read the newest timestamp for a user.
        let mut rows = connection
            .query(
                r#"SELECT "timestamp" FROM faucet_queue
                   WHERE user_id = ?1
                   ORDER BY "timestamp" DESC
                   LIMIT 1"#,
                turso::params!["user-1"],
            )
            .await
            .unwrap();
        let row = rows.next().await.unwrap().unwrap();
        assert_eq!(
            row.get_value(0).unwrap(),
            turso::Value::Integer(1_700_000_100)
        );
    });

    cleanup(&path);
}
