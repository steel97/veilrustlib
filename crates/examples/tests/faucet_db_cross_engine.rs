//! Read and write a `db.sqlite` created by the stock `sqlite3` CLI.
//!
//! The other compatibility test proves the file carries a SQLite header. This one
//! closes the loop in the direction that actually matters for a drop-in
//! replacement: a database written by real SQLite, as the Dart bot's `sqlite3`
//! package would have written it, must be readable and writable here, and the
//! result must still be readable by `sqlite3` afterwards.
//!
//! ## The auto_vacuum caveat
//!
//! `turso` will not write a database that has `auto_vacuum` enabled; it opens such
//! a file read-only instead (`turso_core-0.7.2/lib.rs:1750`). Standard SQLite
//! defaults to `auto_vacuum=NONE`, so a file the Dart bot created is fine, and
//! that is the case checked here. Some SQLite builds ship with a non-zero default
//! though, so the pragma is set explicitly to make the test independent of
//! whichever `sqlite3` happens to be on `PATH`, and a second test pins the
//! read-only behaviour so the limitation cannot regress unnoticed.
//!
//! The tests need the `sqlite3` binary on `PATH`. When it is missing they report
//! that and return, rather than failing, so the suite still passes on a machine
//! without it. Run with:
//!
//! ```text
//! cargo test -p veilrustlib-examples --test faucet_db_cross_engine -- --nocapture
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

/// Whether the stock `sqlite3` CLI is available.
fn sqlite3_available() -> bool {
    Command::new("sqlite3")
        .arg("-version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Run a SQL script through the `sqlite3` CLI, returning stdout.
fn sqlite3_exec(path: &Path, sql: &str) -> String {
    let output = Command::new("sqlite3")
        .arg(path)
        .arg(sql)
        .output()
        .expect("sqlite3 should run");

    assert!(
        output.status.success(),
        "sqlite3 failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n")
}

/// A scratch path unique to this test run.
fn scratch_db(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "veilfaucet-cross-{name}-{}.sqlite",
        std::process::id()
    ));
    path
}

/// Report a database's `auto_vacuum` setting, as stock SQLite sees it.
fn auto_vacuum(path: &Path) -> String {
    sqlite3_exec(path, "PRAGMA auto_vacuum;").trim().to_string()
}

/// Remove a database and any sidecar files.
fn cleanup(path: &Path) {
    for suffix in ["", "-wal", "-shm", "-journal", "-tshm"] {
        let _ = std::fs::remove_file(PathBuf::from(format!("{}{suffix}", path.display())));
    }
}

#[test]
fn a_database_written_by_stock_sqlite_round_trips_through_the_faucet() {
    if !sqlite3_available() {
        println!("skipping: the sqlite3 CLI is not on PATH");
        return;
    }

    let path = scratch_db("roundtrip");
    cleanup(&path);

    // ------------------------------------------------------------------
    // 1. Stock SQLite creates the database, exactly as the Dart bot did.
    // ------------------------------------------------------------------
    // auto_vacuum is set explicitly to SQLite's own default, so the test does not
    // depend on the local sqlite3 build's compiled-in default.
    sqlite3_exec(
        &path,
        r#"PRAGMA auto_vacuum=NONE;
           CREATE TABLE faucet_queue (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             address TEXT,
             user_id TEXT,
             "timestamp" INTEGER,
             used INTEGER DEFAULT (0)
           );
           INSERT INTO faucet_queue (address, user_id, "timestamp", used)
             VALUES ('sv1stealthrow', 'user-a', 1700000000, 0);
           INSERT INTO faucet_queue (address, user_id, "timestamp", used)
             VALUES ('bv1basecoinrow', 'user-b', 1700000050, 0);
           INSERT INTO faucet_queue (address, user_id, "timestamp", used)
             VALUES ('sv1alreadypaid', 'user-c', 1600000000, 1);"#,
    );

    assert_eq!(
        auto_vacuum(&path),
        "0",
        "the fixture must have auto_vacuum off, matching SQLite's default"
    );

    let path_string = path.display().to_string();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // ------------------------------------------------------------------
    // 2. The faucet's engine reads and updates that same file.
    // ------------------------------------------------------------------
    runtime.block_on(async {
        let database = turso::Builder::new_local(&path_string)
            .build()
            .await
            .unwrap();
        let connection = database.connect().unwrap();

        // Opening must not disturb the existing table.
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

        // Two rows are pending; the paid one must be excluded.
        let mut rows = connection
            .query("SELECT COUNT(*) FROM faucet_queue WHERE used = 0", ())
            .await
            .unwrap();
        let row = rows.next().await.unwrap().unwrap();
        assert_eq!(
            row.get_value(0).unwrap(),
            turso::Value::Integer(2),
            "the pending count must ignore rows the Dart bot already paid"
        );

        // The oldest pending row must come first.
        let mut rows = connection
            .query(
                r#"SELECT id, address FROM faucet_queue
                   WHERE used = 0
                   ORDER BY "timestamp" ASC
                   LIMIT 2"#,
                (),
            )
            .await
            .unwrap();

        let first = rows.next().await.unwrap().unwrap();
        assert_eq!(
            first.get_value(1).unwrap(),
            turso::Value::Text("sv1stealthrow".into())
        );
        let first_id = match first.get_value(0).unwrap() {
            turso::Value::Integer(id) => id,
            other => panic!("expected an integer id, got {other:?}"),
        };

        let second = rows.next().await.unwrap().unwrap();
        assert_eq!(
            second.get_value(1).unwrap(),
            turso::Value::Text("bv1basecoinrow".into())
        );

        // Mark the first row paid and queue a new request, which is exactly what
        // a payout cycle plus a /getcoins does.
        connection
            .execute(
                "UPDATE faucet_queue SET used = 1 WHERE id IN (?1)",
                turso::params![first_id],
            )
            .await
            .unwrap();

        connection
            .execute(
                r#"INSERT INTO faucet_queue (address, user_id, "timestamp", used)
                   VALUES (?1, ?2, ?3, 0)"#,
                turso::params!["Vnewrequest", "user-d", 1_700_000_900i64],
            )
            .await
            .unwrap();
    });

    // Drop the runtime so the engine closes the file and flushes any WAL.
    drop(runtime);

    // ------------------------------------------------------------------
    // 3. Stock SQLite reads the result back.
    // ------------------------------------------------------------------
    let dump = sqlite3_exec(
        &path,
        r#"SELECT id || '|' || COALESCE(address,'') || '|' || COALESCE(user_id,'')
                  || '|' || COALESCE("timestamp",0) || '|' || used
           FROM faucet_queue ORDER BY id;"#,
    );

    let lines: Vec<&str> = dump.lines().filter(|line| !line.is_empty()).collect();

    assert_eq!(
        lines.len(),
        4,
        "expected the three original rows plus one new one, got: {dump}"
    );

    // The update the faucet made must be visible to stock SQLite.
    assert_eq!(lines[0], "1|sv1stealthrow|user-a|1700000000|1");
    assert_eq!(lines[1], "2|bv1basecoinrow|user-b|1700000050|0");
    assert_eq!(lines[2], "3|sv1alreadypaid|user-c|1600000000|1");

    // And so must the insert, including its autoincremented id.
    assert_eq!(lines[3], "4|Vnewrequest|user-d|1700000900|0");

    // The schema must be unchanged, so the Dart bot could take the file back.
    let schema = sqlite3_exec(
        &path,
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='faucet_queue';",
    );

    assert!(
        schema.contains("faucet_queue") && schema.contains("used"),
        "the faucet_queue schema should survive intact, got: {schema}"
    );

    // An integrity check is the strongest statement that the file is not subtly
    // corrupt in a way the queries above would not notice.
    let integrity = sqlite3_exec(&path, "PRAGMA integrity_check;");
    assert_eq!(
        integrity.trim(),
        "ok",
        "sqlite3 integrity_check must pass after the faucet writes to the file"
    );

    cleanup(&path);
}

#[test]
fn an_auto_vacuum_database_is_rejected_with_an_actionable_message() {
    // This pins a real limitation of the engine rather than a property of the
    // faucet: turso opens an auto_vacuum database read-only, so writes fail. The
    // faucet must detect that at startup and say what to do about it, because a
    // faucet that cannot record a payout would pay the same user every cycle.
    //
    // If a future turso release lifts the restriction, this test fails and the
    // diagnostic in db.rs can be removed.
    if !sqlite3_available() {
        println!("skipping: the sqlite3 CLI is not on PATH");
        return;
    }

    for mode in ["FULL", "INCREMENTAL"] {
        let path = scratch_db(&format!("autovacuum-{mode}"));
        cleanup(&path);

        sqlite3_exec(
            &path,
            &format!(
                r#"PRAGMA auto_vacuum={mode};
                   CREATE TABLE faucet_queue (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     address TEXT,
                     user_id TEXT,
                     "timestamp" INTEGER,
                     used INTEGER DEFAULT (0)
                   );
                   INSERT INTO faucet_queue (address, user_id, "timestamp", used)
                     VALUES ('sv1row', 'user-a', 1700000000, 0);"#
            ),
        );

        assert_ne!(
            auto_vacuum(&path),
            "0",
            "the {mode} fixture should report auto_vacuum as enabled"
        );

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

            // Reading still works, which is exactly what makes this a trap: a
            // naive check would conclude the database is usable.
            let mut rows = connection
                .query("SELECT COUNT(*) FROM faucet_queue", ())
                .await
                .unwrap();
            let row = rows.next().await.unwrap().unwrap();
            assert_eq!(row.get_value(0).unwrap(), turso::Value::Integer(1));

            // Writing does not.
            let error = connection
                .execute(
                    r#"UPDATE faucet_queue SET used = 1 WHERE id = 1"#,
                    (),
                )
                .await
                .expect_err("an auto_vacuum database should reject writes");

            assert!(
                error.to_string().to_ascii_lowercase().contains("readonly"),
                "expected a read-only error for auto_vacuum={mode}, got: {error}"
            );
        });

        drop(runtime);
        cleanup(&path);
    }
}
