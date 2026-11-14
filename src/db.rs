use rusqlite::{params, Connection};
use serde::Serialize;

pub struct Db {
    pub conn: Connection,
}

impl Db {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Db { conn };
        db.migrate()?;
        Ok(db)
    }

    pub fn open_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Db { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS datasets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                source TEXT NOT NULL,
                owner TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'registered',
                row_count INTEGER NOT NULL DEFAULT 0,
                metrics_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS dataset_files (
                id TEXT PRIMARY KEY,
                dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
                file_name TEXT NOT NULL,
                table_name TEXT NOT NULL,
                table_type TEXT NOT NULL DEFAULT 'structured',
                headers TEXT NOT NULL DEFAULT '[]',
                rows_json TEXT NOT NULL DEFAULT '[]',
                row_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS field_detections (
                id TEXT PRIMARY KEY,
                dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
                file_id TEXT NOT NULL,
                table_name TEXT NOT NULL,
                column_name TEXT NOT NULL,
                detected_type TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 0,
                sample TEXT NOT NULL DEFAULT '',
                evidence TEXT NOT NULL DEFAULT '',
                confirmed INTEGER NOT NULL DEFAULT 0,
                strategy TEXT NOT NULL DEFAULT 'auto',
                updated_at TEXT NOT NULL,
                UNIQUE(dataset_id, file_id, column_name)
            );

            CREATE TABLE IF NOT EXISTS link_rules (
                id TEXT PRIMARY KEY,
                dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
                file_id TEXT NOT NULL,
                table_name TEXT NOT NULL,
                column_name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'pid',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY,
                dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                scope TEXT NOT NULL DEFAULT 'dataset',
                config_json TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                group_name TEXT NOT NULL,
                contact TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS releases (
                id TEXT PRIMARY KEY,
                dataset_id TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
                policy_id TEXT NOT NULL,
                policy_version INTEGER NOT NULL,
                policy_snapshot_json TEXT NOT NULL DEFAULT '{}',
                project_id TEXT NOT NULL,
                k INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'draft',
                risk_json TEXT NOT NULL DEFAULT '{}',
                quality_json TEXT NOT NULL DEFAULT '{}',
                findings_json TEXT NOT NULL DEFAULT '[]',
                detection_json TEXT NOT NULL DEFAULT '[]',
                created_by TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                approved_by TEXT NOT NULL DEFAULT '',
                approved_at TEXT,
                rejected_reason TEXT NOT NULL DEFAULT '',
                artifact_dir TEXT NOT NULL DEFAULT '',
                manifest_json TEXT NOT NULL DEFAULT '{}',
                artifact_sha256 TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                dataset_id TEXT NOT NULL DEFAULT '',
                project_id TEXT NOT NULL DEFAULT '',
                release_id TEXT NOT NULL DEFAULT '',
                policy_id TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                hash_prev TEXT NOT NULL DEFAULT '',
                hash_self TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    pub fn audit(
        &self,
        actor: &str,
        action: &str,
        dataset_id: &str,
        project_id: &str,
        release_id: &str,
        policy_id: &str,
        detail: &str,
    ) -> rusqlite::Result<()> {
        let (prev, id): (String, i64) = self
            .conn
            .query_row(
                "SELECT hash_self, id FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap_or((String::new(), 0));
        let seq = id + 1;
        let now = crate::util::now_iso();
        let payload = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            seq, now, actor, action, dataset_id, project_id, release_id, policy_id, detail
        );
        let hash_self = crate::util::sha256_hex(format!("{}|{}", prev, payload).as_bytes());
        self.conn.execute(
            "INSERT INTO audit_log (event_time, actor, action, dataset_id, project_id, release_id, policy_id, detail, hash_prev, hash_self)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![now, actor, action, dataset_id, project_id, release_id, policy_id, detail, prev, hash_self],
        )?;
        Ok(())
    }

    pub fn audit_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))
    }
}

#[derive(Serialize, serde::Deserialize, Clone, Debug)]
pub struct TableData {
    pub id: String,
    pub file_name: String,
    pub table_name: String,
    pub table_type: String,
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}
