use crate::db::Db;
use rusqlite::params;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

pub struct AppState {
    pub db: Arc<Mutex<Db>>,
    pub master_key: [u8; 32],
    pub data_dir: std::path::PathBuf,
}

pub type SharedState = Arc<AppState>;

pub fn find_dataset(db: &Db, id: &str) -> Option<Value> {
    db.conn
        .query_row(
            "SELECT id,name,source,owner,description,status,row_count,created_at,updated_at FROM datasets WHERE id=?1",
            params![id],
            |r| {
                Ok(json!({
                    "id": r.get::<_,String>(0)?,
                    "name": r.get::<_,String>(1)?,
                    "source": r.get::<_,String>(2)?,
                    "owner": r.get::<_,String>(3)?,
                    "description": r.get::<_,String>(4)?,
                    "status": r.get::<_,String>(5)?,
                    "row_count": r.get::<_,i64>(6)?,
                    "created_at": r.get::<_,String>(7)?,
                    "updated_at": r.get::<_,String>(8)?,
                }))
            },
        )
        .ok()
}

pub fn load_tables(db: &Db, dataset_id: &str) -> Vec<crate::db::TableData> {
    let mut stmt = match db.conn.prepare(
        "SELECT id,file_name,table_name,table_type,headers,rows_json FROM dataset_files WHERE dataset_id=?1 ORDER BY rowid",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let it = stmt
        .query_map(params![dataset_id], |r| {
            let headers: String = r.get(4)?;
            let rows_json: String = r.get(5)?;
            Ok(crate::db::TableData {
                id: r.get(0)?,
                file_name: r.get(1)?,
                table_name: r.get(2)?,
                table_type: r.get(3)?,
                headers: serde_json::from_str(&headers).unwrap_or_default(),
                rows: serde_json::from_str(&rows_json).unwrap_or_default(),
            })
        })
        .ok();
    match it {
        Some(rows) => rows.filter_map(|r| r.ok()).collect(),
        None => vec![],
    }
}

pub fn load_kinds(
    db: &Db,
    dataset_id: &str,
) -> std::collections::HashMap<(String, String), crate::models::ColumnKind> {
    let mut map = std::collections::HashMap::new();
    let Ok(mut stmt) = db.conn.prepare(
        "SELECT file_id,column_name,detected_type FROM field_detections WHERE dataset_id=?1",
    ) else {
        return map;
    };
    let it = stmt.query_map(params![dataset_id], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    });
    if let Ok(rows) = it {
        for (file_id, col, ty) in rows.flatten() {
            if let Ok(kind) = serde_json::from_value::<crate::models::ColumnKind>(Value::String(ty)) {
                map.insert((file_id, col), kind);
            }
        }
    }
    map
}

pub fn load_policy(db: &Db, dataset_id: &str) -> Option<(String, i64, String, crate::models::PolicyConfig)> {
    db.conn
        .query_row(
            "SELECT id,version,name,config_json FROM policies WHERE dataset_id=?1 ORDER BY version DESC LIMIT 1",
            params![dataset_id],
            |r| {
                let raw: String = r.get(3)?;
                let cfg: crate::models::PolicyConfig =
                    serde_json::from_str(&raw).unwrap_or_default();
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, cfg))
            },
        )
        .ok()
}

pub fn load_project(db: &Db, id: &str) -> Option<crate::models::ProjectRow> {
    db.conn
        .query_row(
            "SELECT id,name,group_name,contact,description,created_at FROM projects WHERE id=?1",
            params![id],
            |r| {
                Ok(crate::models::ProjectRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    group_name: r.get(2)?,
                    contact: r.get(3)?,
                    description: r.get(4)?,
                    created_at: r.get(5)?,
                })
            },
        )
        .ok()
}
