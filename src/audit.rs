use crate::db::Db;
use rusqlite::params;
use serde_json::Value;

pub fn verify(db: &Db) -> rusqlite::Result<(i64, bool, String)> {
    let mut stmt = db.conn.prepare(
        "SELECT id,event_time,actor,action,dataset_id,project_id,release_id,policy_id,detail,hash_prev,hash_self
         FROM audit_log ORDER BY id ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, String>(6)?,
            r.get::<_, String>(7)?,
            r.get::<_, String>(8)?,
            r.get::<_, String>(9)?,
            r.get::<_, String>(10)?,
        ))
    })?;
    let mut prev = String::new();
    let mut ok = true;
    let mut count = 0i64;
    for row in rows {
        let (id, event_time, actor, action, dataset_id, project_id, release_id, policy_id, detail, hash_prev, hash_self) = row?;
        let payload = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            id, event_time, actor, action, dataset_id, project_id, release_id, policy_id, detail
        );
        let expect = crate::util::sha256_hex(format!("{}|{}", prev, payload).as_bytes());
        if hash_prev != prev || hash_self != expect {
            ok = false;
        }
        prev = hash_self;
        count += 1;
    }
    Ok((count, ok, prev))
}

pub fn recent_for_release(db: &Db, release_id: &str) -> rusqlite::Result<Vec<Value>> {
    let mut stmt = db.conn.prepare(
        "SELECT event_time,actor,action,detail FROM audit_log WHERE release_id=?1 ORDER BY id ASC",
    )?;
    let rows = stmt.query_map(params![release_id], |r| {
        Ok(serde_json::json!({
            "event_time": r.get::<_,String>(0)?,
            "actor": r.get::<_,String>(1)?,
            "action": r.get::<_,String>(2)?,
            "detail": r.get::<_,String>(3)?,
        }))
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}
