use crate::db::{Db, TableData};
use crate::models::*;
use crate::state::*;
use axum::{
    body::Body,
    extract::{Multipart, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

type ApiResult = Result<Json<Value>, ApiError>;

pub struct ApiError(pub StatusCode, pub String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}

impl From<String> for ApiError {
    fn from(e: String) -> Self {
        ApiError(StatusCode::BAD_REQUEST, e)
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}
fn notfound(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::NOT_FOUND, msg.into())
}
fn conflict(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::CONFLICT, msg.into())
}

fn actor(headers: &HeaderMap) -> String {
    headers
        .get("x-actor")
        .and_then(|v| v.to_str().ok())
        .map(|s| percent_decode(s))
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "科研处管理员".into())
}

/// Minimal %XX decoder for the UTF-8 actor name sent from the browser.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/stats", get(overview))
        .route("/api/datasets", get(list_datasets).post(create_dataset))
        .route("/api/datasets/{id}", get(get_dataset).delete(delete_dataset))
        .route("/api/datasets/{id}/files", get(list_files))
        .route("/api/datasets/{id}/upload", post(upload_files))
        .route("/api/datasets/{id}/preview", get(preview_table))
        .route("/api/datasets/{id}/detect", post(run_detection))
        .route("/api/datasets/{id}/detections", get(list_detections))
        .route("/api/datasets/{id}/detections/{did}", put(update_detection))
        .route("/api/datasets/{id}/detection-eval", get(detection_eval))
        .route("/api/datasets/{id}/entities", get(entity_summary))
        .route("/api/datasets/{id}/linkage", get(linkage_summary))
        .route("/api/datasets/{id}/policy", get(get_policy).put(save_policy))
        .route("/api/datasets/{id}/policy/history", get(policy_history))
        .route("/api/datasets/{id}/transform-preview", get(transform_preview))
        .route("/api/projects", get(list_projects).post(create_project))
        .route("/api/releases", get(list_releases).post(create_release))
        .route("/api/releases/{id}", get(get_release).delete(delete_release))
        .route("/api/releases/{id}/approve", post(approve_release))
        .route("/api/releases/{id}/reject", post(reject_release))
        .route("/api/releases/{id}/export", get(export_release))
        .route("/api/releases/{id}/files/{name}", get(download_artifact))
        .route("/api/releases/{id}/manifest", get(release_manifest))
        .route("/api/audit", get(list_audit))
        .route("/api/audit/verify", get(verify_audit))
        .route("/api/synthetic/generate", post(generate_synthetic))
        .fallback(static_handler)
        .with_state(state)
}

// ---------- health / overview ----------

async fn health() -> Json<Value> {
    Json(json!({"ok": true, "service": "medmask", "version": env!("CARGO_PKG_VERSION")}))
}

async fn overview(State(st): State<SharedState>) -> ApiResult {
    let db = st.db.lock().unwrap();
    let count = |sql: &str| -> i64 { db.conn.query_row(sql, [], |r| r.get(0)).unwrap_or(0) };
    let datasets = count("SELECT COUNT(*) FROM datasets");
    let releases = count("SELECT COUNT(*) FROM releases");
    let approved = count("SELECT COUNT(*) FROM releases WHERE status='approved'");
    let pending = count("SELECT COUNT(*) FROM releases WHERE status IN ('evaluated','pending')");
    let blocked = count("SELECT COUNT(*) FROM releases WHERE status='blocked'");
    let audits = count("SELECT COUNT(*) FROM audit_log");
    let rows = count("SELECT COALESCE(SUM(row_count),0) FROM datasets");
    Ok(Json(json!({
        "datasets": datasets,
        "releases": releases,
        "approved": approved,
        "pending": pending,
        "blocked": blocked,
        "audit_events": audits,
        "total_rows": rows,
    })))
}

// ---------- datasets ----------

#[derive(Deserialize)]
struct CreateDataset {
    name: String,
    source: String,
    owner: Option<String>,
    description: Option<String>,
}

async fn list_datasets(State(st): State<SharedState>) -> ApiResult {
    let db = st.db.lock().unwrap();
    let mut stmt = db.conn.prepare(
        "SELECT d.id,d.name,d.source,d.owner,d.description,d.status,d.row_count,d.created_at,d.updated_at,
                (SELECT COUNT(*) FROM dataset_files f WHERE f.dataset_id=d.id),
                (SELECT COUNT(*) FROM field_detections x WHERE x.dataset_id=d.id)
         FROM datasets d ORDER BY d.created_at DESC",
    )?;
    let rows = stmt
        .query_map([], |r| {
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
                "file_count": r.get::<_,i64>(9)?,
                "field_count": r.get::<_,i64>(10)?,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    Ok(Json(json!({"datasets": rows})))
}

async fn create_dataset(
    State(st): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CreateDataset>,
) -> ApiResult {
    let name = body.name.trim();
    if name.is_empty() {
        return Err(bad("数据集名称不能为空"));
    }
    let id = crate::util::new_id("ds");
    let now = crate::util::now_iso();
    let db = st.db.lock().unwrap();
    db.conn.execute(
        "INSERT INTO datasets (id,name,source,owner,description,status,row_count,created_at,updated_at)
         VALUES (?1,?2,?3,?4,?5,'registered',0,?6,?6)",
        params![
            id,
            name,
            body.source.trim(),
            body.owner.unwrap_or_default(),
            body.description.unwrap_or_default(),
            now
        ],
    )?;
    db.audit(&actor(&headers), "dataset.register", &id, "", "", "", &format!("登记数据集「{}」", name))?;
    Ok(Json(json!({"id": id})))
}

async fn get_dataset(State(st): State<SharedState>, Path(id): Path<String>) -> ApiResult {
    let db = st.db.lock().unwrap();
    let ds = find_dataset(&db, &id).ok_or_else(|| notfound("数据集不存在"))?;
    let files = list_files_json(&db, &id);
    let detection_count: i64 = db
        .conn
        .query_row(
            "SELECT COUNT(*) FROM field_detections WHERE dataset_id=?1",
            params![id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let policy = load_policy(&db, &id).map(|(pid, v, name, _)| json!({"id": pid, "version": v, "name": name}));
    Ok(Json(json!({"dataset": ds, "files": files, "detection_count": detection_count, "policy": policy})))
}

async fn delete_dataset(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult {
    let db = st.db.lock().unwrap();
    let ds = find_dataset(&db, &id).ok_or_else(|| notfound("数据集不存在"))?;
    let n = db.conn.execute("DELETE FROM datasets WHERE id=?1", params![id])?;
    if n == 0 {
        return Err(notfound("数据集不存在"));
    }
    db.audit(&actor(&headers), "dataset.delete", &id, "", "", "", &format!("删除数据集「{}」", ds["name"].as_str().unwrap_or("")))?;
    Ok(Json(json!({"deleted": true})))
}

fn list_files_json(db: &Db, id: &str) -> Vec<Value> {
    let Ok(mut stmt) = db.conn.prepare(
        "SELECT id,file_name,table_name,table_type,headers,row_count FROM dataset_files WHERE dataset_id=?1 ORDER BY rowid",
    ) else {
        return vec![];
    };
    let it = stmt.query_map(params![id], |r| {
        let headers: String = r.get(4)?;
        Ok(json!({
            "id": r.get::<_,String>(0)?,
            "file_name": r.get::<_,String>(1)?,
            "table_name": r.get::<_,String>(2)?,
            "table_type": r.get::<_,String>(3)?,
            "headers": serde_json::from_str::<Vec<String>>(&headers).unwrap_or_default(),
            "row_count": r.get::<_,i64>(5)?,
        }))
    });
    it.map(|rows| rows.filter_map(|r| r.ok()).collect()).unwrap_or_default()
}

async fn list_files(State(st): State<SharedState>, Path(id): Path<String>) -> ApiResult {
    let db = st.db.lock().unwrap();
    if find_dataset(&db, &id).is_none() {
        return Err(notfound("数据集不存在"));
    }
    Ok(Json(json!({"files": list_files_json(&db, &id)})))
}

async fn upload_files(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> ApiResult {
    {
        let db = st.db.lock().unwrap();
        if find_dataset(&db, &id).is_none() {
            return Err(notfound("数据集不存在"));
        }
    }
    let mut tables: Vec<TableData> = Vec::new();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| bad(format!("上传解析失败: {e}")))?
    {
        let fname = field.file_name().unwrap_or("upload.csv").to_string();
        let bytes = field
            .bytes()
            .await
            .map_err(|e| bad(format!("读取文件失败: {e}")))?;
        let parsed = crate::csvio::read_upload(&fname, &bytes)?;
        tables.extend(parsed);
    }
    if tables.is_empty() {
        return Err(bad("未收到文件"));
    }
    let now = crate::util::now_iso();
    let total: i64 = tables.iter().map(|t| t.rows.len() as i64).sum();
    let db = st.db.lock().unwrap();
    for t in &tables {
        let file_id = crate::util::new_id("f");
        db.conn.execute(
            "INSERT INTO dataset_files (id,dataset_id,file_name,table_name,table_type,headers,rows_json,row_count,created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                file_id,
                id,
                t.file_name,
                t.table_name,
                t.table_type,
                serde_json::to_string(&t.headers).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&t.rows).unwrap_or_else(|_| "[]".into()),
                t.rows.len() as i64,
                now
            ],
        )?;
    }
    let existing: i64 = db
        .conn
        .query_row("SELECT row_count FROM datasets WHERE id=?1", params![id], |r| r.get(0))
        .unwrap_or(0);
    db.conn.execute(
        "UPDATE datasets SET row_count=?1,status='loaded',updated_at=?2 WHERE id=?3",
        params![existing + total, now, id],
    )?;
    db.audit(
        &actor(&headers),
        "dataset.upload",
        &id,
        "",
        "",
        "",
        &format!("上传 {} 个文件，共 {} 行", tables.len(), total),
    )?;
    Ok(Json(json!({"files": tables.len(), "rows": total})))
}

// ---------- preview ----------

#[derive(Deserialize)]
struct PreviewQuery {
    file: String,
    limit: Option<usize>,
    offset: Option<usize>,
    scan: Option<String>,
}

async fn preview_table(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    Query(q): Query<PreviewQuery>,
) -> ApiResult {
    let db = st.db.lock().unwrap();
    let mut stmt = db.conn.prepare(
        "SELECT id,file_name,table_name,table_type,headers,rows_json FROM dataset_files WHERE dataset_id=?1 AND id=?2",
    )?;
    let table = stmt
        .query_row(params![id, q.file], |r| {
            let headers: String = r.get(4)?;
            let rows_json: String = r.get(5)?;
            Ok(TableData {
                id: r.get(0)?,
                file_name: r.get(1)?,
                table_name: r.get(2)?,
                table_type: r.get(3)?,
                headers: serde_json::from_str(&headers).unwrap_or_default(),
                rows: serde_json::from_str(&rows_json).unwrap_or_default(),
            })
        })
        .optional()?
        .ok_or_else(|| notfound("文件不存在"))?;
    let limit = q.limit.unwrap_or(20).min(200);
    let offset = q.offset.unwrap_or(0);
    let scan = q.scan.as_deref().unwrap_or("");
    let rows: Vec<Vec<String>> = table
        .rows
        .iter()
        .skip(offset)
        .filter(|r| {
            if scan.is_empty() {
                true
            } else {
                r.iter().any(|c| c.contains(scan))
            }
        })
        .take(limit)
        .cloned()
        .collect();
    Ok(Json(json!({
        "file": {
            "id": table.id,
            "file_name": table.file_name,
            "table_name": table.table_name,
            "table_type": table.table_type,
            "headers": table.headers,
            "row_count": table.rows.len(),
        },
        "rows": rows,
        "offset": offset,
        "limit": limit,
    })))
}

// ---------- detection ----------

async fn run_detection(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult {
    let db = st.db.lock().unwrap();
    if find_dataset(&db, &id).is_none() {
        return Err(notfound("数据集不存在"));
    }
    let tables = load_tables(&db, &id);
    if tables.is_empty() {
        return Err(bad("请先上传数据文件"));
    }
    let now = crate::util::now_iso();
    let mut count = 0;
    let mut direct = 0;
    let mut free_text = 0;

    // free-text headers per table
    let free_text_cols: Vec<String> = crate::csvio::FREE_TEXT_HEADERS
        .iter()
        .map(|s| s.to_string())
        .collect();

    db.conn.execute("DELETE FROM field_detections WHERE dataset_id=?1", params![id])?;
    for t in &tables {
        for (ci, header) in t.headers.iter().enumerate() {
            let values: Vec<String> = t
                .rows
                .iter()
                .filter_map(|r| r.get(ci).cloned())
                .collect();
            let det = crate::detect::detect_column(
                header,
                &values,
                if crate::csvio::is_free_text_header(header) {
                    &free_text_cols
                } else {
                    &[]
                },
            );
            let did = crate::util::new_id("fd");
            let is_direct = det.kind.is_direct_identifier();
            let ft = det.kind == ColumnKind::FreeText;
            if is_direct {
                direct += 1;
            }
            if ft {
                free_text += 1;
            }
            count += 1;
            db.conn.execute(
                "INSERT INTO field_detections
                 (id,dataset_id,file_id,table_name,column_name,detected_type,confidence,sample,evidence,confirmed,strategy,updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'auto',?11)",
                params![
                    did,
                    id,
                    t.id,
                    t.table_name,
                    header,
                    serde_json::to_value(&det.kind).unwrap().as_str().unwrap_or("unknown"),
                    det.confidence,
                    det.sample,
                    det.evidence,
                    if is_direct || ft { 1 } else { 0 },
                    now
                ],
            )?;
        }
    }
    db.conn
        .execute("UPDATE datasets SET status='detected',updated_at=?1 WHERE id=?2", params![now, id])?;
    db.audit(
        &actor(&headers),
        "field.detect",
        &id,
        "",
        "",
        "",
        &format!("字段识别：{} 个字段，直接标识 {} 个，自由文本 {} 个", count, direct, free_text),
    )?;
    Ok(Json(json!({"fields": count, "direct": direct, "free_text": free_text})))
}

async fn list_detections(State(st): State<SharedState>, Path(id): Path<String>) -> ApiResult {
    let db = st.db.lock().unwrap();
    if find_dataset(&db, &id).is_none() {
        return Err(notfound("数据集不存在"));
    }
    let mut stmt = db.conn.prepare(
        "SELECT id,file_id,table_name,column_name,detected_type,confidence,sample,evidence,confirmed,strategy,updated_at
         FROM field_detections WHERE dataset_id=?1 ORDER BY table_name,column_name",
    )?;
    let rows: Vec<Value> = stmt
        .query_map(params![id], |r| {
            let ty: String = r.get(4)?;
            let label = serde_json::from_value::<ColumnKind>(Value::String(ty.clone()))
                .map(|k| k.label().to_string())
                .unwrap_or_else(|_| ty.clone());
            Ok(json!({
                "id": r.get::<_,String>(0)?,
                "file_id": r.get::<_,String>(1)?,
                "table_name": r.get::<_,String>(2)?,
                "column_name": r.get::<_,String>(3)?,
                "detected_type": ty,
                "type_label": label,
                "confidence": r.get::<_,f64>(5)?,
                "sample": r.get::<_,String>(6)?,
                "evidence": r.get::<_,String>(7)?,
                "confirmed": r.get::<_,i64>(8)? != 0,
                "strategy": r.get::<_,String>(9)?,
                "updated_at": r.get::<_,String>(10)?,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();
    // summary by type
    let mut by_type: HashMap<String, usize> = HashMap::new();
    for r in &rows {
        *by_type
            .entry(r["type_label"].as_str().unwrap_or("").to_string())
            .or_insert(0) += 1;
    }
    Ok(Json(json!({"detections": rows, "by_type": by_type})))
}

#[derive(Deserialize)]
struct UpdateDetection {
    detected_type: String,
    confirmed: Option<bool>,
}

async fn update_detection(
    State(st): State<SharedState>,
    Path((id, did)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<UpdateDetection>,
) -> ApiResult {
    let kind: ColumnKind = serde_json::from_value(Value::String(body.detected_type.clone()))
        .map_err(|_| bad("未知字段类型"))?;
    let db = st.db.lock().unwrap();
    let now = crate::util::now_iso();
    let n = db.conn.execute(
        "UPDATE field_detections SET detected_type=?1,confirmed=?2,strategy='manual',updated_at=?3
         WHERE id=?4 AND dataset_id=?5",
        params![
            body.detected_type,
            if body.confirmed.unwrap_or(true) { 1 } else { 0 },
            now,
            did,
            id
        ],
    )?;
    if n == 0 {
        return Err(notfound("字段不存在"));
    }
    db.audit(
        &actor(&headers),
        "field.override",
        &id,
        "",
        "",
        "",
        &format!("人工调整字段 {} 类型为 {}", did, kind.label()),
    )?;
    Ok(Json(json!({"updated": true, "label": kind.label()})))
}

async fn detection_eval(State(st): State<SharedState>, Path(id): Path<String>) -> ApiResult {
    let db = st.db.lock().unwrap();
    if find_dataset(&db, &id).is_none() {
        return Err(notfound("数据集不存在"));
    }
    let raw: String = db
        .conn
        .query_row(
            "SELECT metrics_json FROM datasets WHERE id=?1",
            params![id],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| "{}".into());
    let v: Value = serde_json::from_str(&raw).unwrap_or(json!({}));
    Ok(Json(json!({
        "detection_eval": v.get("detection_eval").cloned().unwrap_or(Value::Null),
        "column_eval": v.get("column_eval").cloned().unwrap_or(Value::Null),
    })))
}

async fn entity_summary(State(st): State<SharedState>, Path(id): Path<String>) -> ApiResult {
    let db = st.db.lock().unwrap();
    if find_dataset(&db, &id).is_none() {
        return Err(notfound("数据集不存在"));
    }
    let tables = load_tables(&db, &id);
    let kinds = load_kinds(&db, &id);
    let entities = crate::engine::entity_summary(&tables, &kinds);
    Ok(Json(entities))
}

async fn linkage_summary(State(st): State<SharedState>, Path(id): Path<String>) -> ApiResult {
    let db = st.db.lock().unwrap();
    if find_dataset(&db, &id).is_none() {
        return Err(notfound("数据集不存在"));
    }
    let tables = load_tables(&db, &id);
    let kinds = load_kinds(&db, &id);
    let linkages = crate::engine::linkage_summary(&tables, &kinds);
    Ok(Json(linkages))
}

// ---------- policy ----------

async fn get_policy(State(st): State<SharedState>, Path(id): Path<String>) -> ApiResult {
    let db = st.db.lock().unwrap();
    if find_dataset(&db, &id).is_none() {
        return Err(notfound("数据集不存在"));
    }
    match load_policy(&db, &id) {
        Some((pid, version, name, cfg)) => Ok(Json(json!({
            "policy": {"id": pid, "version": version, "name": name, "config": cfg}
        }))),
        None => Ok(Json(json!({
            "policy": {"id": Value::Null, "version": 0, "name": "默认策略", "config": PolicyConfig::default()}
        }))),
    }
}

#[derive(Deserialize)]
struct SavePolicy {
    name: Option<String>,
    config: PolicyConfig,
}

async fn save_policy(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SavePolicy>,
) -> ApiResult {
    let db = st.db.lock().unwrap();
    if find_dataset(&db, &id).is_none() {
        return Err(notfound("数据集不存在"));
    }
    let now = crate::util::now_iso();
    let current = load_policy(&db, &id);
    let (pid, version) = match &current {
        Some((pid, v, _, _)) => (pid.clone(), v + 1),
        None => (crate::util::new_id("pol"), 1),
    };
    let mut cfg = body.config;
    cfg.version = version as u32;
    let name = body
        .name
        .unwrap_or_else(|| format!("科研脱敏策略 v{}", version));
    if current.is_some() {
        db.conn.execute("DELETE FROM policies WHERE dataset_id=?1", params![id])?;
    }
    db.conn.execute(
        "INSERT INTO policies (id,dataset_id,name,scope,config_json,version,created_at,updated_at)
         VALUES (?1,?2,?3,'dataset',?4,?5,?6,?6)",
        params![
            pid,
            id,
            name,
            serde_json::to_string(&cfg).unwrap_or_default(),
            version,
            now
        ],
    )?;
    db.conn.execute(
        "UPDATE datasets SET status='configured',updated_at=?1 WHERE id=?2",
        params![now, id],
    )?;
    db.audit(
        &actor(&headers),
        "policy.save",
        &id,
        "",
        "",
        &pid,
        &format!("保存策略「{}」v{}：k={}，日期{}天~{}天", name, version, cfg.k_anonymity.k, cfg.dates.min_days, cfg.dates.max_days),
    )?;
    Ok(Json(json!({"id": pid, "version": version, "name": name})))
}

async fn policy_history(State(st): State<SharedState>, Path(id): Path<String>) -> ApiResult {
    let db = st.db.lock().unwrap();
    let mut stmt = db.conn.prepare(
        "SELECT id,version,name,created_at,config_json FROM policies WHERE dataset_id=?1 ORDER BY version DESC",
    )?;
    let rows: Vec<Value> = stmt
        .query_map(params![id], |r| {
            Ok(json!({
                "id": r.get::<_,String>(0)?,
                "version": r.get::<_,i64>(1)?,
                "name": r.get::<_,String>(2)?,
                "created_at": r.get::<_,String>(3)?,
                "config": serde_json::from_str::<Value>(&r.get::<_,String>(4)?).unwrap_or(json!({})),
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(Json(json!({"history": rows})))
}

#[derive(Deserialize)]
struct TransformQuery {
    project: Option<String>,
    k: Option<usize>,
    limit: Option<usize>,
}

async fn transform_preview(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    Query(q): Query<TransformQuery>,
) -> ApiResult {
    let db = st.db.lock().unwrap();
    if find_dataset(&db, &id).is_none() {
        return Err(notfound("数据集不存在"));
    }
    let tables = load_tables(&db, &id);
    if tables.is_empty() {
        return Err(bad("请先上传数据文件"));
    }
    let kinds = load_kinds(&db, &id);
    if kinds.is_empty() {
        return Err(bad("请先执行字段识别"));
    }
    let (policy_id, version, _, mut cfg) = load_policy(&db, &id).unwrap_or_else(|| {
        (
            "default".into(),
            0,
            "默认策略".into(),
            PolicyConfig::default(),
        )
    });
    let project_id = q.project.unwrap_or_else(|| "preview".into());
    if let Some(k) = q.k {
        cfg.k_anonymity.k = k;
    }
    let k_value = cfg.k_anonymity.k;
    let limit = q.limit.unwrap_or(20);
    let trimmed: Vec<TableData> = tables
        .into_iter()
        .map(|t| TableData {
            rows: t.rows.into_iter().take(800).collect(),
            ..t
        })
        .collect();
    let output = crate::engine::run(crate::engine::EngineInput {
        dataset_id: &id,
        project_id: &project_id,
        tables: trimmed,
        kinds,
        policy: cfg,
        master_key: st.master_key,
        k: k_value,
    });
    let mut samples = Vec::new();
    for t in &output.tables {
        samples.push(json!({
            "table": t.table_name,
            "headers": t.headers,
            "rows": t.rows.iter().take(limit).collect::<Vec<_>>(),
        }));
    }
    Ok(Json(json!({
        "policy_id": policy_id,
        "policy_version": version,
        "samples": samples,
        "quality": output.quality,
        "risk": output.risk,
        "decisions": output.decisions,
        "preview": true,
    })))
}

// ---------- projects ----------

#[derive(Deserialize)]
struct CreateProject {
    name: String,
    group_name: String,
    contact: Option<String>,
    description: Option<String>,
}

async fn list_projects(State(st): State<SharedState>) -> ApiResult {
    let db = st.db.lock().unwrap();
    let mut stmt = db.conn.prepare(
        "SELECT p.id,p.name,p.group_name,p.contact,p.description,p.created_at,
                (SELECT COUNT(*) FROM releases r WHERE r.project_id=p.id)
         FROM projects p ORDER BY p.created_at DESC",
    )?;
    let rows: Vec<Value> = stmt
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_,String>(0)?,
                "name": r.get::<_,String>(1)?,
                "group_name": r.get::<_,String>(2)?,
                "contact": r.get::<_,String>(3)?,
                "description": r.get::<_,String>(4)?,
                "created_at": r.get::<_,String>(5)?,
                "release_count": r.get::<_,i64>(6)?,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(Json(json!({"projects": rows})))
}

async fn create_project(
    State(st): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CreateProject>,
) -> ApiResult {
    if body.name.trim().is_empty() || body.group_name.trim().is_empty() {
        return Err(bad("课题名称与课题组不能为空"));
    }
    let id = crate::util::new_id("prj");
    let now = crate::util::now_iso();
    let db = st.db.lock().unwrap();
    db.conn.execute(
        "INSERT INTO projects (id,name,group_name,contact,description,created_at)
         VALUES (?1,?2,?3,?4,?5,?6)",
        params![
            id,
            body.name.trim(),
            body.group_name.trim(),
            body.contact.unwrap_or_default(),
            body.description.unwrap_or_default(),
            now
        ],
    )?;
    db.audit(
        &actor(&headers),
        "project.create",
        "",
        &id,
        "",
        "",
        &format!("新建课题组「{}」", body.group_name),
    )?;
    Ok(Json(json!({"id": id})))
}

// ---------- releases ----------

#[derive(Deserialize)]
struct CreateRelease {
    dataset_id: String,
    project_id: String,
    policy_id: Option<String>,
    k: Option<usize>,
    created_by: Option<String>,
    actor: Option<String>,
}

fn evaluate_and_store(
    st: &AppState,
    dataset_id: &str,
    project_id: &str,
    policy_id: Option<&str>,
    k_override: Option<usize>,
    created_by: &str,
    release_id: &str,
) -> Result<(Value, PolicyConfig, i64, String), ApiError> {
    let db = st.db.lock().unwrap();
    find_dataset(&db, dataset_id).ok_or_else(|| notfound("数据集不存在"))?;
    let tables = load_tables(&db, dataset_id);
    if tables.is_empty() {
        return Err(bad("数据集没有数据文件"));
    }
    let kinds = load_kinds(&db, dataset_id);
    if kinds.is_empty() {
        return Err(bad("请先执行字段识别"));
    }
    let project = load_project(&db, project_id).ok_or_else(|| notfound("课题组不存在"))?;
    let (pid, version, _, mut cfg) = match policy_id {
        Some(pid) => db
            .conn
            .query_row(
                "SELECT id,version,name,config_json FROM policies WHERE id=?1 AND dataset_id=?2",
                params![pid, dataset_id],
                |r| {
                    let raw: String = r.get(3)?;
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        serde_json::from_str::<PolicyConfig>(&raw).unwrap_or_default(),
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| notfound("策略不存在"))?,
        None => load_policy(&db, dataset_id).ok_or_else(|| bad("请先保存脱敏策略"))?,
    };
    if let Some(k) = k_override {
        cfg.k_anonymity.k = k;
    }
    let k = cfg.k_anonymity.k.max(2);
    // ensure policy version recorded
    let policy_snapshot = serde_json::to_string(&cfg).unwrap_or_default();
    drop(db);

    let output = crate::engine::run(crate::engine::EngineInput {
        dataset_id,
        project_id,
        tables,
        kinds,
        policy: cfg.clone(),
        master_key: st.master_key,
        k,
    });
    let risk = serde_json::to_value(&output.risk).unwrap_or(json!({}));
    let quality = serde_json::to_value(&output.quality).unwrap_or(json!({}));
    let findings = serde_json::to_value(collection_findings(&output, k)).unwrap_or(json!([]));
    let d = st.db.lock().unwrap();
    d.conn.execute(
        "INSERT INTO releases (id,dataset_id,policy_id,policy_version,policy_snapshot_json,project_id,k,status,risk_json,quality_json,findings_json,created_by,created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            release_id,
            dataset_id,
            pid,
            version,
            policy_snapshot,
            project_id,
            k as i64,
            if output.risk.passed { "pending" } else { "blocked" },
            serde_json::to_string(&risk).unwrap_or_default(),
            serde_json::to_string(&quality).unwrap_or_default(),
            serde_json::to_string(&findings).unwrap_or_default(),
            created_by,
            crate::util::now_iso()
        ],
    )?;
    d.conn.execute(
        "UPDATE datasets SET status='evaluated',updated_at=?1 WHERE id=?2",
        params![crate::util::now_iso(), dataset_id],
    )?;
    d.audit(
        created_by,
        if output.risk.passed { "release.evaluate.pass" } else { "release.evaluate.block" },
        dataset_id,
        project_id,
        release_id,
        &pid,
        &format!(
            "策略「{}」v{}，课题组「{}」，k={}，判定{}；k_min={}，残留={}，抑制={}",
            project.name,
            version,
            project.group_name,
            k,
            if output.risk.passed { "通过" } else { "不通过" },
            output.risk.min_class_size,
            output.risk.high_confidence_residual,
            output.risk.suppressed_rows
        ),
    )?;
    let risk_value = serde_json::to_value(&output.risk).unwrap_or(json!({}));
    Ok((risk_value, cfg, version, pid))
}

fn collection_findings(out: &crate::engine::EngineOutput, _k: usize) -> Vec<Value> {
    let mut v: Vec<Value> = out
        .risk
        .criteria
        .iter()
        .map(|c| {
            json!({
                "severity": if c.passed { "info" } else { "error" },
                "code": "risk",
                "message": format!("{}：{}", c.name, c.detail),
                "passed": c.passed
            })
        })
        .collect();
    if out.risk.suppressed_rows > 0 {
        v.push(json!({
            "severity": "warn",
            "code": "suppressed",
            "message": format!("为保证 k 匿名抑制了 {} 行数据（涉及 {} 位患者）", out.risk.suppressed_rows, out.risk.patients_suppressed),
            "passed": true
        }));
    }
    if !out.quality.interval_preserved {
        v.push(json!({
            "severity": "warn",
            "code": "interval",
            "message": "住院天数/用药间隔统计量发生偏差，请检查日期平移逻辑",
            "passed": false
        }));
    }
    v
}

async fn list_releases(State(st): State<SharedState>) -> ApiResult {
    let db = st.db.lock().unwrap();
    let mut stmt = db.conn.prepare(
        "SELECT r.id,r.dataset_id,COALESCE(d.name,''),r.policy_id,r.policy_version,r.project_id,
                COALESCE(p.name,''),COALESCE(p.group_name,''),r.k,r.status,r.risk_json,r.created_by,r.created_at,
                r.approved_by,r.approved_at
         FROM releases r
         LEFT JOIN datasets d ON d.id=r.dataset_id
         LEFT JOIN projects p ON p.id=r.project_id
         ORDER BY r.created_at DESC",
    )?;
    let rows: Vec<Value> = stmt
        .query_map([], |r| {
            let risk: String = r.get(10)?;
            let rv: Value = serde_json::from_str(&risk).unwrap_or(json!({}));
            let passed = rv.get("passed").and_then(|v| v.as_bool()).unwrap_or(false);
            Ok(json!({
                "id": r.get::<_,String>(0)?,
                "dataset_id": r.get::<_,String>(1)?,
                "dataset_name": r.get::<_,String>(2)?,
                "policy_id": r.get::<_,String>(3)?,
                "policy_version": r.get::<_,i64>(4)?,
                "project_id": r.get::<_,String>(5)?,
                "project_name": r.get::<_,String>(6)?,
                "group_name": r.get::<_,String>(7)?,
                "k": r.get::<_,i64>(8)?,
                "status": r.get::<_,String>(9)?,
                "risk": rv,
                "created_by": r.get::<_,String>(11)?,
                "created_at": r.get::<_,String>(12)?,
                "approved_by": r.get::<_,String>(13)?,
                "approved_at": r.get::<_,Option<String>>(14)?,
                "passed": passed,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(Json(json!({"releases": rows})))
}

async fn create_release(
    State(st): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<CreateRelease>,
) -> ApiResult {
    let release_id = crate::util::new_id("rel");
    let who = body.created_by.clone().or(body.actor.clone()).unwrap_or_else(|| actor(&headers));
    let (risk, _cfg, _version, _pid) = evaluate_and_store(
        &st,
        &body.dataset_id,
        &body.project_id,
        body.policy_id.as_deref(),
        body.k,
        &who,
        &release_id,
    )?;
    Ok(Json(json!({"id": release_id, "passed": risk["passed"], "risk": risk})))
}

async fn get_release(State(st): State<SharedState>, Path(id): Path<String>) -> ApiResult {
    let db = st.db.lock().unwrap();
    let mut stmt = db.conn.prepare(
        "SELECT r.id,r.dataset_id,COALESCE(d.name,''),r.policy_id,r.policy_version,r.project_id,
                COALESCE(p.name,''),COALESCE(p.group_name,''),r.k,r.status,r.risk_json,r.quality_json,
                r.findings_json,r.created_by,r.created_at,r.approved_by,r.approved_at,r.rejected_reason,
                r.manifest_json,r.artifact_sha256,r.policy_snapshot_json,r.artifact_dir
         FROM releases r
         LEFT JOIN datasets d ON d.id=r.dataset_id
         LEFT JOIN projects p ON p.id=r.project_id
         WHERE r.id=?1",
    )?;
    let row = stmt
        .query_row(params![id], |r| {
            let risk: String = r.get(10)?;
            let quality: String = r.get(11)?;
            let findings: String = r.get(12)?;
            let manifest: String = r.get(18)?;
            let status: String = r.get(9)?;
            let policy_snapshot: String = r.get(20)?;
            let passed = serde_json::from_str::<Value>(&risk)
                .ok()
                .and_then(|v| v.get("passed").and_then(|x| x.as_bool()))
                .unwrap_or(false);
            let approved = status == "approved";
            Ok(json!({
                "id": r.get::<_,String>(0)?,
                "dataset_id": r.get::<_,String>(1)?,
                "dataset_name": r.get::<_,String>(2)?,
                "policy_id": r.get::<_,String>(3)?,
                "policy_version": r.get::<_,i64>(4)?,
                "project_id": r.get::<_,String>(5)?,
                "project_name": r.get::<_,String>(6)?,
                "group_name": r.get::<_,String>(7)?,
                "k": r.get::<_,i64>(8)?,
                "status": status,
                "risk": serde_json::from_str::<Value>(&risk).unwrap_or(json!({})),
                "quality": serde_json::from_str::<Value>(&quality).unwrap_or(json!({})),
                "findings": serde_json::from_str::<Value>(&findings).unwrap_or(json!([])),
                "created_by": r.get::<_,String>(13)?,
                "created_at": r.get::<_,String>(14)?,
                "approved_by": r.get::<_,String>(15)?,
                "approved_at": r.get::<_,Option<String>>(16)?,
                "rejected_reason": r.get::<_,String>(17)?,
                "manifest": serde_json::from_str::<Value>(&manifest).unwrap_or(json!({})),
                "artifact_sha256": r.get::<_,String>(19)?,
                "policy_snapshot": serde_json::from_str::<Value>(&policy_snapshot).unwrap_or(json!({})),
                "artifact_dir": r.get::<_,String>(21)?,
                "passed": passed,
                "can_approve": passed && status == "pending",
                "can_export": approved,
            }))
        })
        .optional()?
        .ok_or_else(|| notfound("发布记录不存在"))?;
    Ok(Json(json!({"release": row})))
}

async fn delete_release(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult {
    let db = st.db.lock().unwrap();
    let status: String = db
        .conn
        .query_row("SELECT status FROM releases WHERE id=?1", params![id], |r| r.get(0))
        .optional()?
        .ok_or_else(|| notfound("发布记录不存在"))?;
    if status == "approved" {
        return Err(conflict("已批准的发布不能删除，以保留审计追溯"));
    }
    db.conn.execute("DELETE FROM releases WHERE id=?1", params![id])?;
    db.audit(&actor(&headers), "release.delete", "", "", &id, "", "删除未批准发布记录")?;
    Ok(Json(json!({"deleted": true})))
}

#[derive(Deserialize)]
struct ApproveBody {
    approved_by: Option<String>,
    #[allow(dead_code)]
    note: Option<String>,
}

async fn approve_release(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ApproveBody>,
) -> ApiResult {
    let who = body.approved_by.unwrap_or_else(|| actor(&headers));
    if who.trim().is_empty() {
        return Err(bad("审批人不能为空"));
    }
    let release_row = {
        let db = st.db.lock().unwrap();
        let row: Option<(String, String, String, i64, String, String, String)> = db
            .conn
            .query_row(
                "SELECT dataset_id,project_id,policy_id,k,risk_json,policy_version,policy_snapshot_json FROM releases WHERE id=?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get::<_, i64>(5)?.to_string(), r.get(6)?)),
            )
            .optional()?;
        row.ok_or_else(|| notfound("发布记录不存在"))?
    };
    let (dataset_id, project_id, policy_id, k, risk_json, policy_version, policy_snapshot) = release_row;
    let risk: Value = serde_json::from_str(&risk_json).unwrap_or(json!({}));
    let passed = risk.get("passed").and_then(|v| v.as_bool()).unwrap_or(false);
    if !passed {
        return Err(conflict(
            "风险评估未通过，系统拒绝审批与导出。请调整脱敏策略或 k 值后重新评估。",
        ));
    }
    // re-run the engine to produce the artifact for the approved snapshot
    let ds_name = {
        let db = st.db.lock().unwrap();
        find_dataset(&db, &dataset_id)
            .map(|d| d["name"].as_str().unwrap_or("").to_string())
            .unwrap_or_default()
    };
    let project = {
        let db = st.db.lock().unwrap();
        load_project(&db, &project_id).ok_or_else(|| notfound("课题组不存在"))?
    };
    let tables = {
        let db = st.db.lock().unwrap();
        load_tables(&db, &dataset_id)
    };
    let kinds = {
        let db = st.db.lock().unwrap();
        load_kinds(&db, &dataset_id)
    };
    let cfg: PolicyConfig = serde_json::from_str(&policy_snapshot).unwrap_or_default();
    let output = crate::engine::run(crate::engine::EngineInput {
        dataset_id: &dataset_id,
        project_id: &project_id,
        tables,
        kinds,
        policy: cfg,
        master_key: st.master_key,
        k: k as usize,
    });
    if !output.risk.passed {
        return Err(conflict("重放脱敏流水线后风险评估变为不通过，已阻止发布"));
    }
    let now = crate::util::now_iso();
    let seed = crate::release::ManifestSeed {
        dataset_id: dataset_id.clone(),
        dataset_name: ds_name,
        project_id: project.id.clone(),
        project_name: project.name.clone(),
        group_name: project.group_name.clone(),
        policy_id: policy_id.clone(),
        policy_version: policy_version.parse().unwrap_or(1),
        k: k as usize,
        created_by: who.clone(),
        created_at: now.clone(),
        approved_by: who.clone(),
        approved_at: Some(now.clone()),
    };
    let art = crate::release::build(&st.data_dir.join("releases"), &id, &seed, &output)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("生成发布包失败: {e}")))?;

    let manifest_value = serde_json::to_value(&art.manifest).unwrap_or(json!({}));
    let db = st.db.lock().unwrap();
    db.conn.execute(
        "UPDATE releases SET status='approved',approved_by=?1,approved_at=?2,manifest_json=?3,artifact_sha256=?4,artifact_dir=?5
         WHERE id=?6",
        params![
            who,
            now,
            serde_json::to_string(&manifest_value).unwrap_or_default(),
            art.zip_sha256,
            art.dir.to_string_lossy().to_string(),
            id
        ],
    )?;
    let detail = format!(
        "批准发布至课题组「{}」；策略 v{}，k={}，最小等价类 {}，抑制 {} 行；发布包 sha256={}",
        project.group_name, policy_version, k, output.risk.min_class_size, output.risk.suppressed_rows,
        &art.zip_sha256[..16.min(art.zip_sha256.len())]
    );
    db.audit(&who, "release.approve", &dataset_id, &project_id, &id, &policy_id, &detail)?;
    Ok(Json(json!({
        "approved": true,
        "approved_by": who,
        "approved_at": now,
        "artifact_sha256": art.zip_sha256,
        "manifest": manifest_value,
    })))
}

#[derive(Deserialize)]
struct RejectBody {
    reason: String,
    actor: Option<String>,
}

async fn reject_release(
    State(st): State<SharedState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RejectBody>,
) -> ApiResult {
    let who = body.actor.unwrap_or_else(|| actor(&headers));
    let db = st.db.lock().unwrap();
    let n = db.conn.execute(
        "UPDATE releases SET status='rejected',approved_by=?1,approved_at=?2,rejected_reason=?3 WHERE id=?4",
        params![who, crate::util::now_iso(), body.reason, id],
    )?;
    if n == 0 {
        return Err(notfound("发布记录不存在"));
    }
    db.audit(&who, "release.reject", "", "", &id, "", &format!("驳回发布：{}", body.reason))?;
    Ok(Json(json!({"rejected": true})))
}

async fn export_release(State(st): State<SharedState>, Path(id): Path<String>) -> Result<Response, ApiError> {
    let db = st.db.lock().unwrap();
    let row: Option<(String, String)> = db
        .conn
        .query_row(
            "SELECT status,artifact_dir FROM releases WHERE id=?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (status, dir) = row.ok_or_else(|| notfound("发布记录不存在"))?;
    if status != "approved" {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "未通过审批的发布不能导出。请先完成风险评估与审批。".into(),
        ));
    }
    if dir.is_empty() {
        return Err(ApiError(StatusCode::NOT_FOUND, "发布包不存在".into()));
    }
    let zip_path = std::path::Path::new(&dir).with_extension("zip");
    let bytes = std::fs::read(&zip_path)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("读取发布包失败: {e}")))?;
    let name = format!("{}.zip", id);
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/zip")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", name),
        )
        .body(Body::from(bytes))
        .unwrap())
}

async fn download_artifact(
    State(st): State<SharedState>,
    Path((id, name)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    if name.contains("..") || name.contains('/') {
        return Err(bad("非法文件名"));
    }
    let db = st.db.lock().unwrap();
    let (status, dir): (String, String) = db
        .conn
        .query_row(
            "SELECT status,artifact_dir FROM releases WHERE id=?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .ok_or_else(|| notfound("发布记录不存在"))?;
    if status != "approved" {
        return Err(ApiError(StatusCode::FORBIDDEN, "未审批通过".into()));
    }
    let path = std::path::Path::new(&dir).join(&name);
    let bytes = std::fs::read(&path).map_err(|_| notfound("文件不存在"))?;
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(bytes))
        .unwrap())
}

async fn release_manifest(State(st): State<SharedState>, Path(id): Path<String>) -> ApiResult {
    let db = st.db.lock().unwrap();
    let raw: String = db
        .conn
        .query_row(
            "SELECT manifest_json FROM releases WHERE id=?1",
            params![id],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| notfound("发布记录不存在"))?;
    Ok(Json(json!({"manifest": serde_json::from_str::<Value>(&raw).unwrap_or(json!({}))})))
}

// ---------- audit ----------

#[derive(Deserialize)]
struct AuditQuery {
    dataset_id: Option<String>,
    project_id: Option<String>,
    release_id: Option<String>,
    action: Option<String>,
    q: Option<String>,
    limit: Option<usize>,
}

async fn list_audit(State(st): State<SharedState>, Query(q): Query<AuditQuery>) -> ApiResult {
    let db = st.db.lock().unwrap();
    let mut stmt = db.conn.prepare(
        "SELECT id,event_time,actor,action,dataset_id,project_id,release_id,policy_id,detail,hash_prev,hash_self
         FROM audit_log ORDER BY id ASC",
    )?;
    let all: Vec<AuditRow> = stmt
        .query_map([], |r| {
            Ok(AuditRow {
                id: r.get(0)?,
                event_time: r.get(1)?,
                actor: r.get(2)?,
                action: r.get(3)?,
                dataset_id: r.get(4)?,
                project_id: r.get(5)?,
                release_id: r.get(6)?,
                policy_id: r.get(7)?,
                detail: r.get(8)?,
                hash_prev: r.get(9)?,
                hash_self: r.get(10)?,
                chain_ok: true,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    // verify chain
    let mut prev_hash = String::new();
    let mut all_ok = true;
    let mut verified: Vec<AuditRow> = Vec::new();
    for (i, mut row) in all.into_iter().enumerate() {
        let seq = row.id;
        let payload = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            seq, row.event_time, row.actor, row.action, row.dataset_id, row.project_id, row.release_id, row.policy_id, row.detail
        );
        let expect = crate::util::sha256_hex(format!("{}|{}", prev_hash, payload).as_bytes());
        row.chain_ok = row.hash_prev == prev_hash && row.hash_self == expect;
        if !row.chain_ok {
            all_ok = false;
        }
        prev_hash = row.hash_self.clone();
        let _ = i;
        verified.push(row);
    }
    let mut filtered: Vec<&AuditRow> = verified.iter().collect();
    if let Some(d) = &q.dataset_id {
        filtered.retain(|r| &r.dataset_id == d);
    }
    if let Some(p) = &q.project_id {
        filtered.retain(|r| &r.project_id == p);
    }
    if let Some(rl) = &q.release_id {
        filtered.retain(|r| &r.release_id == rl);
    }
    if let Some(a) = &q.action {
        filtered.retain(|r| r.action.contains(a.as_str()));
    }
    if let Some(s) = &q.q {
        filtered.retain(|r| {
            r.detail.contains(s.as_str())
                || r.action.contains(s.as_str())
                || r.actor.contains(s.as_str())
        });
    }
    let total = filtered.len();
    filtered.reverse();
    filtered.truncate(q.limit.unwrap_or(200));
    Ok(Json(json!({
        "events": filtered,
        "total": total,
        "chain_ok": all_ok,
    })))
}

async fn verify_audit(State(st): State<SharedState>) -> ApiResult {
    let db = st.db.lock().unwrap();
    let (count, chain_ok, last_hash) = crate::audit::verify(&db)?;
    Ok(Json(json!({"events": count, "chain_ok": chain_ok, "last_hash": last_hash})))
}

// ---------- synthetic ----------

#[derive(Deserialize)]
struct GenerateBody {
    patients: Option<usize>,
    seed: Option<u64>,
    name: Option<String>,
}

async fn generate_synthetic(
    State(st): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<GenerateBody>,
) -> ApiResult {
    let patients = body.patients.unwrap_or(300).clamp(50, 100000);
    let seed = body.seed.unwrap_or(20260101);
    let ds = crate::synth::generate(patients, seed);
    let name = body
        .name
        .unwrap_or_else(|| format!("合成测试数据（{} 例）", patients));
    let id = crate::util::new_id("ds");
    let now = crate::util::now_iso();

    let mut profile = serde_json::to_value(&ds.profile).unwrap_or(json!({}));
    let det_report = {
        let texts: Vec<(String, usize, String, String)> = ds
            .tables
            .iter()
            .flat_map(|t| {
                let table = t.table_name.clone();
                let headers = t.headers.clone();
                t.rows
                    .iter()
                    .enumerate()
                    .flat_map(move |(ri, row)| {
                        let table = table.clone();
                        let headers: Vec<(usize, String)> = headers
                            .iter()
                            .enumerate()
                            .map(|(i, h)| (i, h.clone()))
                            .collect();
                        headers.into_iter().filter_map(move |(ci, h)| {
                            if crate::csvio::is_free_text_header(&h) {
                                Some((table.clone(), ri, h.clone(), row[ci].clone()))
                            } else {
                                None
                            }
                        })
                    })
            })
            .collect();
        crate::detection_eval::evaluate(crate::detection_eval::TruthInput {
            truth: &ds.truth,
            texts,
        })
    };
    let column_eval = {
        let mut correct = 0;
        let mut total = 0;
        let mut mistakes = Vec::new();
        let ft_cols: Vec<String> = crate::csvio::FREE_TEXT_HEADERS
            .iter()
            .map(|s| s.to_string())
            .collect();
        for ct in &ds.column_truth {
            let t = match ds.tables.iter().find(|t| t.table_name == ct.table) {
                Some(t) => t,
                None => continue,
            };
            let col_idx = match t.headers.iter().position(|h| h == &ct.column) {
                Some(i) => i,
                None => {
                    mistakes.push(json!({"table": ct.table, "column": ct.column, "expected": ct.kind, "actual": "missing"}));
                    continue;
                }
            };
            let values: Vec<String> = t.rows.iter().filter_map(|r| r.get(col_idx).cloned()).collect();
            let det = crate::detect::detect_column(
                &ct.column,
                &values,
                if crate::csvio::is_free_text_header(&ct.column) {
                    &ft_cols
                } else {
                    &[]
                },
            );
            let actual = serde_json::to_value(&det.kind)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_default();
            total += 1;
            if actual == ct.kind {
                correct += 1;
            } else {
                mistakes.push(json!({"table": ct.table, "column": ct.column, "expected": ct.kind, "actual": actual}));
            }
        }
        json!({
            "columns": total,
            "correct": correct,
            "accuracy": if total == 0 { 1.0 } else { correct as f64 / total as f64 },
            "mistakes": mistakes,
        })
    };
    profile["detection_eval"] = serde_json::to_value(&det_report).unwrap_or(json!({}));
    profile["column_eval"] = column_eval;
    profile["truth_spans_total"] = json!(ds.truth.len());
    profile["free_text_labels"] = json!(ds.truth);
    profile["column_truth"] = json!(ds.column_truth);

    let db = st.db.lock().unwrap();
    db.conn.execute(
        "INSERT INTO datasets (id,name,source,owner,description,status,row_count,metrics_json,created_at,updated_at)
         VALUES (?1,?2,'合成数据','科研处','自动生成的测试数据集，含门诊/住院/自由文本与埋点真值','loaded',?3,?4,?5,?5)",
        params![
            id,
            name,
            ds.profile.inpatient_rows as i64
                + ds.profile.outpatient_rows as i64
                + ds.profile.medication_rows as i64
                + ds.profile.note_rows as i64
                + ds.profile.patients as i64,
            serde_json::to_string(&profile).unwrap_or_else(|_| "{}".into()),
            now
        ],
    )?;
    for t in &ds.tables {
        let file_id = crate::util::new_id("f");
        db.conn.execute(
            "INSERT INTO dataset_files (id,dataset_id,file_name,table_name,table_type,headers,rows_json,row_count,created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                file_id,
                id,
                t.file_name,
                t.table_name,
                t.table_type,
                serde_json::to_string(&t.headers).unwrap_or_default(),
                serde_json::to_string(&t.rows).unwrap_or_default(),
                t.rows.len() as i64,
                now
            ],
        )?;
    }
    db.audit(
        &actor(&headers),
        "dataset.generate",
        &id,
        "",
        "",
        "",
        &format!("生成合成测试数据 {} 例，埋点真值 {} 处", patients, ds.truth.len()),
    )?;
    Ok(Json(json!({
        "id": id,
        "name": name,
        "profile": profile,
        "free_text_detection": det_report_public(&ds),
    })))
}

fn det_report_public(ds: &crate::synth::SyntheticDataset) -> Value {
    let texts: Vec<(String, usize, String, String)> = ds
        .tables
        .iter()
        .flat_map(|t| {
            let table = t.table_name.clone();
            let headers = t.headers.clone();
            t.rows
                .iter()
                .enumerate()
                .flat_map(move |(ri, row)| {
                    let table = table.clone();
                    let headers: Vec<(usize, String)> = headers
                        .iter()
                        .enumerate()
                        .map(|(i, h)| (i, h.clone()))
                        .collect();
                    headers.into_iter().filter_map(move |(ci, h)| {
                        if crate::csvio::is_free_text_header(&h) {
                            Some((table.clone(), ri, h.clone(), row[ci].clone()))
                        } else {
                            None
                        }
                    })
                })
        })
        .collect();
    serde_json::to_value(crate::detection_eval::evaluate(
        crate::detection_eval::TruthInput {
            truth: &ds.truth,
            texts,
        },
    ))
    .unwrap_or(json!({}))
}

// ---------- static ----------

async fn static_handler(uri: axum::http::Uri) -> Response {
    let path = uri.path();
    let asset = match path {
        "/" => Some(("index.html", include_str!("../web/index.html"))),
        "/app.js" => Some(("app.js", include_str!("../web/app.js"))),
        "/style.css" => Some(("style.css", include_str!("../web/style.css"))),
        _ => None,
    };
    match asset {
        Some((_, body)) => {
            let ct = if path.ends_with(".js") {
                "application/javascript; charset=utf-8"
            } else if path.ends_with(".css") {
                "text/css; charset=utf-8"
            } else {
                "text/html; charset=utf-8"
            };
            Response::builder()
                .header(header::CONTENT_TYPE, ct)
                .body(Body::from(body))
                .unwrap()
        }
        None => (StatusCode::NOT_FOUND, "404").into_response(),
    }
}
