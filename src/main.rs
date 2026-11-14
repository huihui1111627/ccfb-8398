use medmask::{api, db, state, util};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() {
    let data_dir = std::env::var("MEDMASK_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("data"));
    std::fs::create_dir_all(&data_dir).expect("create data dir");
    let db_path = data_dir.join("medmask.db");
    let key_dir = data_dir.join("keys");
    let master_key = util::load_or_create_master_key(&key_dir).expect("master key");

    let db = db::Db::open(db_path.to_str().unwrap()).expect("open database");
    seed_demo_if_empty(&db);

    let state: state::SharedState = Arc::new(state::AppState {
        db: Arc::new(Mutex::new(db)),
        master_key,
        data_dir: data_dir.clone(),
    });

    let app = api::router(state.clone());
    let addr = std::env::var("MEDMASK_ADDR").unwrap_or_else(|_| "127.0.0.1:8398".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("bind {addr}: {e}"));
    println!("科研数据脱敏平台已启动: http://{addr}");
    println!("数据目录: {}", data_dir.display());
    axum::serve(listener, app).await.expect("server");
}

fn seed_demo_if_empty(db: &db::Db) {
    let count: i64 = db
        .conn
        .query_row("SELECT COUNT(*) FROM projects", [], |r| r.get(0))
        .unwrap_or(0);
    if count > 0 {
        return;
    }
    let now = util::now_iso();
    let projects = vec![
        ("prj_demo1", "心血管队列研究", "心内科课题组", "李教授", "回顾性分析高血压/冠心病住院结局"),
        ("prj_demo2", "呼吸系统疾病研究", "呼吸科课题组", "张研究员", "慢阻肺与肺炎的疗效比较"),
        ("prj_demo3", "医院管理研究", "医务处课题组", "王主任", "住院日与费用分析"),
    ];
    for (id, name, group, contact, desc) in projects {
        let _ = db.conn.execute(
            "INSERT INTO projects (id,name,group_name,contact,description,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params![id, name, group, contact, desc, now],
        );
    }
    let _ = db.audit(
        "系统",
        "system.seed",
        "",
        "",
        "",
        "",
        "初始化演示课题组（3 个），可用于验证跨课题组假名不一致",
    );
}
