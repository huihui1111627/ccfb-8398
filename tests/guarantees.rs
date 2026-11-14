//! End-to-end tests for the privacy guarantees the platform claims:
//! pseudonym stability/linkability, date-shift interval preservation,
//! k-anonymity escalation, residual-free free text, and audit chaining.

use medmask::detect::TextExtractor;
use medmask::engine::{run, EngineInput};
use medmask::synth;

fn setup(n: usize, seed: u64) -> (Vec<medmask::db::TableData>, medmask::models::PolicyConfig) {
    let ds = synth::generate(n, seed);
    // Column kinds are re-derived with the same detector the server uses, so the
    // tests exercise the production path rather than a hand-built fixture.
    (ds.tables, medmask::models::PolicyConfig::default())
}

fn kinds_for(tables: &[medmask::db::TableData]) -> std::collections::HashMap<(String, String), medmask::models::ColumnKind> {
    let ft_cols: Vec<String> = medmask::csvio::FREE_TEXT_HEADERS.iter().map(|s| s.to_string()).collect();
    let mut kinds = std::collections::HashMap::new();
    for t in tables {
        for (ci, h) in t.headers.iter().enumerate() {
            let values: Vec<String> = t.rows.iter().filter_map(|r| r.get(ci).cloned()).collect();
            let det = medmask::detect::detect_column(
                h,
                &values,
                if medmask::csvio::is_free_text_header(h) { &ft_cols } else { &[] },
            );
            kinds.insert((t.id.clone(), h.clone()), det.kind);
        }
    }
    kinds
}

fn run_engine(tables: Vec<medmask::db::TableData>, project: &str, k: usize, policy: medmask::models::PolicyConfig) -> medmask::engine::EngineOutput {
    let kinds = kinds_for(&tables);
    run(EngineInput {
        dataset_id: "ds_test",
        project_id: project,
        tables,
        kinds,
        policy,
        master_key: [7u8; 32],
        k,
    })
}

#[test]
fn pseudonyms_are_stable_within_project_and_differ_across_projects() {
    let (tables, policy) = setup(60, 11);
    let a = run_engine(tables.clone(), "proj_a", 3, policy.clone());
    let b = run_engine(tables.clone(), "proj_a", 3, policy.clone());
    let c = run_engine(tables, "proj_b", 3, policy.clone());

    // collect the set of patient tokens in the patients table for each run
    let tokens = |out: &medmask::engine::EngineOutput| -> Vec<String> {
        out.tables
            .iter()
            .find(|t| t.table_name == "患者主索引")
            .map(|t| t.rows.iter().map(|r| r[0].clone()).collect())
            .unwrap_or_default()
    };
    let ta = tokens(&a);
    let tb = tokens(&b);
    let tc = tokens(&c);
    assert!(!ta.is_empty());
    assert_eq!(ta, tb, "same project must yield identical pseudonyms run to run");
    // cross-project overlap should be empty
    let set_a: std::collections::HashSet<_> = ta.iter().collect();
    assert!(
        tc.iter().all(|t| !set_a.contains(t)),
        "pseudonyms must not be comparable across projects"
    );
}

#[test]
fn same_patient_token_across_all_tables() {
    let (tables, policy) = setup(80, 5);
    let out = run_engine(tables, "proj_x", 3, policy);
    let mut per_table: Vec<std::collections::HashSet<String>> = vec![];
    for t in &out.tables {
        if let Some(idx) = t.headers.iter().position(|h| h == "病案号") {
            per_table.push(t.rows.iter().map(|r| r[idx].clone()).filter(|s| !s.is_empty()).collect());
        }
    }
    assert!(per_table.len() >= 3);
    // every table's patient set should be a subset of the master index
    let master = &per_table[0];
    for (i, s) in per_table.iter().enumerate().skip(1) {
        let missing: Vec<_> = s.difference(master).collect();
        assert!(missing.is_empty(), "table {i} has tokens not in master index: {missing:?}");
    }
}

#[test]
fn date_shift_preserves_intervals() {
    let (tables, policy) = setup(120, 3);
    // record original LOS and medication interval per row position
    let orig_los: Vec<i64> = {
        let t = tables.iter().find(|t| t.table_name == "住院记录").unwrap();
        let ci = t.headers.iter().position(|h| h == "住院天数").unwrap();
        t.rows.iter().map(|r| r[ci].parse().unwrap()).collect()
    };
    let out = run_engine(tables, "proj_y", 3, policy);
    let t = out.tables.iter().find(|t| t.table_name == "住院记录").unwrap();
    let los_ci = t.headers.iter().position(|h| h == "住院天数").unwrap();
    let adm = t.headers.iter().position(|h| h == "入院日期").unwrap();
    let dis = t.headers.iter().position(|h| h == "出院日期").unwrap();
    // LOS column untouched; and discharge-admit difference must equal LOS-1 for every row
    for row in &t.rows {
        let los: i64 = row[los_ci].parse().unwrap();
        let a = medmask::util::parse_date(&row[adm]).unwrap();
        let d = medmask::util::parse_date(&row[dis]).unwrap();
        assert_eq!((d - a).num_days(), los - 1, "date gap must equal stated LOS");
    }
    // the multiset of LOS values in survivors is a subset of the original
    let orig_set: std::collections::HashMap<i64, usize> =
        orig_los.iter().fold(Default::default(), |mut m, v| { *m.entry(*v).or_insert(0) += 1; m });
    for row in &t.rows {
        let los: i64 = row[los_ci].parse().unwrap();
        assert!(orig_set.contains_key(&los));
    }
}

#[test]
fn k_anonymity_is_met_or_rows_suppressed() {
    let (tables, mut policy) = setup(150, 21);
    policy.k_anonymity.k = 5;
    let out = run_engine(tables, "proj_k", 5, policy);
    assert!(
        out.risk.min_class_size >= 5,
        "expected min class >= k after escalation/suppression, got {}",
        out.risk.min_class_size
    );
}

#[test]
fn free_text_is_residual_free() {
    let (tables, policy) = setup(80, 8);
    let out = run_engine(tables, "proj_r", 3, policy);
    assert_eq!(
        out.risk.high_confidence_residual, 0,
        "residual identifiers remain: {:?}",
        out.risk.residual.iter().take(5).collect::<Vec<_>>()
    );
}

#[test]
fn detection_recall_and_precision_are_high() {
    let ds = synth::generate(80, 8);
    let texts: Vec<(String, usize, String, String)> = ds
        .tables
        .iter()
        .flat_map(|t| {
            let table = t.table_name.clone();
            let headers = t.headers.clone();
            t.rows.iter().enumerate().flat_map(move |(ri, row)| {
                let table = table.clone();
                let headers: Vec<(usize, String)> =
                    headers.iter().enumerate().map(|(i, h)| (i, h.clone())).collect();
                headers.into_iter().filter_map(move |(ci, h)| {
                    if medmask::csvio::is_free_text_header(&h) {
                        Some((table.clone(), ri, h.clone(), row[ci].clone()))
                    } else {
                        None
                    }
                })
            })
        })
        .collect();
    let report = medmask::detection_eval::evaluate(medmask::detection_eval::TruthInput {
        truth: &ds.truth,
        texts,
    });
    assert!(report.totals.recall >= 0.85, "recall too low: {}", report.totals.recall);
    assert!(report.totals.precision >= 0.85, "precision too low: {}", report.totals.precision);
    // per-type phone/id/address/mrn must be essentially perfect
    for t in &report.per_type {
        if ["身份证号", "手机号", "住址", "病案号"].contains(&t.pii_type.as_str()) {
            assert!(t.recall >= 0.99, "{} recall {}", t.pii_type, t.recall);
            assert!(t.fpr <= 0.02, "{} fpr {}", t.pii_type, t.fpr);
        }
    }
}

#[test]
fn audit_chain_detects_tampering() {
    let db = medmask::db::Db::open_memory().unwrap();
    db.audit("a", "one", "d", "", "", "", "first").unwrap();
    db.audit("b", "two", "d", "", "", "", "second").unwrap();
    db.audit("c", "three", "d", "", "", "", "third").unwrap();
    let (n, ok, _) = medmask::audit::verify(&db).unwrap();
    assert_eq!(n, 3);
    assert!(ok);
    // tamper with the middle record
    db.conn
        .execute("UPDATE audit_log SET detail='tampered' WHERE id=2", [])
        .unwrap();
    let (_, ok2, _) = medmask::audit::verify(&db).unwrap();
    assert!(!ok2, "tamper must break the chain");
}

#[test]
fn text_extractor_finds_known_identifiers() {
    let ex = TextExtractor::new();
    let text = "患者：张伟，男，45岁，病案号：10000012，身份证号：110105196001010017，联系电话：13812345678，家庭住址：北京市朝阳区望京街道花家地小区22号楼2单元501室。";
    let found = ex.extract(text);
    let types: std::collections::HashSet<_> = found.iter().map(|m| m.pii_type.label()).collect();
    for t in ["姓名", "身份证号", "手机号", "住址", "病案号"] {
        assert!(types.contains(t), "missing {t} in {types:?}");
    }
}

#[test]
fn pseudonym_is_independent_of_batching() {
    // One row carries all three identifiers; another carries only MRN+name+birth.
    // Loading them together vs. loading the MRN-only row alone must give the
    // same pseudonym, because the canonical identifier is chosen from the class.
    let mut together = medmask::db::TableData {
        id: "f1".into(), file_name: "a.csv".into(), table_name: "主索引".into(),
        table_type: "structured".into(),
        headers: vec!["病案号".into(), "姓名".into(), "出生日期".into(), "身份证号".into()],
        rows: vec![
            vec!["M9001".into(), "张伟".into(), "1965-03-12".into(), "110105196503120017".into()],
            vec!["M9002".into(), "李娜".into(), "1978-11-02".into(), "110105197811020024".into()],
        ],
    };
    let kinds: std::collections::HashMap<(String,String), medmask::models::ColumnKind> = [
        (("f1".to_string(), "病案号".to_string()), medmask::models::ColumnKind::Mrn),
        (("f1".to_string(), "姓名".to_string()), medmask::models::ColumnKind::Name),
        (("f1".to_string(), "出生日期".to_string()), medmask::models::ColumnKind::BirthDate),
        (("f1".to_string(), "身份证号".to_string()), medmask::models::ColumnKind::IdCard),
    ].into_iter().collect();
    let run_on = |tables: Vec<medmask::db::TableData>, kinds: &std::collections::HashMap<(String,String), medmask::models::ColumnKind>, ds: &str| {
        medmask::engine::run(medmask::engine::EngineInput {
            dataset_id: ds, project_id: "p", tables, kinds: kinds.clone(),
            policy: medmask::models::PolicyConfig::default(), master_key: [3u8;32], k: 1,
        })
    };
    let full = run_on(vec![together.clone()], &kinds, "ds_one");
    // second batch: only the MRN/name/birth columns, separate file id
    let partial = medmask::db::TableData {
        id: "f2".into(), file_name: "b.csv".into(), table_name: "主索引".into(),
        table_type: "structured".into(),
        headers: vec!["病案号".into(), "姓名".into(), "出生日期".into()],
        rows: vec![vec!["M9001".into(), "张伟".into(), "1965-03-12".into()]],
    };
    let pk: std::collections::HashMap<(String,String), medmask::models::ColumnKind> = [
        (("f2".to_string(), "病案号".to_string()), medmask::models::ColumnKind::Mrn),
        (("f2".to_string(), "姓名".to_string()), medmask::models::ColumnKind::Name),
        (("f2".to_string(), "出生日期".to_string()), medmask::models::ColumnKind::BirthDate),
    ].into_iter().collect();
    let half = run_on(vec![partial], &pk, "ds_two");
    // find the token for 张伟 in each run (row 0 in both)
    let tok_full = &full.tables[0].rows[0][0];
    let tok_half = &half.tables[0].rows[0][0];
    assert_eq!(tok_full, tok_half, "同一患者的假名不应因批次/字段组合而改变");
}

#[test]
fn date_shift_is_project_scoped_and_batch_independent() {
    // Same patient in two datasets/with different field subsets, same project:
    // the admitted-date shift must be identical, so intervals can be merged.
    let make = |ds: &str, extra: bool| -> i64 {
        let mut headers = vec!["病案号".to_string(), "姓名".to_string(), "出生日期".to_string(), "入院日期".to_string()];
        let mut kinds: std::collections::HashMap<(String,String), medmask::models::ColumnKind> = [
            (("f".to_string(),"病案号".to_string()), medmask::models::ColumnKind::Mrn),
            (("f".to_string(),"姓名".to_string()), medmask::models::ColumnKind::Name),
            (("f".to_string(),"出生日期".to_string()), medmask::models::ColumnKind::BirthDate),
            (("f".to_string(),"入院日期".to_string()), medmask::models::ColumnKind::Date),
        ].into_iter().collect();
        if extra {
            headers.push("身份证号".into());
            kinds.insert(("f".to_string(),"身份证号".to_string()), medmask::models::ColumnKind::IdCard);
        }
        let mut row = vec!["M9001".to_string(),"张伟".to_string(),"1965-03-12".to_string(),"2024-03-15".to_string()];
        if extra { row.push("110105196503120017".into()); }
        let t = medmask::db::TableData {
            id: "f".into(), file_name:"x.csv".into(), table_name:"t".into(), table_type:"structured".into(),
            headers, rows: vec![row],
        };
        let out = medmask::engine::run(medmask::engine::EngineInput {
            dataset_id: ds, project_id: "same_project", tables: vec![t], kinds,
            policy: medmask::models::PolicyConfig::default(), master_key: [9u8;32], k: 1,
        });
        let t = &out.tables[0];
        let ci = t.headers.iter().position(|h| h == "入院日期").unwrap();
        let orig = chrono::NaiveDate::from_ymd_opt(2024,3,15).unwrap();
        let got = medmask::util::parse_date(&t.rows[0][ci]).unwrap();
        (got - orig).num_days()
    };
    let a = make("ds1", false);
    let b = make("ds2", true);
    assert_eq!(a, b, "同一课题组内不同批次/字段组合的日期偏移必须一致");
}
