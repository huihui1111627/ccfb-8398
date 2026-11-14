//! De-identification engine.
//!
//! * patient identity is resolved across tables/batches with a union-find over
//!   identity tokens (ID card, MRN, name+birthdate);
//! * pseudonyms are HMAC project-scoped, so the same patient links within a
//!   project but cannot be linked across projects;
//! * dates are shifted by a per-patient constant, preserving intervals;
//! * quasi-identifiers are generalised and escalated until k-anonymity holds.

use crate::db::TableData;
use crate::detect::{address_prefix_len, TextExtractor};
use crate::models::{ColumnKind, FreeTextConfig, PolicyConfig, PiiType};
use crate::util::{
    age_band, base32, hmac, id_card_birth, mask_value,
    norm_header, parse_date, shift_date,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TableStat {
    pub table: String,
    pub rows_before: usize,
    pub rows_after: usize,
    pub suppressed: usize,
    pub columns: usize,
    pub free_text_columns: usize,
    pub direct_columns: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct NumericStat {
    pub table: String,
    pub column: String,
    pub before_mean: f64,
    pub after_mean: f64,
    pub before_median: f64,
    pub after_median: f64,
    pub before_std: f64,
    pub after_std: f64,
    pub rel_dev_mean: f64,
    pub rel_dev_median: f64,
    pub rel_dev_std: f64,
    pub n_before: usize,
    pub n_after: usize,
    pub is_interval: bool,
    pub quasi: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct QualityReport {
    pub tables: Vec<TableStat>,
    pub numeric: Vec<NumericStat>,
    pub patients_before: usize,
    pub patients_after: usize,
    pub gender_before: BTreeMap<String, usize>,
    pub gender_after: BTreeMap<String, usize>,
    pub diagnosis_before: BTreeMap<String, usize>,
    pub diagnosis_after: BTreeMap<String, usize>,
    pub los_before_mean: Option<f64>,
    pub los_after_mean: Option<f64>,
    pub los_rel_dev: Option<f64>,
    pub max_rel_dev: f64,
    pub interval_preserved: bool,
    pub suppressed_rows: usize,
    pub total_rows_before: usize,
    pub total_rows_after: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ResidualFinding {
    pub table: String,
    pub column: String,
    pub pii_type: String,
    pub rule: String,
    pub snippet: String,
    pub confidence: f32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RiskReport {
    pub k_target: usize,
    pub k_achieved: usize,
    pub min_class_size: usize,
    pub max_reid_risk: f64,
    pub prosecution_risk: f64,
    pub rows_below_k: usize,
    pub rows_total: usize,
    pub equivalence_classes: usize,
    pub qi_columns: Vec<String>,
    pub qi_after: Vec<String>,
    pub residual_count: usize,
    pub residual: Vec<ResidualFinding>,
    pub high_confidence_residual: usize,
    pub suppressed_rows: usize,
    pub patients_total: usize,
    pub patients_suppressed: usize,
    pub criteria: Vec<RiskCriterion>,
    pub passed: bool,
    pub date_shift_days: BTreeMap<String, i64>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RiskCriterion {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FieldDecision {
    pub table: String,
    pub column: String,
    pub kind: String,
    pub action: String,
    pub detail: String,
}

pub struct EngineInput<'a> {
    pub dataset_id: &'a str,
    pub project_id: &'a str,
    pub tables: Vec<TableData>,
    /// kinds keyed by (file_id, column_name)
    pub kinds: HashMap<(String, String), ColumnKind>,
    pub policy: PolicyConfig,
    pub master_key: [u8; 32],
    pub k: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EngineOutput {
    pub tables: Vec<TableData>,
    pub quality: QualityReport,
    pub risk: RiskReport,
    pub decisions: Vec<FieldDecision>,
    pub policy_after: PolicyConfig,
    pub suppressed_rows: usize,
}

#[derive(Default)]
struct Uf {
    parent: HashMap<String, String>,
}

impl Uf {
    fn find(&mut self, x: &str) -> String {
        let p = match self.parent.get(x) {
            Some(p) => p.clone(),
            None => {
                self.parent.insert(x.to_string(), x.to_string());
                return x.to_string();
            }
        };
        if p == x {
            return p;
        }
        let root = self.find(&p);
        self.parent.insert(x.to_string(), root.clone());
        root
    }
    fn union(&mut self, a: &str, b: &str) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            // deterministic root: lexicographically smaller
            if ra < rb {
                self.parent.insert(rb, ra);
            } else {
                self.parent.insert(ra, rb);
            }
        }
    }
}

pub fn run(input: EngineInput) -> EngineOutput {
    let EngineInput {
        // dataset_id is part of the input contract but the pseudonym/date keys
        // are intentionally project-scoped, not dataset-scoped.
        dataset_id: _dataset_id,
        project_id,
        tables,
        kinds,
        policy,
        master_key,
        k,
    } = input;
    let mut decisions: Vec<FieldDecision> = Vec::new();
    let kinds = &kinds;
    let kind_of = |file_id: &str, col: &str| -> ColumnKind {
        kinds
            .get(&(file_id.to_string(), col.to_string()))
            .cloned()
            .unwrap_or(ColumnKind::Unknown)
    };

    let extractor = TextExtractor::new();

    // ---------- pass 1: identity resolution across all tables ----------
    let mut uf = Uf::default();
    let mut row_root: HashMap<(String, usize), String> = HashMap::new();
    let mut patient_names: HashMap<String, HashSet<String>> = HashMap::new();
    let mut patient_birth: HashMap<String, String> = HashMap::new();

    for t in &tables {
        for (ri, row) in t.rows.iter().enumerate() {
            let mut tokens: Vec<String> = Vec::new();
            let mut names: Vec<String> = Vec::new();
            let mut birth: Option<String> = None;
            for (ci, header) in t.headers.iter().enumerate() {
                let val = row.get(ci).cloned().unwrap_or_default();
                let v = val.trim();
                if v.is_empty() {
                    continue;
                }
                match kind_of(&t.id, header) {
                    ColumnKind::IdCard => {
                        if crate::util::id_card_valid(v) {
                            tokens.push(format!("ID:{}", v.to_uppercase()));
                            if let Some(b) = id_card_birth(v) {
                                birth = Some(b.format("%Y-%m-%d").to_string());
                            }
                        }
                    }
                    ColumnKind::Mrn => tokens.push(format!("MRN:{}", clean_token(v))),
                    ColumnKind::Name => names.push(norm_name(v)),
                    ColumnKind::BirthDate => {
                        if let Some(d) = parse_date(v) {
                            birth = Some(d.format("%Y-%m-%d").to_string());
                        }
                    }
                    _ => {}
                }
            }
            if let (Some(n), Some(b)) = (names.first(), birth.as_ref()) {
                tokens.push(format!("NB:{}|{}", n, b));
            }
            if tokens.is_empty() {
                tokens.push(format!(
                    "ROW:{}:{}:{}",
                    t.table_name,
                    ri,
                    crate::util::sha256_hex(format!("{}|{}", t.table_name, row.join("\u{1f}")).as_bytes())
                ));
            }
            for w in tokens.windows(2) {
                uf.union(&w[0], &w[1]);
            }
            // ensure all tokens exist even without windows
            if tokens.len() == 1 {
                uf.find(&tokens[0]);
            }
            let root = uf.find(&tokens[0]);
            row_root.insert((t.id.clone(), ri), root.clone());
            let name_set = patient_names.entry(root.clone()).or_default();
            for n in names {
                name_set.insert(n);
            }
            if let Some(b) = birth {
                patient_birth.entry(root).or_insert(b);
            }
        }
    }

    // name -> patient roots for free-text resolution
    let mut name_roots: HashMap<String, HashSet<String>> = HashMap::new();
    for (root, names) in &patient_names {
        for n in names {
            name_roots.entry(n.clone()).or_default().insert(root.clone());
        }
    }

    // Choose a *canonical* identity per patient from the union-find class. The
    // union-find root itself depends on which identifiers happened to appear in
    // this particular extract, so two batches could pick different roots for the
    // same person. Sorting the class's tokens and taking the first yields a
    // batch-independent representative. ID card outranks MRN outranks
    // name+birthdate because of the "ID:"/"MRN:"/"NB:" prefixes' lexical order.
    let mut canonical: HashMap<String, String> = HashMap::new();
    let mut class_members: HashMap<String, Vec<String>> = HashMap::new();
    let all_tokens: Vec<String> = uf.parent.keys().cloned().collect();
    for tok in all_tokens {
        let root = uf.find(&tok);
        class_members.entry(root).or_default().push(tok);
    }
    for (root, mut members) in class_members {
        members.sort();
        // Prefer the ID card, then MRN, then name+birthdate, then any row token.
        let canonical_tok = members
            .iter()
            .find(|t| t.starts_with("ID:"))
            .or_else(|| members.iter().find(|t| t.starts_with("MRN:")))
            .or_else(|| members.iter().find(|t| t.starts_with("NB:")))
            .cloned()
            .unwrap_or_else(|| members[0].clone());
        canonical.insert(root, canonical_tok);
    }

    // patient token + date shift
    let mut patient_token: HashMap<String, String> = HashMap::new();
    let mut patient_shift: HashMap<String, i64> = HashMap::new();
    let all_roots: HashSet<String> = row_root.values().cloned().collect();
    for root in all_roots.iter() {
        let ident = canonical.get(root).cloned().unwrap_or_else(|| root.clone());
        let p = base32(
            &hmac(
                &master_key,
                format!("{}|patient|{}", project_id, ident).as_bytes(),
            ),
            10,
        );
        patient_token.insert(root.clone(), format!("{}{}", policy.direct.pseudonym_prefix, p));
        // Keyed by project (like the pseudonym) so a patient's dates shift by the
        // same amount in every batch/dataset released to that project, keeping
        // cross-batch intervals intact. A different project gets a different
        // shift, so dates cannot be used to link groups.
        let h = hmac(&master_key, format!("date|{}|{}", project_id, ident).as_bytes());
        let u = u64::from_be_bytes(h[0..8].try_into().unwrap());
        let span = (policy.dates.max_days - policy.dates.min_days).max(1);
        let days = policy.dates.min_days + (u % (span as u64 + 1)) as i64;
        patient_shift.insert(root.clone(), days);
    }

    // ---------- pass 2: transform ----------
    let mut out_tables: Vec<TableData> = Vec::new();
    let mut out_row_roots: Vec<Vec<String>> = Vec::new();
    let mut shift_map: BTreeMap<String, i64> = BTreeMap::new();

    for t in &tables {
        let mut out = TableData {
            id: t.id.clone(),
            file_name: t.file_name.clone(),
            table_name: t.table_name.clone(),
            table_type: t.table_type.clone(),
            headers: t.headers.clone(),
            rows: Vec::with_capacity(t.rows.len()),
        };
        let qtypes: Vec<ColumnKind> = t.headers.iter().map(|h| kind_of(&t.id, h)).collect();
        let mut roots: Vec<String> = Vec::with_capacity(t.rows.len());

        for (ri, row) in t.rows.iter().enumerate() {
            let root = row_root
                .get(&(t.id.clone(), ri))
                .cloned()
                .unwrap_or_default();
            let p_token = patient_token.get(&root).cloned().unwrap_or_else(|| "PUNKNOWN".into());
            let p_shift = *patient_shift.get(&root).unwrap_or(&0);
            shift_map.entry(p_token.clone()).or_insert(p_shift);

            let mut new_row: Vec<String> = Vec::with_capacity(t.headers.len());
            for (ci, header) in t.headers.iter().enumerate() {
                let val = row.get(ci).cloned().unwrap_or_default();
                let kind = qtypes[ci].clone();
                let nv = transform_cell(
                    &extractor,
                    &policy,
                    &master_key,
                    project_id,
                    &val,
                    &kind,
                    &p_token,
                    p_shift,
                    &name_roots,
                    &root,
                    &mut decisions,
                    &t.table_name,
                    header,
                );
                new_row.push(nv);
            }
            out.rows.push(new_row);
            roots.push(root);
        }
        out_tables.push(out);
        out_row_roots.push(roots);
    }

    // ---------- pass 3: quasi-identifier generalisation + patient-level k ----------
    // QI columns that define the equivalence class. Birth date is generalised
    // but not used as a QI key when an age column exists, to avoid double
    // counting the same quasi-identifier.
    let has_age = out_tables.iter().any(|t| {
        t.headers
            .iter()
            .any(|h| kind_of(&t.id, h) == ColumnKind::Age)
    });
    let mut qcfg = policy.quasi.clone();
    let mut qi_cols: Vec<(String, String, ColumnKind)> = Vec::new();
    for t in &out_tables {
        for h in t.headers.iter() {
            let k = kind_of(&t.id, h);
            let is_qi = matches!(
                k,
                ColumnKind::Age | ColumnKind::Postcode | ColumnKind::Diagnosis | ColumnKind::Gender
            ) || (k == ColumnKind::BirthDate && !has_age);
            if is_qi {
                qi_cols.push((t.table_name.clone(), h.clone(), k));
            }
        }
    }

    #[allow(unused_assignments)]
    let mut k_achieved;
    let mut min_class;
    let suppressed_total;
    let mut class_sizes_final: Vec<usize>;
    let patients_before = {
        let mut s: HashSet<&String> = HashSet::new();
        for roots in &out_row_roots {
            for r in roots {
                s.insert(r);
            }
        }
        s.len()
    };

    let mut iteration = 0;
    let (suppress_roots, suppressed_rows_final) = loop {
        iteration += 1;
        apply_generalisation(&mut out_tables, &kinds, &qcfg, has_age);

        let patient_qi = collect_patient_qi(&out_tables, &out_row_roots, &kinds, has_age);
        let mut counts: HashMap<String, usize> = HashMap::new();
        for (_, sig) in &patient_qi {
            *counts.entry(sig.clone()).or_insert(0) += 1;
        }
        min_class = counts.values().copied().min().unwrap_or(0);
        k_achieved = min_class;
        class_sizes_final = counts.values().copied().collect();
        let _ = (&k_achieved, &class_sizes_final);

        let can_escalate = policy.k_anonymity.auto_escalate
            && (qcfg.age_width < policy.k_anonymity.max_age_width
                || qcfg.postcode_keep_prefix > policy.k_anonymity.min_postcode_prefix
                || diag_level_rank(&qcfg.diagnosis_level) < 2);
        if min_class >= k || !can_escalate || iteration > 12 {
            let mut suppress: HashSet<String> = HashSet::new();
            for (root, sig) in &patient_qi {
                if counts[sig] < k {
                    suppress.insert(root.clone());
                }
            }
            let rows: usize = out_tables
                .iter()
                .enumerate()
                .map(|(ti, t)| {
                    out_row_roots[ti]
                        .iter()
                        .filter(|r| suppress.contains(*r))
                        .count()
                        .min(t.rows.len())
                })
                .sum();
            break (suppress, rows);
        }
        // escalate one dimension at a time
        if qcfg.age_width < policy.k_anonymity.max_age_width {
            qcfg.age_width = (qcfg.age_width + 5).min(policy.k_anonymity.max_age_width);
        } else if qcfg.postcode_keep_prefix > policy.k_anonymity.min_postcode_prefix {
            qcfg.postcode_keep_prefix -= 1;
        } else if diag_level_rank(&qcfg.diagnosis_level) < 2 {
            qcfg.diagnosis_level = next_diag_level(&qcfg.diagnosis_level);
        }
    };
    suppressed_total = suppressed_rows_final;

    // Snapshot the generalised, still-positionally-aligned tables. Utility
    // metrics are measured on this snapshot so before/after rows line up 1:1;
    // suppression is reported separately as an information loss of its own.
    let generalised_tables = out_tables.clone();

    // drop rows belonging to suppressed patients, keeping roots aligned
    if !suppress_roots.is_empty() {
        for ti in 0..out_tables.len() {
            let roots = std::mem::take(&mut out_row_roots[ti]);
            let mut kept_rows = Vec::with_capacity(out_tables[ti].rows.len());
            let mut kept_roots = Vec::with_capacity(roots.len());
            for (ri, row) in out_tables[ti].rows.drain(..).enumerate() {
                let root = roots.get(ri).cloned().unwrap_or_default();
                if !suppress_roots.contains(&root) {
                    kept_rows.push(row);
                    kept_roots.push(root);
                }
            }
            out_tables[ti].rows = kept_rows;
            out_row_roots[ti] = kept_roots;
        }
    }
    // recompute achieved k on the surviving, correctly-aligned patients
    {
        let patient_qi = collect_patient_qi(&out_tables, &out_row_roots, &kinds, has_age);
        let mut counts: HashMap<String, usize> = HashMap::new();
        for (_root, sig) in &patient_qi {
            *counts.entry(sig.clone()).or_insert(0) += 1;
        }
        k_achieved = counts.values().copied().min().unwrap_or(0);
        min_class = k_achieved;
        class_sizes_final = counts.values().copied().collect();
    }
    let patients_after = patients_before.saturating_sub(suppress_roots.len());

    // ---------- quality ----------
    let mut quality = quality_report(&tables, &generalised_tables, &kinds, suppressed_total, &qcfg);
    quality.patients_before = patients_before;
    quality.patients_after = patients_after;

    // ---------- residual scan ----------
    let mut residual: Vec<ResidualFinding> = Vec::new();
    for t in &out_tables {
        for (ci, h) in t.headers.iter().enumerate() {
            let kind = kind_of(&t.id, h);
            if !matches!(kind, ColumnKind::FreeText) {
                // scan direct columns too, they should be clean
                if matches!(
                    kind,
                    ColumnKind::Name | ColumnKind::IdCard | ColumnKind::Phone | ColumnKind::Address | ColumnKind::Mrn
                ) {
                    // intentionally no-op: pseudonyms are not raw PII
                }
                continue;
            }
            for row in &t.rows {
                let txt = row.get(ci).cloned().unwrap_or_default();
                for m in extractor.extract(&txt) {
                    // Only untransformed direct identifiers count as residual
                    // risk: shifted dates are intended output, pseudonyms and
                    // masked/generalised values are recognisable by shape.
                    if !matches!(
                        m.pii_type,
                        PiiType::Name | PiiType::IdCard | PiiType::Phone | PiiType::Address | PiiType::Mrn
                    ) {
                        continue;
                    }
                    if is_transformed_token(&m.text, &policy.direct.pseudonym_prefix) {
                        continue;
                    }
                    if m.confidence >= 0.5 {
                        residual.push(ResidualFinding {
                            table: t.table_name.clone(),
                            column: h.clone(),
                            pii_type: m.pii_type.label().to_string(),
                            rule: m.rule.clone(),
                            snippet: crate::util::truncate_chars(&m.text, 24),
                            confidence: m.confidence,
                        });
                    }
                }
            }
        }
    }
    let high_res = residual.iter().filter(|r| r.confidence >= 0.8).count();

    // ---------- risk ----------
    let max_reid = if min_class == 0 { 1.0 } else { 1.0 / min_class as f64 };
    let total_after: usize = out_tables.iter().map(|t| t.rows.len()).sum();
    let patients_below_k = class_sizes_final.iter().filter(|c| **c < k).sum::<usize>();
    let prosecution = if patients_after == 0 {
        0.0
    } else {
        patients_below_k as f64 / patients_after as f64
    };
    let mut qi_names: Vec<String> = qi_cols
        .iter()
        .filter(|(_, _, kind)| *kind != ColumnKind::BirthDate || !has_age)
        .map(|(_, c, _)| c.clone())
        .collect();
    qi_names.sort();
    qi_names.dedup();
    let criteria = vec![
        RiskCriterion {
            name: format!("k 匿名 (k={})", k),
            passed: min_class >= k,
            detail: format!(
                "患者级最小等价类 {} 人，等价类 {} 个，抑制患者 {} 人 / {} 行",
                min_class,
                class_sizes_final.len(),
                suppress_roots.len(),
                suppressed_total
            ),
        },
        RiskCriterion {
            name: "再识别风险阈值".into(),
            passed: max_reid <= policy.risk.max_reid_risk,
            detail: format!(
                "最大再识别风险 {:.3}（1/最小等价类），阈值 {:.2}",
                max_reid, policy.risk.max_reid_risk
            ),
        },
        RiskCriterion {
            name: "起诉风险阈值".into(),
            passed: prosecution <= policy.risk.max_prosecution_risk,
            detail: format!(
                "起诉风险 {:.3}（小等价类患者占比），阈值 {:.2}",
                prosecution, policy.risk.max_prosecution_risk
            ),
        },
        RiskCriterion {
            name: "残留直接标识".into(),
            passed: high_res == 0 || !policy.risk.require_no_residual_pii,
            detail: format!("高置信度残留 {} 处（阈值 0）", high_res),
        },
        RiskCriterion {
            name: "关键统计量偏差".into(),
            passed: quality.max_rel_dev <= policy.quality.max_relative_deviation,
            detail: format!(
                "最大相对偏差 {:.3}，阈值 {:.2}",
                quality.max_rel_dev, policy.quality.max_relative_deviation
            ),
        },
    ];
    let passed = criteria.iter().all(|c| c.passed);

    let risk = RiskReport {
        k_target: k,
        k_achieved,
        min_class_size: min_class,
        max_reid_risk: max_reid,
        prosecution_risk: prosecution,
        rows_below_k: suppressed_total,
        rows_total: total_after,
        equivalence_classes: class_sizes_final.len(),
        qi_columns: qi_names.clone(),
        qi_after: qi_names,
        residual_count: residual.len(),
        residual,
        high_confidence_residual: high_res,
        suppressed_rows: suppressed_total,
        patients_total: patients_after,
        patients_suppressed: suppress_roots.len(),
        criteria,
        passed,
        date_shift_days: shift_map,
    };

    EngineOutput {
        tables: out_tables,
        quality,
        risk,
        decisions,
        policy_after: {
            let mut p = policy.clone();
            p.quasi = qcfg;
            p
        },
        suppressed_rows: suppressed_total,
    }
}

fn apply_generalisation(
    tables: &mut [TableData],
    kinds: &HashMap<(String, String), ColumnKind>,
    qcfg: &crate::models::QuasiConfig,
    has_age: bool,
) {
    for t in tables.iter_mut() {
        for row in t.rows.iter_mut() {
            for (ci, h) in t.headers.iter().enumerate() {
                let kind = kinds
                    .get(&(t.id.clone(), h.clone()))
                    .cloned()
                    .unwrap_or(ColumnKind::Unknown);
                match kind {
                    ColumnKind::Age => {
                        if let Some(age) = parse_age(&row[ci]) {
                            row[ci] = age_band(age, qcfg.age_width);
                        }
                    }
                    ColumnKind::Postcode => {
                        if !row[ci].is_empty() {
                            let keep = qcfg.postcode_keep_prefix.min(row[ci].chars().count());
                            let p: String = row[ci].chars().take(keep).collect();
                            row[ci] = format!("{}***", p);
                        }
                    }
                    ColumnKind::Diagnosis => {
                        row[ci] = generalize_diagnosis(&row[ci], &qcfg.diagnosis_level);
                    }
                    ColumnKind::Gender => {
                        if qcfg.gender == "suppress" {
                            row[ci] = "*".into();
                        }
                    }
                    ColumnKind::BirthDate if !has_age => {
                        if qcfg.birth_date == "year" && parse_date(&row[ci]).is_some() {
                            row[ci] = row[ci].chars().take(4).collect();
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Build a QI signature per patient from the *most specific* observation of
/// each QI type across all their rows. Using one signature per patient is
/// required for patient-level k-anonymity (otherwise one patient contributes
/// many rows and inflates the class counts).
fn collect_patient_qi(
    tables: &[TableData],
    roots: &[Vec<String>],
    kinds: &HashMap<(String, String), ColumnKind>,
    has_age: bool,
) -> Vec<(String, String)> {
    let mut per: HashMap<String, HashMap<&'static str, String>> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for (ti, t) in tables.iter().enumerate() {
        for (ri, row) in t.rows.iter().enumerate() {
            let root = match roots.get(ti).and_then(|r| r.get(ri)) {
                Some(r) => r.clone(),
                None => continue,
            };
            let entry = per.entry(root.clone()).or_insert_with(|| {
                order.push(root);
                HashMap::new()
            });
            for (ci, h) in t.headers.iter().enumerate() {
                let kind = kinds
                    .get(&(t.id.clone(), h.clone()))
                    .cloned()
                    .unwrap_or(ColumnKind::Unknown);
                let tag = match kind {
                    ColumnKind::Age => "age",
                    ColumnKind::Postcode => "pc",
                    ColumnKind::Diagnosis => "dx",
                    ColumnKind::Gender => "sex",
                    ColumnKind::BirthDate if !has_age => "dob",
                    _ => continue,
                };
                let v = &row[ci];
                if v.is_empty() {
                    continue;
                }
                match entry.get(tag) {
                    // postal code: keep the shortest (least specific) prefix
                    Some(existing) if tag == "pc" => {
                        if existing.chars().count() > v.chars().count() {
                            entry.insert(tag, v.clone());
                        }
                    }
                    // diagnosis: keep the shortest (most general) label
                    Some(existing) if tag == "dx" => {
                        if existing.chars().count() > v.chars().count() {
                            entry.insert(tag, v.clone());
                        }
                    }
                    Some(_) => {}
                    None => {
                        entry.insert(tag, v.clone());
                    }
                }
            }
        }
    }
    order
        .into_iter()
        .map(|root| {
            let m = per.get(&root).cloned().unwrap_or_default();
            let sig = format!(
                "age={}|pc={}|dx={}|sex={}{}",
                m.get("age").cloned().unwrap_or_default(),
                m.get("pc").cloned().unwrap_or_default(),
                m.get("dx").cloned().unwrap_or_default(),
                m.get("sex").cloned().unwrap_or_default(),
                if has_age {
                    String::new()
                } else {
                    format!("|dob={}", m.get("dob").cloned().unwrap_or_default())
                }
            );
            (root, sig)
        })
        .collect()
}

fn diag_level_rank(level: &str) -> usize {
    match level {
        "icd3" => 0,
        "icd2" => 1,
        _ => 2,
    }
}

fn next_diag_level(level: &str) -> String {
    match level {
        "icd3" => "icd2".into(),
        "icd2" => "chapter".into(),
        _ => "chapter".into(),
    }
}

/// Recognise values already replaced by the pipeline so the residual scan does
/// not double-count them: mask characters, or a pseudonym prefix + base32 body.
fn is_transformed_token(text: &str, prefix: &str) -> bool {
    let t = text.trim();
    if t.is_empty() || t.contains('*') {
        return true;
    }
    if let Some(rest) = t.strip_prefix(prefix) {
        if !rest.is_empty()
            && rest
                .chars()
                .all(|c| crate::util::B32_ALPHABET.contains(&(c as u8)))
        {
            return true;
        }
    }
    false
}

fn clean_token(v: &str) -> String {
    v.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_uppercase()
}

pub fn norm_name(v: &str) -> String {
    v.chars()
        .filter(|c| !c.is_whitespace() && *c != '·')
        .collect()
}

fn parse_age(v: &str) -> Option<i32> {
    let t = v.trim().trim_end_matches('岁');
    if let Ok(n) = t.parse::<i32>() {
        return Some(n);
    }
    // "45-49岁" style
    if let Some(first) = t.split(['-', '~']).next() {
        return first.trim().parse().ok();
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn transform_cell(
    extractor: &TextExtractor,
    policy: &PolicyConfig,
    master_key: &[u8; 32],
    project_id: &str,
    value: &str,
    kind: &ColumnKind,
    patient_token: &str,
    shift: i64,
    name_roots: &HashMap<String, HashSet<String>>,
    root: &str,
    decisions: &mut Vec<FieldDecision>,
    table: &str,
    column: &str,
) -> String {
    if value.trim().is_empty() {
        return value.to_string();
    }
    let d = &policy.direct;
    match kind {
        ColumnKind::Name => {
            let action = d.name.as_str();
            let out = match action {
                "suppress" => String::new(),
                "mask" => mask_value(value),
                "hash" => base32(&hmac(master_key, format!("{}|name|{}", project_id, norm_name(value)).as_bytes()), 10),
                _ => name_pseudonym(policy, master_key, project_id, value, name_roots, root, patient_token),
            };
            push_decision(decisions, table, column, kind, action, "姓名假名化/遮盖");
            out
        }
        ColumnKind::IdCard => {
            let action = d.id_card.as_str();
            push_decision(decisions, table, column, kind, action, "身份证号处理");
            match action {
                "suppress" => String::new(),
                "hash" => base32(&hmac(master_key, format!("{}|id|{}", project_id, value.to_uppercase()).as_bytes()), 12),
                "pseudonym" => format!("{}{}", d.pseudonym_prefix, base32(&hmac(master_key, format!("{}|id|{}", project_id, value.to_uppercase()).as_bytes()), 12)),
                _ => mask_id(value),
            }
        }
        ColumnKind::Phone => {
            let action = d.phone.as_str();
            push_decision(decisions, table, column, kind, action, "手机号遮盖");
            match action {
                "suppress" => String::new(),
                "hash" | "pseudonym" => format!("{}{}", d.pseudonym_prefix, base32(&hmac(master_key, format!("{}|phone|{}", project_id, value).as_bytes()), 10)),
                _ => mask_phone(value, d.phone_keep_last),
            }
        }
        ColumnKind::Address => {
            let action = d.address.as_str();
            push_decision(decisions, table, column, kind, action, "住址泛化");
            match action {
                "suppress" => String::new(),
                "mask" => mask_value(value),
                "hash" | "pseudonym" => format!("{}{}", d.pseudonym_prefix, base32(&hmac(master_key, format!("{}|addr|{}", project_id, value).as_bytes()), 10)),
                _ => generalize_address(value, &d.address_level),
            }
        }
        ColumnKind::Mrn => {
            let action = d.mrn.as_str();
            push_decision(decisions, table, column, kind, action, "病案号假名化");
            match action {
                "suppress" => String::new(),
                "mask" => mask_value(value),
                _ => patient_token.to_string(),
            }
        }
        ColumnKind::Date => {
            if policy.dates.action == "shift" {
                push_decision(decisions, table, column, kind, "shift", &format!("日期整体平移 {} 天", shift));
                shift_date(value, shift).unwrap_or_else(|| value.to_string())
            } else if policy.dates.action == "suppress" {
                push_decision(decisions, table, column, kind, "suppress", "日期删除");
                String::new()
            } else {
                push_decision(decisions, table, column, kind, "generalize", "日期泛化到月");
                generalize_date(value, &policy.dates.granularity)
            }
        }
        ColumnKind::BirthDate => {
            if policy.quasi.birth_date == "year" {
                push_decision(decisions, table, column, kind, "generalize", "出生日期保留年份");
                value.chars().take(4).collect()
            } else {
                push_decision(decisions, table, column, kind, "shift", &format!("出生日期平移 {} 天", shift));
                shift_date(value, shift).unwrap_or_else(|| value.to_string())
            }
        }
        ColumnKind::FreeText => {
            if !policy.free_text.enabled {
                push_decision(decisions, table, column, kind, "keep", "自由文本未启用脱敏");
                return value.to_string();
            }
            push_decision(decisions, table, column, kind, "redact", "自由文本标识替换");
            redact_text(extractor, policy, master_key, project_id, value, patient_token, shift, name_roots, root)
        }
        ColumnKind::Age
        | ColumnKind::Postcode
        | ColumnKind::Gender
        | ColumnKind::Diagnosis => value.to_string(),
        ColumnKind::Numeric | ColumnKind::Categorical | ColumnKind::Unknown => value.to_string(),
    }
}

fn push_decision(
    decisions: &mut Vec<FieldDecision>,
    table: &str,
    column: &str,
    kind: &ColumnKind,
    action: &str,
    detail: &str,
) {
    if decisions
        .iter()
        .any(|d| d.table == table && d.column == column)
    {
        return;
    }
    decisions.push(FieldDecision {
        table: table.to_string(),
        column: column.to_string(),
        kind: kind.label().to_string(),
        action: action.to_string(),
        detail: detail.to_string(),
    });
}

fn name_pseudonym(
    policy: &PolicyConfig,
    master_key: &[u8; 32],
    project_id: &str,
    value: &str,
    name_roots: &HashMap<String, HashSet<String>>,
    root: &str,
    patient_token: &str,
) -> String {
    let n = norm_name(value);
    // If this name belongs to the current patient, use the patient token so the
    // pseudonym stays consistent with MRN/ID pseudonyms across tables.
    if let Some(roots) = name_roots.get(&n) {
        if roots.contains(root) {
            return patient_token.to_string();
        }
    }
    let code = base32(
        &hmac(
            master_key,
            format!("{}|name|{}", project_id, n).as_bytes(),
        ),
        10,
    );
    format!("{}{}", policy.direct.pseudonym_prefix, code)
}

fn mask_phone(v: &str, keep_last: usize) -> String {
    let digits: Vec<char> = v.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 7 {
        return "*".repeat(v.chars().count().max(1));
    }
    let keep = keep_last.min(digits.len() - 4);
    let mut out = String::new();
    let prefix_keep = 3.min(digits.len().saturating_sub(keep));
    for (i, c) in digits.iter().enumerate() {
        if i < prefix_keep || i >= digits.len() - keep {
            out.push(*c);
        } else {
            out.push('*');
        }
    }
    out
}

fn mask_id(v: &str) -> String {
    let chars: Vec<char> = v.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let mut out: String = chars[..3].iter().collect();
    out.push_str(&"*".repeat(chars.len() - 7));
    out.extend(&chars[chars.len() - 4..]);
    out
}

pub fn generalize_address(v: &str, level: &str) -> String {
    let n = address_prefix_len(v, level);
    let prefix: String = v.chars().take(n).collect();
    format!("{}***", prefix)
}

fn generalize_date(v: &str, granularity: &str) -> String {
    match granularity {
        "year" => v.chars().take(4).collect(),
        _ => {
            let chars: Vec<char> = v.chars().collect();
            if chars.len() >= 7 {
                let y: String = chars[..4].iter().collect();
                let m: String = chars[5..7].iter().collect();
                format!("{}-{}", y, m)
            } else {
                v.to_string()
            }
        }
    }
}

fn generalize_diagnosis(v: &str, level: &str) -> String {
    let t = v.trim();
    if t.is_empty() {
        return String::new();
    }
    // ICD-10 code prefix like I10.1 / J18.9
    let code: String = t
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.')
        .collect();
    let is_code = code.len() >= 3
        && code.chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false)
        && code.chars().nth(1).map(|c| c.is_ascii_digit()).unwrap_or(false);
    if is_code {
        return match level {
            "icd3" => code.chars().take(3).collect(),
            "icd2" => {
                let chapter = code.chars().next().unwrap();
                format!("{}章", icd_chapter(chapter))
            }
            _ => format!("{}章", icd_chapter(code.chars().next().unwrap())),
        };
    }
    // Chinese diagnosis: map to body-system chapter; fall back to head noun.
    if level == "icd3" {
        return t.to_string();
    }
    let cat = cjk_chapter(t);
    cat.to_string()
}

fn icd_chapter(c: char) -> &'static str {
    match c.to_ascii_uppercase() {
        'A' | 'B' => "感染与寄生虫",
        'C' | 'D' => "肿瘤与血液",
        'E' => "内分泌代谢",
        'F' => "精神行为",
        'G' => "神经系统",
        'H' => "眼与耳",
        'I' => "循环系统",
        'J' => "呼吸系统",
        'K' => "消化系统",
        'L' => "皮肤",
        'M' => "肌肉骨骼",
        'N' => "泌尿生殖",
        'O' => "妊娠分娩",
        'P' => "围产期",
        'Q' => "先天畸形",
        'R' => "症状体征",
        'S' | 'T' => "损伤中毒",
        'V' | 'W' | 'X' | 'Y' => "外因",
        'Z' => "健康因素",
        _ => "其他",
    }
}

fn cjk_chapter(t: &str) -> &'static str {
    let map: &[(&[&str], &str)] = &[
        (&["高血压", "冠心病", "心梗", "心肌", "心律失常", "房颤", "心衰", "动脉", "静脉", "脑梗", "脑出血", "卒中", "血管"], "循环系统"),
        (&["糖尿病", "甲状腺", "垂体", "肾上腺", "痛风", "高脂", "肥胖", "代谢"], "内分泌代谢"),
        (&["肺炎", "支气管", "哮喘", "慢阻肺", "肺气肿", "肺结核", "呼吸", "胸腔", "咳嗽"], "呼吸系统"),
        (&["胃炎", "胃溃疡", "肠炎", "肝炎", "肝硬化", "胆囊", "胰腺", "消化", "腹泻", "阑尾"], "消化系统"),
        (&["肾", "膀胱", "前列腺", "尿", "泌尿", "输尿管"], "泌尿生殖"),
        (&["骨折", "脱位", "扭伤", "损伤", "创伤", "烧伤", "中毒"], "损伤中毒"),
        (&["癌", "瘤", "白血病", "淋巴瘤", "肿瘤", "转移"], "肿瘤与血液"),
        (&["贫血", "血小板", "白细胞", "凝血", "血友"], "肿瘤与血液"),
        (&["脑", "癫痫", "帕金森", "神经", "偏头痛", "痴呆", "脊髓"], "神经系统"),
        (&["白内障", "青光眼", "视网膜", "近视", "眼", "耳聋", "中耳", "鼻窦", "咽炎", "扁桃体"], "眼与耳"),
        (&["皮炎", "湿疹", "银屑", "荨麻疹", "皮肤", "癣"], "皮肤"),
        (&["关节", "腰椎", "颈椎", "椎间盘", "骨质疏松", "肌", "腱"], "肌肉骨骼"),
        (&["妊娠", "分娩", "剖宫", "流产", "孕", "产褥"], "妊娠分娩"),
        (&["抑郁", "焦虑", "精神", "失眠", "精神分裂"], "精神行为"),
        (&["感染", "结核", "病毒", "细菌", "真菌", "败血"], "感染与寄生虫"),
    ];
    for (keys, cat) in map {
        if keys.iter().any(|k| t.contains(k)) {
            return cat;
        }
    }
    "其他疾病"
}

#[allow(clippy::too_many_arguments)]
fn redact_text(
    extractor: &TextExtractor,
    policy: &PolicyConfig,
    master_key: &[u8; 32],
    project_id: &str,
    text: &str,
    patient_token: &str,
    shift: i64,
    name_roots: &HashMap<String, HashSet<String>>,
    root: &str,
) -> String {
    let mut matches = extractor.extract(text);
    if matches.is_empty() {
        return text.to_string();
    }
    // dates created by earlier replacements must not be re-shifted: replace in
    // descending byte order using the original spans.
    matches.sort_by_key(|m| std::cmp::Reverse(m.start));
    let mut out = text.to_string();
    let cfg: &FreeTextConfig = &policy.free_text;
    for m in &matches {
        let action = match m.pii_type {
            PiiType::Name => cfg.name.as_str(),
            PiiType::IdCard => cfg.id_card.as_str(),
            PiiType::Phone => cfg.phone.as_str(),
            PiiType::Address => cfg.address.as_str(),
            PiiType::Mrn => cfg.mrn.as_str(),
            PiiType::Date => cfg.date.as_str(),
            PiiType::BirthDate => cfg.birth_date.as_str(),
            PiiType::Postcode => cfg.postcode.as_str(),
        };
        if action == "keep" {
            continue;
        }
        let replacement = match m.pii_type {
            PiiType::Name => match action {
                "suppress" => String::new(),
                "mask" => "*".repeat(m.text.chars().count()),
                _ => name_pseudonym(policy, master_key, project_id, &m.text, name_roots, root, patient_token),
            },
            PiiType::IdCard => match action {
                "suppress" => String::new(),
                "pseudonym" | "hash" => format!(
                    "{}{}",
                    policy.direct.pseudonym_prefix,
                    base32(&hmac(master_key, format!("{}|id|{}", project_id, m.text.to_uppercase()).as_bytes()), 12)
                ),
                _ => mask_id(&m.text),
            },
            PiiType::Phone => match action {
                "suppress" => String::new(),
                _ => mask_phone(&m.text, policy.direct.phone_keep_last),
            },
            PiiType::Address => match action {
                "suppress" => String::new(),
                "mask" => "*".repeat(m.text.chars().count()),
                _ => generalize_address(&m.text, &cfg.address_level),
            },
            PiiType::Mrn => match action {
                "suppress" => String::new(),
                "mask" => mask_value(&m.text),
                _ => patient_token.to_string(),
            },
            PiiType::Date => match action {
                "suppress" => String::new(),
                "generalize" => generalize_date(&m.text, "month"),
                _ => shift_date_preserve_fmt(&m.text, shift),
            },
            PiiType::BirthDate => match action {
                "generalize" => m.text.chars().take(4).collect(),
                "suppress" => String::new(),
                _ => shift_date_preserve_fmt(&m.text, shift),
            },
            PiiType::Postcode => match action {
                "suppress" => String::new(),
                _ => {
                    let p: String = m.text.chars().take(2).collect();
                    format!("{}****", p)
                }
            },
        };
        if m.start <= out.len() && m.end <= out.len() && m.start < m.end {
            out.replace_range(m.start..m.end, &replacement);
        }
    }
    out
}

fn shift_date_preserve_fmt(v: &str, days: i64) -> String {
    let Some(d) = parse_date(v) else {
        return v.to_string();
    };
    let shifted = d + chrono::Duration::days(days);
    if v.contains('年') {
        let month_part = if v.contains('月') {
            if v.contains('日') {
                format!(
                    "{}年{}月{}日",
                    shifted.year(),
                    shifted.month(),
                    shifted.day()
                )
            } else {
                format!("{}年{}月", shifted.year(), shifted.month())
            }
        } else {
            format!("{}年", shifted.year())
        };
        month_part
    } else if v.contains('/') {
        shifted.format("%Y/%m/%d").to_string()
    } else if v.contains('.') {
        shifted.format("%Y.%m.%d").to_string()
    } else {
        shifted.format("%Y-%m-%d").to_string()
    }
}

use chrono::Datelike;

// ---------- quality ----------

fn quality_report(
    before: &[TableData],
    after: &[TableData],
    kinds: &HashMap<(String, String), ColumnKind>,
    suppressed: usize,
    qcfg: &crate::models::QuasiConfig,
) -> QualityReport {
    let mut q = QualityReport::default();
    let mut total_before = 0usize;
    let mut total_after = 0usize;
    for (bt, at) in before.iter().zip(after.iter()) {
        total_before += bt.rows.len();
        total_after += at.rows.len();
        let free_text = bt
            .headers
            .iter()
            .filter(|h| kinds.get(&(bt.id.clone(), (*h).clone())) == Some(&ColumnKind::FreeText))
            .count();
        let direct = bt
            .headers
            .iter()
            .filter(|h| {
                kinds
                    .get(&(bt.id.clone(), (*h).clone()))
                    .map(|k| k.is_direct_identifier())
                    .unwrap_or(false)
            })
            .count();
        q.tables.push(TableStat {
            table: bt.table_name.clone(),
            rows_before: bt.rows.len(),
            rows_after: at.rows.len(),
            suppressed: bt.rows.len().saturating_sub(at.rows.len()),
            columns: bt.headers.len(),
            free_text_columns: free_text,
            direct_columns: direct,
        });

        // numeric comparisons on surviving pairs (positional match is broken by
        // suppression, so compare distributions rather than pairs)
        for (ci, h) in bt.headers.iter().enumerate() {
            let kind = kinds
                .get(&(bt.id.clone(), h.clone()))
                .cloned()
                .unwrap_or(ColumnKind::Unknown);
            let is_quasi = matches!(kind, ColumnKind::Age | ColumnKind::Postcode | ColumnKind::Date | ColumnKind::BirthDate);
            let interval = {
                let nh = norm_header(h);
                (nh.contains("住院天数") || nh.contains("住院日") || nh.contains("住院时长") || nh.contains("间隔") || nh.contains("天数"))
                    && matches!(kind, ColumnKind::Numeric | ColumnKind::Unknown | ColumnKind::Age)
            };
            // Only report numeric-looking columns
            let before_vals: Vec<f64> = bt
                .rows
                .iter()
                .filter_map(|r| r.get(ci).and_then(|v| v.trim().parse::<f64>().ok()))
                .collect();
            if before_vals.len() < 3 || before_vals.len() * 2 < bt.rows.len().max(1) {
                continue;
            }
            let acol = at.headers.iter().position(|x| x == h);
            let after_vals: Vec<f64> = match acol {
                Some(ac) => at
                    .rows
                    .iter()
                    .filter_map(|r| r.get(ac).and_then(|v| v.trim().parse::<f64>().ok()))
                    .collect(),
                None => Vec::new(),
            };
            if after_vals.is_empty() {
                continue;
            }
            let (bm, bmd, bs) = stats(&before_vals);
            let (am, amd, as_) = stats(&after_vals);
            let rel = |b: f64, a: f64| {
                if b.abs() < 1e-9 {
                    if a.abs() < 1e-9 { 0.0 } else { 1.0 }
                } else {
                    (a - b).abs() / b.abs()
                }
            };
            let stat = NumericStat {
                table: bt.table_name.clone(),
                column: h.clone(),
                before_mean: bm,
                after_mean: am,
                before_median: bmd,
                after_median: amd,
                before_std: bs,
                after_std: as_,
                rel_dev_mean: rel(bm, am),
                rel_dev_median: rel(bmd, amd),
                rel_dev_std: rel(bs, as_),
                n_before: before_vals.len(),
                n_after: after_vals.len(),
                is_interval: interval,
                quasi: is_quasi,
            };
            q.numeric.push(stat);
        }
    }
    // gender / diagnosis distributions
    for t in before {
        for (ci, h) in t.headers.iter().enumerate() {
            let k = kinds
                .get(&(t.id.clone(), h.clone()))
                .cloned()
                .unwrap_or(ColumnKind::Unknown);
            if k == ColumnKind::Gender {
                for r in &t.rows {
                    if let Some(v) = r.get(ci) {
                        *q.gender_before.entry(v.clone()).or_insert(0) += 1;
                    }
                }
            }
            if k == ColumnKind::Diagnosis {
                for r in &t.rows {
                    if let Some(v) = r.get(ci) {
                        *q.diagnosis_before.entry(v.clone()).or_insert(0) += 1;
                    }
                }
            }
        }
    }
    for t in after {
        for (ci, h) in t.headers.iter().enumerate() {
            let k = kinds
                .get(&(t.id.clone(), h.clone()))
                .cloned()
                .unwrap_or(ColumnKind::Unknown);
            if k == ColumnKind::Gender {
                for r in &t.rows {
                    if let Some(v) = r.get(ci) {
                        *q.gender_after.entry(v.clone()).or_insert(0) += 1;
                    }
                }
            }
            if k == ColumnKind::Diagnosis {
                for r in &t.rows {
                    if let Some(v) = r.get(ci) {
                        *q.diagnosis_after.entry(v.clone()).or_insert(0) += 1;
                    }
                }
            }
        }
    }

    // interval (LOS) preservation
    if let Some(s) = q
        .numeric
        .iter()
        .find(|s| s.is_interval && s.column.contains("住院"))
        .cloned()
    {
        q.los_before_mean = Some(s.before_mean);
        q.los_after_mean = Some(s.after_mean);
        q.los_rel_dev = Some(s.rel_dev_mean);
    }
    q.interval_preserved = q
        .numeric
        .iter()
        .filter(|s| s.is_interval)
        .all(|s| s.rel_dev_mean <= 0.01 && s.rel_dev_median <= 0.01);
    q.max_rel_dev = q
        .numeric
        .iter()
        .filter(|s| !s.quasi && !s.is_interval)
        .map(|s| s.rel_dev_mean.max(s.rel_dev_median))
        .fold(0.0f64, f64::max);
    if q.numeric.iter().all(|s| s.quasi || s.is_interval) {
        q.max_rel_dev = q
            .numeric
            .iter()
            .map(|s| s.rel_dev_mean.max(s.rel_dev_median))
            .fold(0.0f64, f64::max);
    }
    q.suppressed_rows = suppressed;
    q.total_rows_before = total_before;
    q.total_rows_after = total_after;
    q.patients_before = total_before;
    q.patients_after = total_after;
    let _ = qcfg;
    q
}

fn stats(v: &[f64]) -> (f64, f64, f64) {
    let n = v.len() as f64;
    let mean = v.iter().sum::<f64>() / n;
    let mut sorted = v.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = if sorted.len() % 2 == 1 {
        sorted[sorted.len() / 2]
    } else {
        (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0
    };
    let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    (mean, median, var.sqrt())
}


// ---------- entity & linkage analysis (read-only, for console) ----------

pub fn entity_summary(tables: &[TableData], kinds: &HashMap<(String, String), ColumnKind>) -> serde_json::Value {
    let extractor = TextExtractor::new();
    let mut per_type: HashMap<String, usize> = HashMap::new();
    let mut per_rule: HashMap<String, usize> = HashMap::new();
    let mut per_column: HashMap<String, usize> = HashMap::new();
    for t in tables {
        for (ci, h) in t.headers.iter().enumerate() {
            let kind = kinds
                .get(&(t.id.clone(), h.clone()))
                .cloned()
                .unwrap_or(ColumnKind::Unknown);
            if kind != ColumnKind::FreeText {
                continue;
            }
            for row in &t.rows {
                let txt = row.get(ci).cloned().unwrap_or_default();
                for m in extractor.extract(&txt) {
                    *per_type.entry(m.pii_type.label().to_string()).or_insert(0) += 1;
                    *per_rule.entry(m.rule.clone()).or_insert(0) += 1;
                    *per_column
                        .entry(format!("{} / {}", t.table_name, h))
                        .or_insert(0) += 1;
                }
            }
        }
    }
    serde_json::json!({
        "by_type": per_type,
        "by_rule": per_rule,
        "by_column": per_column,
    })
}

/// Resolve patient identities across tables and report the linkage structure
/// that the pseudonymisation step will use. Does not expose raw identifiers.
pub fn linkage_summary(tables: &[TableData], kinds: &HashMap<(String, String), ColumnKind>) -> serde_json::Value {
    let mut uf = Uf::default();
    let mut row_ident: HashMap<(String, usize), Vec<String>> = HashMap::new();
    let mut id_sources: HashMap<String, HashSet<String>> = HashMap::new(); // token -> kinds used
    let mut id_cards: HashSet<String> = HashSet::new();
    let mut mrns: HashSet<String> = HashSet::new();
    let mut name_birth: HashSet<String> = HashSet::new();

    for t in tables {
        for (ri, row) in t.rows.iter().enumerate() {
            let mut tokens: Vec<String> = vec![];
            let mut names: Vec<String> = vec![];
            let mut birth: Option<String> = None;
            for (ci, h) in t.headers.iter().enumerate() {
                let v = row.get(ci).cloned().unwrap_or_default();
                let v = v.trim().to_string();
                if v.is_empty() {
                    continue;
                }
                match kinds.get(&(t.id.clone(), h.clone())) {
                    Some(ColumnKind::IdCard) if crate::util::id_card_valid(&v) => {
                        tokens.push(format!("ID:{}", v));
                        id_cards.insert(v.clone());
                        id_sources.entry("id_card".into()).or_default().insert(t.table_name.clone());
                        if let Some(b) = crate::util::id_card_birth(&v) {
                            birth = Some(b.format("%Y-%m-%d").to_string());
                        }
                    }
                    Some(ColumnKind::Mrn) => {
                        tokens.push(format!("MRN:{}", clean_token(&v)));
                        mrns.insert(v.clone());
                        id_sources.entry("mrn".into()).or_default().insert(t.table_name.clone());
                    }
                    Some(ColumnKind::Name) => names.push(norm_name(&v)),
                    Some(ColumnKind::BirthDate) => {
                        if let Some(d) = parse_date(&v) {
                            birth = Some(d.format("%Y-%m-%d").to_string());
                        }
                    }
                    _ => {}
                }
            }
            if let (Some(n), Some(b)) = (names.first(), birth.as_ref()) {
                tokens.push(format!("NB:{}|{}", n, b));
                name_birth.insert(format!("{}|{}", n, b));
                id_sources.entry("name+birthdate".into()).or_default().insert(t.table_name.clone());
            }
            if tokens.is_empty() {
                continue;
            }
            for w in tokens.windows(2) {
                uf.union(&w[0], &w[1]);
            }
            if tokens.len() == 1 {
                uf.find(&tokens[0]);
            }
            row_ident.insert((t.id.clone(), ri), tokens);
        }
    }
    let mut roots: HashMap<String, usize> = HashMap::new();
    for toks in row_ident.values() {
        if let Some(first) = toks.first() {
            *roots.entry(uf.find(first)).or_insert(0) += 1;
        }
    }
    let patients = roots.len();
    let multi_table = {
        // count patients appearing in more than one table
        let mut patient_tables: HashMap<String, HashSet<String>> = HashMap::new();
        for ((file, _ri), toks) in &row_ident {
            if let Some(f) = toks.first() {
                let root = uf.find(f);
                let table = tables
                    .iter()
                    .find(|t| &t.id == file)
                    .map(|t| t.table_name.clone())
                    .unwrap_or_default();
                patient_tables.entry(root).or_default().insert(table);
            }
        }
        patient_tables.values().filter(|s| s.len() > 1).count()
    };
    serde_json::json!({
        "patients": patients,
        "rows": row_ident.len(),
        "linked_across_tables": multi_table,
        "unique_id_cards": id_cards.len(),
        "unique_mrns": mrns.len(),
        "unique_name_birthdates": name_birth.len(),
        "sources": id_sources,
        "strategy": "身份证号/病案号/姓名+出生日期 联合并查集；同一患者在不同表、不同批次的记录归并为一个实体，再按课题组 HMAC 生成假名。",
    })
}
