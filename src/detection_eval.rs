//! Detection evaluation against ground-truth spans.

use crate::detect::TextExtractor;
use crate::models::PiiType;
use crate::synth::TruthSpan;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TypeMetrics {
    pub pii_type: String,
    pub truth: usize,
    pub detected: usize,
    pub tp: usize,
    pub fp: usize,
    pub fn_: usize,
    pub recall: f64,
    pub precision: f64,
    pub fpr: f64, // false discoveries / all reported spans
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct UnmatchedExample {
    pub pii_type: String,
    pub column: String,
    pub text: String,
    pub reason: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DetectionReport {
    pub per_type: Vec<TypeMetrics>,
    pub totals: TypeMetrics,
    pub by_rule: BTreeMap<String, usize>,
    pub unmatched: Vec<UnmatchedExample>,
    pub false_positives: Vec<UnmatchedExample>,
    pub scanned_texts: usize,
    pub truth_spans: usize,
    pub notes: Vec<String>,
}

pub struct TruthInput<'a> {
    pub truth: &'a [TruthSpan],
    pub texts: Vec<(String, usize, String, String)>, // table, row, column, text
}

pub fn evaluate(input: TruthInput) -> DetectionReport {
    let extractor = TextExtractor::new();
    let mut by_type_truth: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_type_tp: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_type_det: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_type_fp: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_rule: BTreeMap<String, usize> = BTreeMap::new();
    let mut unmatched: Vec<UnmatchedExample> = Vec::new();
    let mut false_positives: Vec<UnmatchedExample> = Vec::new();
    let mut total_det = 0usize;
    let mut total_truth = 0usize;
    let mut total_tp = 0usize;

    for t in input.truth {
        // Only text-bearing identifiers are part of the free-text evaluation;
        // structured columns are covered by the column-detection evaluation.
        *by_type_truth.entry(t.pii_type.clone()).or_insert(0) += 1;
        total_truth += 1;
        let _ = t;
    }

    // map (table,row,column) -> truth spans
    let mut keyed: BTreeMap<(String, usize, String), Vec<&TruthSpan>> = BTreeMap::new();
    for t in input.truth {
        keyed
            .entry((t.table.clone(), t.row, t.column.clone()))
            .or_default()
            .push(t);
    }

    let mut scanned = 0usize;
    for (table, row, column, text) in &input.texts {
        scanned += 1;
        let matches = extractor.extract(text);
        let truth = keyed
            .get(&(table.clone(), *row, column.clone()))
            .cloned()
            .unwrap_or_default();

        // greedily pair matches with truth spans by overlap
        let mut used_truth: HashSet<usize> = HashSet::new();
        let mut used_match: HashSet<usize> = HashSet::new();
        for (mi, m) in matches.iter().enumerate() {
            *by_rule.entry(m.rule.clone()).or_insert(0) += 1;
            *by_type_det.entry(m.pii_type.label().to_string()).or_insert(0) += 1;
            total_det += 1;
            let mut best: Option<(usize, usize)> = None;
            for (ti, t) in truth.iter().enumerate() {
                if used_truth.contains(&ti) {
                    continue;
                }
                if t.pii_type != m.pii_type.label() {
                    continue;
                }
                let ov = overlap(t.start, t.end, m.start, m.end);
                if ov > 0 {
                    match best {
                        Some((_, bo)) if ov <= bo => {}
                        _ => best = Some((ti, ov)),
                    }
                }
            }
            if let Some((ti, _)) = best {
                used_truth.insert(ti);
                used_match.insert(mi);
                *by_type_tp.entry(m.pii_type.label().to_string()).or_insert(0) += 1;
                total_tp += 1;
            } else {
                *by_type_fp.entry(m.pii_type.label().to_string()).or_insert(0) += 1;
                if false_positives.len() < 40 {
                    false_positives.push(UnmatchedExample {
                        pii_type: m.pii_type.label().into(),
                        column: format!("{} / {}", table, column),
                        text: format!("{}|{}", m.rule, m.text),
                        reason: "误报".into(),
                    });
                }
            }
        }
        // unmatched truth
        for (ti, t) in truth.iter().enumerate() {
            if !used_truth.contains(&ti) {
                unmatched.push(UnmatchedExample {
                    pii_type: t.pii_type.clone(),
                    column: column.clone(),
                    text: t.text.clone(),
                    reason: "未被识别".into(),
                });
            }
        }
    }

    let mut per_type = Vec::new();
    let mut all_types: Vec<String> = vec![];
    for ty in PiiType::all() {
        all_types.push(ty.label().to_string());
    }
    for ty in all_types {
        let truth_n = by_type_truth.get(&ty).copied().unwrap_or(0);
        let det = by_type_det.get(&ty).copied().unwrap_or(0);
        let tp = by_type_tp.get(&ty).copied().unwrap_or(0);
        let fp = by_type_fp.get(&ty).copied().unwrap_or(0);
        if truth_n == 0 && det == 0 {
            continue;
        }
        let fn_ = truth_n.saturating_sub(tp);
        let recall = if truth_n == 0 { 1.0 } else { tp as f64 / truth_n as f64 };
        let precision = if det == 0 { 0.0 } else { tp as f64 / det as f64 };
        let fpr = if det == 0 { 0.0 } else { fp as f64 / det as f64 };
        per_type.push(TypeMetrics {
            pii_type: ty,
            truth: truth_n,
            detected: det,
            tp,
            fp,
            fn_,
            recall,
            precision,
            fpr,
        });
    }
    let fn_total = total_truth.saturating_sub(total_tp);
    let totals = TypeMetrics {
        pii_type: "全部".into(),
        truth: total_truth,
        detected: total_det,
        tp: total_tp,
        fp: total_det.saturating_sub(total_tp),
        fn_: fn_total,
        recall: if total_truth == 0 { 1.0 } else { total_tp as f64 / total_truth as f64 },
        precision: if total_det == 0 { 0.0 } else { total_tp as f64 / total_det as f64 },
        fpr: if total_det == 0 { 0.0 } else { (total_det - total_tp) as f64 / total_det as f64 },
    };

    DetectionReport {
        per_type,
        totals,
        by_rule,
        unmatched,
        false_positives,
        scanned_texts: scanned,
        truth_spans: total_truth,
        notes: vec![
            "真值由数据生成器在埋点时记录，与检测器使用同一套类型定义。".into(),
            "误报率 = 未被真值覆盖的检出 / 全部检出（按类型统计）。".into(),
            "自由文本评估同时覆盖姓名、身份证、手机、住址、病案号、日期。".into(),
        ],
    }
}

fn overlap(a1: usize, a2: usize, b1: usize, b2: usize) -> usize {
    let lo = a1.max(b1);
    let hi = a2.min(b2);
    if hi > lo {
        hi - lo
    } else {
        0
    }
}
