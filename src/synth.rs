//! Synthetic test data generator.
//!
//! Produces a realistic hospital extract: patient index, inpatient stays,
//! outpatient visits, medication intervals and free-text clinical notes.
//! Every free-text identifier injected is recorded as a ground-truth span so
//! the platform can report per-type detection rate and false-positive rate.

use crate::db::TableData;
use crate::models::ColumnKind;
use crate::util::{make_id_card, new_id, now_iso};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{Duration, NaiveDate};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TruthSpan {
    pub table: String,
    pub row: usize,
    pub column: String,
    pub pii_type: String,
    pub start: usize,
    pub end: usize,
    pub text: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DatasetProfile {
    pub patients: usize,
    pub inpatient_rows: usize,
    pub outpatient_rows: usize,
    pub medication_rows: usize,
    pub note_rows: usize,
    pub age_mean: f64,
    pub gender: HashMap<String, usize>,
    pub diagnosis: HashMap<String, usize>,
    pub los_mean: f64,
    pub interval_mean_days: f64,
    pub text_chars: usize,
    pub truth_spans: usize,
    pub generated_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ColumnTruth {
    pub table: String,
    pub column: String,
    pub kind: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SyntheticDataset {
    pub tables: Vec<TableData>,
    pub truth: Vec<TruthSpan>,
    pub column_truth: Vec<ColumnTruth>,
    pub profile: DatasetProfile,
    pub free_text_headers: Vec<String>,
}

struct Patient {
    #[allow(dead_code)]
    seq: usize,
    name: String,
    gender: String,
    birth: NaiveDate,
    id_card: String,
    phone: String,
    address: String,
    postcode: String,
    mrn: String,
    age: i32,
    dept: String,
    diag: String,
    diag_code: String,
    arch: usize,
}

struct NoteBuilder {
    text: String,
    spans: Vec<(usize, usize, &'static str)>,
}

impl NoteBuilder {
    fn new() -> Self {
        NoteBuilder { text: String::new(), spans: Vec::new() }
    }
    fn push(&mut self, s: &str) -> &mut Self {
        self.text.push_str(s);
        self
    }
    fn pii(&mut self, s: &str, ty: &'static str) -> &mut Self {
        let start = self.text.len();
        self.text.push_str(s);
        self.spans.push((start, self.text.len(), ty));
        self
    }
}

// (age_low, age_high, male_pct, district_idx, diagnosis, icd_code, dept, count, los_lo, los_hi)
const ARCHETYPES: &[(i32, i32, u32, usize, &str, &str, &str, usize, i64, i64)] = &[
    (62, 64, 85, 0, "高血压", "I10.x00", "心内科", 14, 4, 8),
    (67, 69, 10, 0, "高血压", "I10.x00", "心内科", 11, 5, 10),
    (55, 59, 90, 1, "冠心病", "I25.101", "心内科", 13, 4, 9),
    (70, 74, 12, 1, "冠心病", "I25.101", "心内科", 9, 6, 12),
    (45, 49, 80, 2, "脑梗死", "I63.900", "神经内科", 7, 6, 14),
    (72, 74, 70, 2, "脑梗死", "I63.900", "神经内科", 10, 7, 15),
    (52, 54, 35, 0, "2型糖尿病", "E11.900", "内分泌科", 13, 4, 9),
    (58, 59, 55, 1, "2型糖尿病", "E11.900", "内分泌科", 8, 5, 10),
    (75, 79, 75, 2, "肺炎", "J18.900", "呼吸科", 11, 6, 13),
    (75, 79, 45, 0, "肺炎", "J18.900", "呼吸科", 7, 7, 14),
    (65, 69, 80, 1, "慢性阻塞性肺疾病", "J44.900", "呼吸科", 9, 5, 11),
    (60, 64, 40, 2, "慢性阻塞性肺疾病", "J44.900", "呼吸科", 6, 6, 12),
    (38, 39, 70, 0, "慢性胃炎", "K29.500", "消化科", 10, 3, 7),
    (42, 44, 60, 1, "急性阑尾炎", "K35.900", "普外科", 6, 3, 6),
    (68, 69, 40, 2, "慢性肾脏病", "N18.900", "肾内科", 8, 4, 10),
    (44, 49, 75, 0, "腰椎间盘突出", "M48.000", "骨科", 7, 4, 9),
    (74, 79, 55, 1, "股骨骨折", "S72.001", "骨科", 10, 8, 16),
    (63, 64, 85, 2, "肺恶性肿瘤", "C34.900", "肿瘤科", 6, 6, 13),
    (30, 34, 65, 0, "肺结核", "A16.200", "感染科", 7, 8, 15),
    (28, 29, 5, 1, "妊娠状态", "O80.000", "产科", 11, 2, 4),
    (35, 39, 20, 2, "抑郁症", "F32.900", "精神科", 6, 5, 11),
    (76, 79, 70, 0, "老年性白内障", "H25.900", "眼科", 9, 2, 4),
    (25, 29, 75, 1, "癫痫", "G40.900", "神经内科", 6, 3, 7),
    (48, 49, 55, 0, "银屑病", "L40.000", "皮肤科", 7, 4, 9),
    (55, 59, 80, 2, "头痛", "R51.900", "神经内科", 6, 3, 6),
    (66, 69, 90, 0, "健康查体", "Z00.000", "体检中心", 12, 1, 2),
];

const SURNAMES: &[&str] = &[
    "王", "李", "张", "刘", "陈", "杨", "黄", "赵", "吴", "周", "徐", "孙", "马", "朱", "胡",
    "郭", "何", "高", "林", "罗", "郑", "梁", "谢", "宋", "唐", "许", "韩", "冯", "邓", "曹",
    "彭", "曾", "肖", "田", "董", "袁", "潘", "蒋", "蔡", "余", "杜", "叶", "程", "苏", "魏",
    "吕", "丁", "任", "沈", "姚", "卢", "姜", "崔", "钟", "谭", "陆", "汪", "范", "金", "石",
    "廖", "贾", "夏", "韦", "付", "方", "邹", "孟", "熊", "秦", "邱", "江", "尹", "薛", "段",
    "雷", "侯", "龙", "史", "陶", "黎", "贺", "顾", "毛", "郝", "龚", "邵", "钱", "严", "武",
    "戴", "莫", "孔", "向", "汤", "常", "温", "康", "施", "文", "牛", "樊", "葛", "邢", "安",
    "齐", "易", "乔", "伍", "庞", "颜", "倪", "庄", "聂", "章", "鲁", "岳", "翟", "殷", "詹",
    "申", "欧", "耿", "关", "兰", "焦", "俞", "左", "柳", "甘", "祝", "包", "宁", "尚", "符",
    "舒", "阮", "柯", "纪", "梅", "童", "凌", "毕", "单", "季", "裴", "霍", "涂", "成", "苗",
    "谷", "盛", "曲", "翁", "冉", "骆", "蓝", "路", "游", "辛", "靳", "管", "柴", "蒙", "鲍",
    "华", "喻", "祁", "蒲", "房", "滕", "屈", "饶", "解", "牟", "艾", "尤", "阳", "时", "穆",
    "农", "司", "卓", "古", "吉", "缪", "简", "车", "项", "连", "芦", "麦", "褚", "娄", "窦",
    "戚", "岑", "景", "党", "宫", "费", "卜", "冷", "晏", "席", "卫", "米", "柏", "宗", "瞿",
    "桂", "全", "佟", "应", "臧", "闵", "苟", "邬", "边", "卞", "姬", "师", "和", "仇", "栾",
    "隋", "商", "刁", "沙", "荣", "巫", "寇", "桑", "郎", "甄", "丛", "仲", "虞", "敖", "巩",
    "明", "佘", "池", "查", "麻", "苑", "迟", "邝",
];

const GIVEN_CHARS: &[&str] = &[
    "伟", "芳", "娜", "秀", "英", "敏", "静", "丽", "强", "磊", "军", "洋", "勇", "艳", "杰",
    "娟", "涛", "明", "超", "霞", "平", "刚", "桂", "华", "建", "国", "志", "文", "红", "梅",
    "玉", "兰", "淑", "珍", "凤", "金", "海", "燕", "晓", "小", "东", "峰", "斌", "彬", "波",
    "辉", "鹏", "飞", "宇", "浩", "鑫", "琳", "晶", "莉", "萍", "颖", "洁", "慧", "倩", "雪",
    "云", "龙", "凯", "健", "康", "宁", "丹", "青", "春", "秋", "冬", "林", "森", "岩", "峰",
    "利", "民", "生", "庆", "福", "贵", "富", "荣", "发", "成", "功", "胜", "安", "定", "远",
    "达", "进", "新", "征", "锋", "武", "刚", "毅", "俊", "帅", "亮", "光", "明", "晖", "昊",
    "天", "阳", "帆", "航", "涛", "浪", "雨", "雷", "电", "山", "河", "海", "月", "星", "辰",
];

const DISTRICTS: &[(usize, &str, &str, &str, &str)] = &[
    (0, "110105", "北京市朝阳区", "望京街道花家地小区", "100102"),
    (1, "110108", "北京市海淀区", "中关村街道知春里小区", "100086"),
    (2, "110106", "北京市丰台区", "右安门街道开阳里小区", "100069"),
];

const COMPLAINTS: &[&str] = &[
    "反复胸闷、气短3年，加重2天",
    "头晕伴右侧肢体乏力1天",
    "口干、多饮、多尿半年",
    "发热伴咳嗽、咳痰4天",
    "上腹部胀痛、反酸1周",
    "腰痛伴左下肢放射痛3天",
    "跌伤后左髋部疼痛、活动受限6小时",
    "咳嗽、咳痰伴喘息10年，加重3天",
    "体检发现血压升高2年",
    "胸闷、心悸反复发作1月",
];

const COMORBID: &[&str] = &["高血压", "2型糖尿病", "冠心病", "慢性胃炎", "骨质疏松"];

const MEDS: &[&str] = &[
    "阿司匹林肠溶片", "氯吡格雷", "氨氯地平", "美托洛尔", "二甲双胍", "胰岛素",
    "头孢曲松", "布地奈德", "奥美拉唑", "沙丁胺醇", "华法林", "左氧氟沙星",
    "单硝酸异山梨酯", "甘露醇", "缬沙坦", "阿托伐他汀",
];

struct Gen {
    rng: StdRng,
    used_names: HashMap<String, usize>,
    patients: Vec<Patient>,
    truth: Vec<TruthSpan>,
    doctors: Vec<String>,
    kins: Vec<String>,
    profile: DatasetProfile,
    #[allow(dead_code)]
    sub: usize,
}

impl Gen {
    fn pick<'a, T>(&mut self, arr: &'a [T]) -> &'a T {
        let i = self.rng.gen_range(0..arr.len());
        &arr[i]
    }
    fn name(&mut self, gender: &str) -> String {
        for _ in 0..200 {
            let sur = self.pick(SURNAMES).to_string();
            let glen = if self.rng.gen::<f64>() < 0.55 { 1 } else { 2 };
            let mut given = String::new();
            for _ in 0..glen {
                // female-leaning and male-leaning pools overlap; keep simple
                given.push_str(self.pick(GIVEN_CHARS));
            }
            let full = format!("{}{}", sur, given);
            if !self.used_names.contains_key(&full) {
                // plausible gender association not enforced; names are synthetic
                let _ = gender;
                self.used_names.insert(full.clone(), 1);
                return full;
            }
        }
        format!("{}{}童", self.pick(SURNAMES), self.rng.gen_range(10..99))
    }
    fn phone(&mut self) -> String {
        let prefix = ["138", "139", "136", "137", "150", "151", "158", "186", "187", "188", "135"][
            self.rng.gen_range(0..11)
        ];
        format!("{}{:08}", prefix, self.rng.gen_range(0..100_000_000u32))
    }
    fn landline(&mut self) -> String {
        format!("010-{:08}", self.rng.gen_range(60_000_000..69_999_999u32))
    }
    fn address(&mut self, district: usize) -> String {
        let d = DISTRICTS[district];
        let building = self.rng.gen_range(1..25);
        let unit = self.rng.gen_range(1..7);
        let room = self.rng.gen_range(1..7);
        let suite = self.rng.gen_range(1..7);
        format!("{}{}{}号楼{}单元{}0{}室", d.2, d.3, building, unit, room, suite)
    }
}

pub fn generate(patient_target: usize, seed: u64) -> SyntheticDataset {
    let mut g = Gen {
        rng: StdRng::seed_from_u64(seed),
        used_names: HashMap::new(),
        patients: Vec::new(),
        truth: Vec::new(),
        doctors: vec![],
        kins: vec![],
        profile: DatasetProfile::default(),
        sub: 0,
    };
    // clinician names (also personal data; redacted from notes)
    let mut doc_names = vec![];
    for _ in 0..10 {
        doc_names.push(g.name("男"));
    }
    g.doctors = doc_names;
    let mut kin_names = vec![];
    for _ in 0..16 {
        kin_names.push(g.name("女"));
    }
    g.kins = kin_names;

    // ----- patients, following archetype counts scaled to target -----
    let total_arch: usize = ARCHETYPES.iter().map(|a| a.7).sum();
    let scale = patient_target as f64 / total_arch as f64;
    // Largest-remainder allocation so the generated count equals the target
    // exactly (naive per-archetype rounding drifts by a few percent).
    let mut alloc: Vec<usize> = ARCHETYPES
        .iter()
        .map(|a| ((a.7 as f64 * scale) as usize).max(3))
        .collect();
    let mut allocated: usize = alloc.iter().sum();
    let remainders: Vec<(f64, usize)> = ARCHETYPES
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let exact = a.7 as f64 * scale;
            (exact - exact.floor(), i)
        })
        .collect();
    let mut sorted_rem = remainders;
    sorted_rem.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let mut idx = 0;
    while allocated < patient_target.max(ARCHETYPES.len() * 3) && !sorted_rem.is_empty() {
        alloc[sorted_rem[idx % sorted_rem.len()].1] += 1;
        allocated += 1;
        idx += 1;
    }
    while allocated > patient_target && !sorted_rem.is_empty() {
        let i = sorted_rem[idx % sorted_rem.len()].1;
        if alloc[i] > 3 {
            alloc[i] -= 1;
            allocated -= 1;
        }
        idx += 1;
        if idx > patient_target * 4 + ARCHETYPES.len() { break; }
    }
    let mut seq = 0usize;
    for (ai, a) in ARCHETYPES.iter().enumerate() {
        let count = alloc[ai];
        for _ in 0..count {
            seq += 1;
            let age = g.rng.gen_range(a.0..=a.1);
            let male = g.rng.gen_range(0..100u32) < a.2;
            let gender = if male { "男" } else { "女" }.to_string();
            let birth: NaiveDate = NaiveDate::from_ymd_opt(2024 - age, g.rng.gen_range(1..13), g.rng.gen_range(1..29))
                .unwrap_or_else(|| NaiveDate::from_ymd_opt(1960, 1, 1).unwrap());
            let region = DISTRICTS[a.3].1;
            let id_card = make_id_card(region, birth, seq as u32, male);
            let name = g.name(&gender);
            let phone = g.phone();
            let address = g.address(a.3);
            let postcode = DISTRICTS[a.3].4.to_string();
            let mrn = format!("{:08}", 10_000_000 + seq * 37 + 11);
            g.patients.push(Patient {
                seq,
                name,
                gender,
                birth,
                id_card,
                phone,
                address,
                postcode,
                mrn,
                age,
                dept: a.6.to_string(),
                diag: a.4.to_string(),
                diag_code: a.5.to_string(),
                arch: ai,
            });
        }
    }
    // Deliberate same-name collision: two different patients with identical
    // name but different birth dates must not be linked.
    if let Some(first) = g.patients.first().map(|p| p.name.clone()) {
        let idx = 1.min(g.patients.len().saturating_sub(1));
        if let Some(p) = g.patients.get_mut(idx) {
            p.name = first.clone();
        }
    }

    // ----- tables -----
    let mut patients_t = TableData {
        id: new_id("f"),
        file_name: "patients.csv".into(),
        table_name: "患者主索引".into(),
        table_type: "structured".into(),
        headers: vec![
            "病案号".into(), "姓名".into(), "性别".into(), "出生日期".into(),
            "身份证号".into(), "手机号".into(), "家庭住址".into(), "邮编".into(),
        ],
        rows: vec![],
    };
    let mut inpatient = TableData {
        id: new_id("f"),
        file_name: "inpatient.csv".into(),
        table_name: "住院记录".into(),
        table_type: "structured".into(),
        headers: vec![
            "病案号".into(), "姓名".into(), "性别".into(), "年龄".into(),
            "入院日期".into(), "出院日期".into(), "住院天数".into(), "科室".into(),
            "入院诊断".into(), "出院诊断".into(), "诊断编码".into(), "手术操作".into(),
            "总费用".into(), "白细胞计数".into(),
        ],
        rows: vec![],
    };
    let mut outpatient = TableData {
        id: new_id("f"),
        file_name: "outpatient.csv".into(),
        table_name: "门诊记录".into(),
        table_type: "structured".into(),
        headers: vec![
            "病案号".into(), "姓名".into(), "性别".into(), "年龄".into(),
            "就诊日期".into(), "科室".into(), "诊断".into(), "诊断编码".into(), "处方金额".into(),
        ],
        rows: vec![],
    };
    let mut meds = TableData {
        id: new_id("f"),
        file_name: "medications.csv".into(),
        table_name: "用药记录".into(),
        table_type: "structured".into(),
        headers: vec![
            "病案号".into(), "姓名".into(), "用药开始日期".into(), "用药结束日期".into(),
            "药品".into(), "剂量".into(), "给药间隔天数".into(),
        ],
        rows: vec![],
    };
    let mut notes = TableData {
        id: new_id("f"),
        file_name: "notes.csv".into(),
        table_name: "临床文本".into(),
        table_type: "free_text".into(),
        headers: vec![
            "病案号".into(), "姓名".into(), "记录日期".into(),
            "出院小结".into(), "病程记录".into(),
        ],
        rows: vec![],
    };

    let mut los_sum = 0f64;
    let mut interval_sum = 0f64;
    let mut interval_n = 0usize;
    let mut text_chars = 0usize;
    let mut age_sum = 0f64;

    let base = NaiveDate::from_ymd_opt(2024, 1, 8).unwrap();

    let mut patients_clone: Vec<(usize, String, String, NaiveDate, String, String, String, String, String, i32, String, String, String)> = vec![];

    for p in &g.patients {
        patients_t.rows.push(vec![
            p.mrn.clone(),
            p.name.clone(),
            p.gender.clone(),
            p.birth.format("%Y-%m-%d").to_string(),
            p.id_card.clone(),
            p.phone.clone(),
            p.address.clone(),
            p.postcode.clone(),
        ]);
        patients_clone.push((
            p.arch, p.name.clone(), p.gender.clone(), p.birth, p.id_card.clone(),
            p.phone.clone(), p.address.clone(), p.mrn.clone(), p.postcode.clone(),
            p.age, p.diag.clone(), p.diag_code.clone(), p.dept.clone(),
        ));
    }

    for (pi, p) in patients_clone.iter().enumerate() {
        let (arch, name, gender, _birth, id_card, phone, address, mrn, _postcode, age, diag, diag_code, dept) = p;
        let a = ARCHETYPES[*arch];

        // inpatient stay
        let admit_offset = g.rng.gen_range(0..300);
        let admit = base + Duration::days(admit_offset);
        let los = g.rng.gen_range(a.8..=a.9);
        let discharge = admit + Duration::days(los);
        let wbc = format!("{:.2}", g.rng.gen_range(3.2..12.5f64));
        let fee = format!("{:.2}", g.rng.gen_range(3000.0..42000.0f64));
        let surgery = if diag.contains("骨折") || diag.contains("阑尾") || diag.contains("白内障") || diag.contains("腰椎") {
            ["内固定术", "阑尾切除术", "白内障超声乳化术", "椎间盘髓核摘除术"][*arch % 4].to_string()
        } else { String::new() };
        inpatient.rows.push(vec![
            mrn.clone(), name.clone(), gender.clone(), age.to_string(),
            admit.format("%Y-%m-%d").to_string(), discharge.format("%Y-%m-%d").to_string(),
            (los + 1).to_string(), dept.clone(), diag.clone(), diag.clone(), diag_code.clone(),
            surgery, fee, wbc.clone(),
        ]);
        los_sum += los as f64;

        // outpatient visits
        let n_visits = g.rng.gen_range(1..=3);
        for _ in 0..n_visits {
            let vdate = admit - Duration::days(g.rng.gen_range(10..300));
            outpatient.rows.push(vec![
                mrn.clone(), name.clone(), gender.clone(), age.to_string(),
                vdate.format("%Y-%m-%d").to_string(), dept.clone(), diag.clone(), diag_code.clone(),
                format!("{:.2}", g.rng.gen_range(80.0..900.0f64)),
            ]);
        }

        // medications with intervals
        let n_meds = g.rng.gen_range(2..=4);
        let mut current = admit + Duration::days(1);
        for _ in 0..n_meds {
            let days = g.rng.gen_range(3..10);
            let end = current + Duration::days(days);
            let interval = g.rng.gen_range(6..48);
            meds.rows.push(vec![
                mrn.clone(), name.clone(), current.format("%Y-%m-%d").to_string(),
                end.format("%Y-%m-%d").to_string(), g.pick(MEDS).to_string(),
                format!("{}mg", [5, 10, 20, 40, 100][g.rng.gen_range(0..5)]),
                interval.to_string(),
            ]);
            interval_sum += interval as f64;
            interval_n += 1;
            current = end + Duration::days(1);
        }

        // notes: discharge summary + progress notes
        let doctor = g.doctors[*arch % g.doctors.len()].clone();
        let kin = g.kins[pi % g.kins.len()].clone();
        let kin_phone = if g.rng.gen::<f64>() < 0.5 { g.phone() } else { g.landline() };
        let complaint = COMPLAINTS[*arch % COMPLAINTS.len()];
        let comorb = COMORBID[(*arch * 3 + pi) % COMORBID.len()];

        // ---- discharge summary (two phrasings) ----
        let variant = g.rng.gen_range(0..3);
        let mut nb = NoteBuilder::new();
        nb.push("出院小结\n");
        if variant == 0 {
            nb.push("患者：");
        } else if variant == 1 {
            nb.push("姓名：");
        } else {
            nb.push("患者");
        }
        nb.pii(name, "姓名");
        nb.push("，");
        nb.push(gender);
        nb.push("，");
        nb.push(&age.to_string());
        nb.push("岁，");
        if variant == 1 {
            nb.push("住院号：");
        } else {
            nb.push("病案号：");
        }
        nb.pii(mrn, "病案号");
        nb.push("，身份证号：");
        nb.pii(id_card, "身份证号");
        nb.push("，联系电话：");
        nb.pii(phone, "手机号");
        if variant == 2 {
            nb.push("，现住址：");
        } else {
            nb.push("，家庭住址：");
        }
        nb.pii(address, "住址");
        nb.push("。\n入院日期：");
        nb.pii(&admit.format("%Y-%m-%d").to_string(), "日期");
        nb.push("，出院日期：");
        nb.pii(&discharge.format("%Y-%m-%d").to_string(), "日期");
        nb.push(&format!("，住院天数：{}天。\n", los + 1));
        nb.push("主诉：");
        nb.push(complaint);
        nb.push("。\n入院诊断：");
        nb.push(diag);
        nb.push("；出院诊断：");
        nb.push(diag);
        nb.push("；合并");
        nb.push(comorb);
        nb.push("。\n诊疗经过：入院后完善血常规、生化、心电图等检查，白细胞计数 ");
        nb.push(&wbc);
        nb.push("×10^9/L，白蛋白 38g/L，血压 138/86mmHg。给予");
        nb.push(g.pick(MEDS));
        nb.push("等治疗，石蜡切片病理回报未见恶性细胞，症状较前好转。\n出院情况：一般情况可，生命体征平稳。\n出院医嘱：规律服药，1个月后门诊复查。\n医师：");
        nb.pii(&doctor, "姓名");
        nb.push("\n记录日期：");
        nb.pii(&discharge.format("%Y-%m-%d").to_string(), "日期");
        nb.push("\n");
        let text = nb.text.clone();
        let note_date = discharge.format("%Y-%m-%d").to_string();
        let note_row = notes.rows.len();
        push_note(&mut notes, &mut g.truth, note_row, mrn, name, &note_date, Some(text), None, nb);
        text_chars += notes.rows.last().map(|r| r[3].len()).unwrap_or(0);

        // ---- legacy-format note: irregular spacing/date styles that a real HIS
        // export often contains. These exercise the detector's real limits. ----
        if g.rng.gen::<f64>() < 0.18 {
            let mut nb = NoteBuilder::new();
            nb.push("旧版病历摘要\n");
            nb.push("病人 ");
            // spaced name is deliberately hard for the label regex
            let spaced: String = name.chars().map(|c| c.to_string()).collect::<Vec<_>>().join(" ");
            nb.push(&spaced);
            nb.push("  性别 ");
            nb.push(gender);
            nb.push("  年龄 ");
            nb.push(&age.to_string());
            nb.push("\n住院号 ");
            nb.pii(mrn, "病案号");
            nb.push("\n联系电话 ");
            // mobile written with spaces — detector currently misses this
            let spaced_phone = if phone.len() == 11 {
                format!("{} {} {}", &phone[0..3], &phone[3..7], &phone[7..])
            } else {
                phone.clone()
            };
            nb.pii(&spaced_phone, "手机号");
            nb.push("\n住址 ");
            nb.pii(address, "住址");
            nb.push("\n入院 ");
            nb.pii(&admit.format("%Y.%m.%d").to_string(), "日期");
            nb.push(" 出院 ");
            nb.pii(&discharge.format("%Y.%m.%d").to_string(), "日期");
            nb.push("\n");
            // A free-text-only re-mention with no surrounding structure: the
            // detector is expected to miss some of these, so the reported rate
            // is not artificially perfect.
            if g.rng.gen::<f64>() < 0.5 {
                nb.push("联系人 ");
                nb.pii(&kin, "姓名");
                nb.push("，电话 ");
                nb.pii(&kin_phone, "手机号");
                nb.push("。\n");
            }
            let text = nb.text.clone();
            let note_date = discharge.format("%Y-%m-%d").to_string();
            let note_row = notes.rows.len();
            push_note(&mut notes, &mut g.truth, note_row, mrn, name, &note_date, None, Some(text), nb);
        }

        // ---- admission record: narrative opening, name not behind a label ----
        let adate = admit;
        let mut nb = NoteBuilder::new();
        nb.push("入院记录\n");
        nb.pii(name, "姓名");
        nb.push("，");
        nb.push(gender);
        nb.push("，");
        nb.push(&age.to_string());
        nb.push("岁，因");
        nb.push(complaint);
        nb.push("入院。\n现病史：患者");
        nb.pii(name, "姓名");
        nb.push("于");
        nb.pii(&adate.format("%Y-%m-%d").to_string(), "日期");
        nb.push("门诊就诊，门诊以");
        nb.push(diag);
        nb.push("收入院。\n既往史：");
        nb.push(comorb);
        nb.push("病史。\n个人史：生于原籍，久居本地，否认疫区接触史。\n婚育史：已婚，配偶体健。\n家族史：父母已故，否认家族遗传病史。\n");
        let text = nb.text.clone();
        let note_date = adate.format("%Y-%m-%d").to_string();
        let note_row = notes.rows.len();
        push_note(&mut notes, &mut g.truth, note_row, mrn, name, &note_date, Some(text), None, nb);

        // ---- progress note ----
        let pdate = admit + Duration::days(g.rng.gen_range(1..los.max(2)));
        let mut nb = NoteBuilder::new();
        nb.pii(&pdate.format("%Y-%m-%d").to_string(), "日期");
        nb.push(" 09:20 病程记录\n患者");
        nb.pii(name, "姓名");
        nb.push("，");
        nb.push(gender);
        nb.push("，");
        nb.push(&age.to_string());
        nb.push("岁，住院号：");
        nb.pii(mrn, "病案号");
        nb.push("。家属：");
        nb.pii(&kin, "姓名");
        nb.push("，联系电话：");
        nb.pii(&kin_phone, "手机号");
        nb.push("。\n今日患者诉");
        nb.push(complaint);
        nb.push(&format!(
            "，查体：T {:.1}℃，P {}次/分，R {}次/分，BP {}/{}mmHg。\n患者",
            g.rng.gen_range(36.2..38.0f64),
            g.rng.gen_range(60..110),
            g.rng.gen_range(14..24),
            g.rng.gen_range(100..170),
            g.rng.gen_range(60..100),
        ));
        nb.pii(name, "姓名");
        nb.push("精神可，饮食睡眠一般。查房医师：");
        nb.pii(&doctor, "姓名");
        nb.push("指示继续");
        nb.push(g.pick(MEDS));
        nb.push("治疗，注意观察药物不良反应。\n计划于");
        nb.pii(&(pdate + Duration::days(7)).format("%Y-%m-%d").to_string(), "日期");
        nb.push("复查胸部CT。\n");
        let text = nb.text.clone();
        let note_date = pdate.format("%Y-%m-%d").to_string();
        let note_row = notes.rows.len();
        push_note(&mut notes, &mut g.truth, note_row, mrn, name, &note_date, None, Some(text), nb);
        text_chars += notes.rows.last().map(|r| r[4].len()).unwrap_or(0);

        age_sum += *age as f64;
        *g.profile.gender.entry(gender.clone()).or_insert(0) += 1;
        *g.profile.diagnosis.entry(diag.clone()).or_insert(0) += 1;
    }

    let n_patients = patients_t.rows.len();
    let mut profile = DatasetProfile {
        patients: n_patients,
        inpatient_rows: inpatient.rows.len(),
        outpatient_rows: outpatient.rows.len(),
        medication_rows: meds.rows.len(),
        note_rows: notes.rows.len(),
        age_mean: age_sum / n_patients.max(1) as f64,
        gender: std::mem::take(&mut g.profile.gender),
        diagnosis: std::mem::take(&mut g.profile.diagnosis),
        los_mean: los_sum / n_patients.max(1) as f64,
        interval_mean_days: interval_sum / interval_n.max(1) as f64,
        text_chars,
        truth_spans: g.truth.len(),
        generated_at: now_iso(),
    };
    profile.gender = std::mem::take(&mut profile.gender);
    profile.diagnosis = std::mem::take(&mut profile.diagnosis);

    let column_truth = build_column_truth();
    let free_text_headers = vec!["出院小结".to_string(), "病程记录".to_string()];

    SyntheticDataset {
        tables: vec![patients_t, inpatient, outpatient, meds, notes],
        truth: g.truth,
        column_truth,
        profile,
        free_text_headers,
    }
}

fn push_note(
    notes: &mut TableData,
    truth: &mut Vec<TruthSpan>,
    row: usize,
    mrn: &str,
    name: &str,
    note_date: &str,
    discharge: Option<String>,
    progress: Option<String>,
    nb: NoteBuilder,
) {
    let discharge = discharge.unwrap_or_default();
    let progress = progress.unwrap_or_default();
    notes.rows.push(vec![
        mrn.to_string(),
        name.to_string(),
        note_date.to_string(),
        discharge.clone(),
        progress.clone(),
    ]);
    let column = if discharge.is_empty() { "病程记录" } else { "出院小结" };
    let _ = column;
    // Map spans onto the correct column. Spans were built for whichever text is
    // present; recompute the offset by re-deriving from the builder order.
    // We stored spans against the concatenated text of exactly one field.
    for (s, e, ty) in nb.spans {
        let selected = if !discharge.is_empty() { &discharge } else { &progress };
        if s <= selected.len() && e <= selected.len() {
            truth.push(TruthSpan {
                table: "临床文本".into(),
                row,
                column: if discharge.is_empty() { "病程记录".into() } else { "出院小结".into() },
                pii_type: ty.into(),
                start: s,
                end: e,
                text: selected[s..e].to_string(),
            });
        }
    }
}

fn build_column_truth() -> Vec<ColumnTruth> {
    let mut out = vec![];
    let t = |table: &str, column: &str, kind: ColumnKind| ColumnTruth {
        table: table.into(),
        column: column.into(),
        kind: serde_json::to_value(&kind)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_default(),
    };
    for (c, k) in [
        ("病案号", ColumnKind::Mrn),
        ("姓名", ColumnKind::Name),
        ("性别", ColumnKind::Gender),
        ("出生日期", ColumnKind::BirthDate),
        ("身份证号", ColumnKind::IdCard),
        ("手机号", ColumnKind::Phone),
        ("家庭住址", ColumnKind::Address),
        ("邮编", ColumnKind::Postcode),
    ] {
        out.push(t("患者主索引", c, k));
    }
    for (c, k) in [
        ("病案号", ColumnKind::Mrn),
        ("姓名", ColumnKind::Name),
        ("性别", ColumnKind::Gender),
        ("年龄", ColumnKind::Age),
        ("入院日期", ColumnKind::Date),
        ("出院日期", ColumnKind::Date),
        ("住院天数", ColumnKind::Numeric),
        ("科室", ColumnKind::Categorical),
        ("入院诊断", ColumnKind::Diagnosis),
        ("出院诊断", ColumnKind::Diagnosis),
        ("诊断编码", ColumnKind::Diagnosis),
        ("手术操作", ColumnKind::Categorical),
        ("总费用", ColumnKind::Numeric),
        ("白细胞计数", ColumnKind::Numeric),
    ] {
        out.push(t("住院记录", c, k));
    }
    for (c, k) in [
        ("病案号", ColumnKind::Mrn),
        ("姓名", ColumnKind::Name),
        ("性别", ColumnKind::Gender),
        ("年龄", ColumnKind::Age),
        ("就诊日期", ColumnKind::Date),
        ("科室", ColumnKind::Categorical),
        ("诊断", ColumnKind::Diagnosis),
        ("诊断编码", ColumnKind::Diagnosis),
        ("处方金额", ColumnKind::Numeric),
    ] {
        out.push(t("门诊记录", c, k));
    }
    for (c, k) in [
        ("病案号", ColumnKind::Mrn),
        ("姓名", ColumnKind::Name),
        ("用药开始日期", ColumnKind::Date),
        ("用药结束日期", ColumnKind::Date),
        ("药品", ColumnKind::Categorical),
        ("剂量", ColumnKind::Categorical),
        ("给药间隔天数", ColumnKind::Numeric),
    ] {
        out.push(t("用药记录", c, k));
    }
    for (c, k) in [
        ("病案号", ColumnKind::Mrn),
        ("姓名", ColumnKind::Name),
        ("记录日期", ColumnKind::Date),
        ("出院小结", ColumnKind::FreeText),
        ("病程记录", ColumnKind::FreeText),
    ] {
        out.push(t("临床文本", c, k));
    }
    out
}
