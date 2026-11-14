use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, Copy)]
#[serde(rename_all = "snake_case")]
pub enum PiiType {
    Name,
    IdCard,
    Phone,
    Address,
    Mrn,
    Postcode,
    BirthDate,
    Date,
}

impl PiiType {
    pub fn label(&self) -> &'static str {
        match self {
            PiiType::Name => "姓名",
            PiiType::IdCard => "身份证号",
            PiiType::Phone => "手机号",
            PiiType::Address => "住址",
            PiiType::Mrn => "病案号",
            PiiType::Postcode => "邮政编码",
            PiiType::BirthDate => "出生日期",
            PiiType::Date => "日期",
        }
    }
    pub fn all() -> Vec<PiiType> {
        vec![
            PiiType::Name,
            PiiType::IdCard,
            PiiType::Phone,
            PiiType::Address,
            PiiType::Mrn,
            PiiType::Postcode,
            PiiType::BirthDate,
            PiiType::Date,
        ]
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ColumnKind {
    Name,
    IdCard,
    Phone,
    Address,
    Mrn,
    Postcode,
    BirthDate,
    Date,
    Age,
    Gender,
    Diagnosis,
    FreeText,
    Numeric,
    Categorical,
    Unknown,
}

impl ColumnKind {
    pub fn label(&self) -> &'static str {
        match self {
            ColumnKind::Name => "姓名",
            ColumnKind::IdCard => "身份证号",
            ColumnKind::Phone => "手机号",
            ColumnKind::Address => "住址",
            ColumnKind::Mrn => "病案号",
            ColumnKind::Postcode => "邮编",
            ColumnKind::BirthDate => "出生日期",
            ColumnKind::Date => "日期",
            ColumnKind::Age => "年龄",
            ColumnKind::Gender => "性别",
            ColumnKind::Diagnosis => "诊断",
            ColumnKind::FreeText => "自由文本",
            ColumnKind::Numeric => "数值",
            ColumnKind::Categorical => "分类",
            ColumnKind::Unknown => "未知",
        }
    }
    pub fn is_direct_identifier(&self) -> bool {
        matches!(
            self,
            ColumnKind::Name
                | ColumnKind::IdCard
                | ColumnKind::Phone
                | ColumnKind::Address
                | ColumnKind::Mrn
        )
    }
    pub fn is_quasi(&self) -> bool {
        matches!(
            self,
            ColumnKind::Age
                | ColumnKind::Gender
                | ColumnKind::Postcode
                | ColumnKind::Diagnosis
                | ColumnKind::Date
                | ColumnKind::BirthDate
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DetectionRow {
    pub id: String,
    pub dataset_id: String,
    pub file_id: String,
    pub table_name: String,
    pub column_name: String,
    pub detected_type: ColumnKind,
    pub confidence: f64,
    pub sample: String,
    pub evidence: String,
    pub confirmed: bool,
    pub strategy: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DatasetRow {
    pub id: String,
    pub name: String,
    pub source: String,
    pub owner: String,
    pub description: String,
    pub status: String,
    pub row_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PolicyConfig {
    pub version: u32,
    pub notes: String,
    pub direct: DirectConfig,
    pub free_text: FreeTextConfig,
    pub dates: DateConfig,
    pub quasi: QuasiConfig,
    pub k_anonymity: KConfig,
    pub risk: RiskConfig,
    pub quality: QualityConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DirectConfig {
    /// action per direct identifier type: pseudonym | mask | suppress | hash
    pub name: String,
    pub id_card: String,
    pub phone: String,
    pub address: String,
    pub mrn: String,
    pub phone_keep_last: usize,
    /// address generalization level: province | city | district
    pub address_level: String,
    /// token display prefix for pseudonyms
    pub pseudonym_prefix: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FreeTextConfig {
    pub enabled: bool,
    pub name: String,
    pub id_card: String,
    pub phone: String,
    pub address: String,
    pub mrn: String,
    pub date: String,
    pub birth_date: String,
    pub postcode: String,
    /// mask addresses to this level in text
    pub address_level: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DateConfig {
    /// shift | suppress | generalize
    pub action: String,
    pub min_days: i64,
    pub max_days: i64,
    /// generalise granularity if action=generalize
    pub granularity: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QuasiConfig {
    pub age_width: i32,
    pub postcode_keep_prefix: usize,
    pub diagnosis_level: String,
    pub gender: String,
    pub birth_date: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KConfig {
    pub k: usize,
    pub max_age_width: i32,
    pub min_postcode_prefix: usize,
    pub auto_escalate: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RiskConfig {
    pub max_reid_risk: f64,
    pub max_prosecution_risk: f64,
    pub require_no_residual_pii: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QualityConfig {
    pub max_relative_deviation: f64,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig {
            version: 1,
            notes: "默认脱敏策略：直接标识假名化，文本标识替换，日期患者级平移，准标识泛化至 k=5".into(),
            direct: DirectConfig {
                name: "pseudonym".into(),
                id_card: "pseudonym".into(),
                phone: "mask".into(),
                address: "generalize".into(),
                mrn: "pseudonym".into(),
                phone_keep_last: 4,
                address_level: "district".into(),
                pseudonym_prefix: "P".into(),
            },
            free_text: FreeTextConfig {
                enabled: true,
                name: "pseudonym".into(),
                id_card: "mask".into(),
                phone: "mask".into(),
                address: "generalize".into(),
                mrn: "pseudonym".into(),
                date: "shift".into(),
                birth_date: "generalize".into(),
                postcode: "mask".into(),
                address_level: "district".into(),
            },
            dates: DateConfig {
                action: "shift".into(),
                min_days: -365,
                max_days: -30,
                granularity: "month".into(),
            },
            quasi: QuasiConfig {
                age_width: 5,
                postcode_keep_prefix: 4,
                diagnosis_level: "icd3".into(),
                gender: "keep".into(),
                birth_date: "year".into(),
            },
            k_anonymity: KConfig {
                k: 5,
                max_age_width: 20,
                min_postcode_prefix: 2,
                auto_escalate: true,
            },
            risk: RiskConfig {
                max_reid_risk: 0.2,
                max_prosecution_risk: 0.2,
                require_no_residual_pii: true,
            },
            quality: QualityConfig {
                max_relative_deviation: 0.25,
            },
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PolicyRow {
    pub id: String,
    pub dataset_id: String,
    pub name: String,
    pub scope: String,
    pub version: i64,
    pub config: PolicyConfig,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProjectRow {
    pub id: String,
    pub name: String,
    pub group_name: String,
    pub contact: String,
    pub description: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReleaseRow {
    pub id: String,
    pub dataset_id: String,
    pub dataset_name: String,
    pub policy_id: String,
    pub policy_version: i64,
    pub project_id: String,
    pub project_name: String,
    pub group_name: String,
    pub k: i64,
    pub status: String,
    pub risk: serde_json::Value,
    pub quality: serde_json::Value,
    pub findings: Vec<String>,
    pub created_by: String,
    pub created_at: String,
    pub approved_by: String,
    pub approved_at: Option<String>,
    pub rejected_reason: String,
    pub manifest: serde_json::Value,
    pub artifact_sha256: String,
    pub can_export: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AuditRow {
    pub id: i64,
    pub event_time: String,
    pub actor: String,
    pub action: String,
    pub dataset_id: String,
    pub project_id: String,
    pub release_id: String,
    pub policy_id: String,
    pub detail: String,
    pub hash_prev: String,
    pub hash_self: String,
    pub chain_ok: bool,
}
