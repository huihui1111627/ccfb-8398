//! Release artifact packaging: de-identified CSVs + manifest + reports.

use crate::csvio::to_csv;
use crate::engine::{EngineOutput, QualityReport, RiskReport};
use crate::models::PolicyConfig;
use crate::util::{sha256_hex, sha256_file};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ArtifactFile {
    pub name: String,
    pub rows: usize,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Manifest {
    pub release_id: String,
    pub dataset_id: String,
    pub dataset_name: String,
    pub project_id: String,
    pub project_name: String,
    pub group_name: String,
    pub policy_id: String,
    pub policy_version: i64,
    pub policy_snapshot: PolicyConfig,
    pub k: usize,
    pub k_achieved: usize,
    pub created_by: String,
    pub created_at: String,
    pub approved_by: String,
    pub approved_at: Option<String>,
    pub files: Vec<ArtifactFile>,
    pub manifest_sha256: String,
    pub risk: RiskReport,
    pub quality: QualityReport,
    pub notes: Vec<String>,
}

pub struct ArtifactOutput {
    pub dir: PathBuf,
    pub zip_path: PathBuf,
    pub manifest: Manifest,
    pub zip_sha256: String,
}

pub fn build(
    base_dir: &Path,
    release_id: &str,
    meta: &ManifestSeed,
    output: &EngineOutput,
) -> std::io::Result<ArtifactOutput> {
    let dir = base_dir.join(release_id);
    fs::create_dir_all(&dir)?;

    let mut files: Vec<ArtifactFile> = Vec::new();
    for (i, t) in output.tables.iter().enumerate() {
        // ASCII-safe file names keep the archive portable across OS/archivers;
        // the human-readable table name lives in the manifest.
        let roles = ["patients", "inpatient", "outpatient", "medications", "notes", "table"];
        let role = roles.get(i).copied().unwrap_or("table");
        let name = format!("{:02}_{}.csv", i + 1, role);
        let path = dir.join(&name);
        fs::write(&path, to_csv(t))?;
        let bytes = fs::metadata(&path)?.len();
        files.push(ArtifactFile {
            name,
            rows: t.rows.len(),
            bytes,
            sha256: sha256_file(&path)?,
        });
    }
    // reports as JSON
    let risk_json = serde_json::to_string_pretty(&output.risk).unwrap_or_default();
    fs::write(dir.join("risk_report.json"), &risk_json)?;
    let qual_json = serde_json::to_string_pretty(&output.quality).unwrap_or_default();
    fs::write(dir.join("quality_report.json"), &qual_json)?;
    let policy_json = serde_json::to_string_pretty(&output.policy_after).unwrap_or_default();
    fs::write(dir.join("policy_snapshot.json"), &policy_json)?;
    let decisions_json = serde_json::to_string_pretty(&output.decisions).unwrap_or_default();
    fs::write(dir.join("field_decisions.json"), &decisions_json)?;

    // README
    let readme = format!(
        "科研数据脱敏发布包\n==================\n数据集: {}\n课题组: {} ({})\n发布编号: {}\n策略版本: v{}\nk={} (实际最小等价类 {})\n生成时间: {}\n审批人: {}\n\n文件清单:\n{}\n\n风险与质量报告见 risk_report.json / quality_report.json。\n所有日期按患者级随机偏移平移，患者内相对间隔保持不变。\n",
        meta.dataset_name,
        meta.project_name,
        meta.group_name,
        release_id,
        meta.policy_version,
        meta.k,
        output.risk.k_achieved,
        meta.created_at,
        meta.approved_by,
        files
            .iter()
            .map(|f| format!("  - {} ({} 行, {} 字节)", f.name, f.rows, f.bytes))
            .collect::<Vec<_>>()
            .join("\n")
    );
    fs::write(dir.join("README.txt"), readme)?;

    let manifest = Manifest {
        release_id: release_id.to_string(),
        dataset_id: meta.dataset_id.clone(),
        dataset_name: meta.dataset_name.clone(),
        project_id: meta.project_id.clone(),
        project_name: meta.project_name.clone(),
        group_name: meta.group_name.clone(),
        policy_id: meta.policy_id.clone(),
        policy_version: meta.policy_version,
        policy_snapshot: output.policy_after.clone(),
        k: meta.k,
        k_achieved: output.risk.k_achieved,
        created_by: meta.created_by.clone(),
        created_at: meta.created_at.clone(),
        approved_by: meta.approved_by.clone(),
        approved_at: meta.approved_at.clone(),
        files: files.clone(),
        manifest_sha256: String::new(),
        risk: output.risk.clone(),
        quality: output.quality.clone(),
        notes: vec![
            "伪名由 HMAC-SHA256(主密钥, 课题组ID|患者ID) 生成，同一课题组内一致、跨课题组不可关联。".into(),
            "发布包内所有 CSV 的 sha256 与清单一致，可用于校验。".into(),
        ],
    };
    let manifest_bare = serde_json::to_string_pretty(&manifest).unwrap_or_default();
    let manifest_sha = sha256_hex(manifest_bare.as_bytes());
    let mut manifest_final = manifest.clone();
    manifest_final.manifest_sha256 = manifest_sha.clone();
    let manifest_text = serde_json::to_string_pretty(&manifest_final).unwrap_or_default();
    fs::write(dir.join("manifest.json"), &manifest_text)?;

    // zip everything in dir
    let zip_path = dir.with_extension("zip");
    write_zip(&dir, &zip_path)?;
    let zip_sha = sha256_file(&zip_path)?;

    Ok(ArtifactOutput {
        dir,
        zip_path,
        manifest: manifest_final,
        zip_sha256: zip_sha,
    })
}

fn write_zip(src: &Path, dest: &Path) -> std::io::Result<()> {
    use zip::write::SimpleFileOptions;
    let file = fs::File::create(dest)?;
    let mut zw = zip::ZipWriter::new(file);
    // UTF-8 filename flag: Chinese table names must survive archivers intact.
    let opts = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .large_file(false)
        .unix_permissions(0o644);
    let mut entries: Vec<PathBuf> = fs::read_dir(src)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for path in entries {
        if !path.is_file() {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        zw.start_file(name, opts)?;
        let data = fs::read(&path)?;
        zw.write_all(&data)?;
    }
    zw.finish()?;
    Ok(())
}

pub struct ManifestSeed {
    pub dataset_id: String,
    pub dataset_name: String,
    pub project_id: String,
    pub project_name: String,
    pub group_name: String,
    pub policy_id: String,
    pub policy_version: i64,
    pub k: usize,
    pub created_by: String,
    pub created_at: String,
    pub approved_by: String,
    pub approved_at: Option<String>,
}
