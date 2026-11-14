use crate::db::TableData;
use std::io::Read;
use std::path::Path;

pub const FREE_TEXT_HEADERS: &[&str] = &[
    "出院小结",
    "病程记录",
    "主诉",
    "现病史",
    "既往史",
    "查体",
    "体格检查",
    "手术记录",
    "会诊记录",
    "护理记录",
    "备注",
    "文本内容",
];

pub fn read_csv_file(path: &Path, table_name: &str) -> Result<TableData, String> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .from_path(path)
        .map_err(|e| format!("读取 CSV 失败: {e}"))?;
    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| e.to_string())?
        .iter()
        .map(|h| h.trim().trim_start_matches('\u{feff}').to_string())
        .collect();
    let mut rows = Vec::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|e| e.to_string())?;
        let mut row: Vec<String> = rec.iter().map(|s| s.to_string()).collect();
        while row.len() < headers.len() {
            row.push(String::new());
        }
        row.truncate(headers.len());
        rows.push(row);
    }
    Ok(TableData {
        id: crate::util::new_id("f"),
        file_name: path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default(),
        table_name: table_name.to_string(),
        table_type: "structured".into(),
        headers,
        rows,
    })
}

pub fn read_upload(name: &str, bytes: &[u8]) -> Result<Vec<TableData>, String> {
    if name.to_lowercase().ends_with(".zip") {
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes.to_vec()))
            .map_err(|e| format!("ZIP 解析失败: {e}"))?;
        let mut out = Vec::new();
        for i in 0..zip.len() {
            let mut file = zip.by_index(i).map_err(|e| e.to_string())?;
            let fname = file.name().to_string();
            if !fname.to_lowercase().ends_with(".csv") || fname.starts_with("__MACOSX") {
                continue;
            }
            let mut content = String::new();
            file.read_to_string(&mut content)
                .map_err(|e| format!("读取 {fname} 失败: {e}"))?;
            let table = parse_csv_str(&content, &fname)?;
            out.push(table);
        }
        if out.is_empty() {
            return Err("ZIP 内没有 CSV 文件".into());
        }
        Ok(out)
    } else if name.to_lowercase().ends_with(".csv") {
        let content = String::from_utf8_lossy(bytes).to_string();
        Ok(vec![parse_csv_str(&content, name)?])
    } else {
        Err("仅支持 .csv 或包含 CSV 的 .zip".into())
    }
}

pub fn parse_csv_str(content: &str, name: &str) -> Result<TableData, String> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(content.as_bytes());
    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| e.to_string())?
        .iter()
        .map(|h| h.trim().trim_start_matches('\u{feff}').to_string())
        .collect();
    let mut rows = Vec::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|e| e.to_string())?;
        let mut row: Vec<String> = rec.iter().map(|s| s.to_string()).collect();
        while row.len() < headers.len() {
            row.push(String::new());
        }
        row.truncate(headers.len());
        rows.push(row);
    }
    let table_name = name
        .trim_end_matches(".csv")
        .trim_end_matches(".CSV")
        .rsplit('/')
        .next()
        .unwrap_or(name)
        .to_string();
    Ok(TableData {
        id: crate::util::new_id("f"),
        file_name: name.to_string(),
        table_name,
        table_type: "structured".into(),
        headers,
        rows,
    })
}

pub fn is_free_text_header(h: &str) -> bool {
    let nh = crate::util::norm_header(h);
    FREE_TEXT_HEADERS
        .iter()
        .any(|k| nh.contains(&crate::util::norm_header(k)))
}

pub fn to_csv(table: &TableData) -> String {
    let mut out = String::new();
    out.push_str(
        &table
            .headers
            .iter()
            .map(|h| crate::util::csv_escape(h))
            .collect::<Vec<_>>()
            .join(","),
    );
    out.push_str("\r\n");
    for row in &table.rows {
        out.push_str(
            &row.iter()
                .map(|v| crate::util::csv_escape(v))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    out
}
