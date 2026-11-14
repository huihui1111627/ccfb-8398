use chrono::{Duration, NaiveDate};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

type HmacSha256 = Hmac<Sha256>;

pub const B32_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let data = fs::read(path)?;
    Ok(sha256_hex(&data))
}

/// Crockford base32, no padding. Deterministic display-safe tokens.
pub fn base32(data: &[u8], chars: usize) -> String {
    let mut out = String::new();
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for b in data {
        buf = (buf << 8) | (*b as u32);
        bits += 8;
        while bits >= 5 && out.len() < chars {
            let idx = ((buf >> (bits - 5)) & 0x1f) as usize;
            out.push(B32_ALPHABET[idx] as char);
            bits -= 5;
        }
        if out.len() >= chars {
            break;
        }
    }
    out
}

pub fn load_or_create_master_key(dir: &Path) -> std::io::Result<[u8; 32]> {
    fs::create_dir_all(dir)?;
    let path = dir.join("master.key");
    if path.exists() {
        let txt = fs::read_to_string(&path)?;
        let bytes = hex::decode(txt.trim())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if bytes.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "master key must be 32 bytes",
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    } else {
        let mut arr = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut arr);
        fs::write(&path, hex::encode(arr))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(arr)
    }
}

pub fn parse_date(s: &str) -> Option<NaiveDate> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // take date part only
    let core = s
        .split(|c: char| c == ' ' || c == 'T')
        .next()
        .unwrap_or(s)
        .trim();
    let cleaned = core
        .replace('年', "-")
        .replace('月', "-")
        .replace("日", "")
        .replace('/', "-")
        .replace('.', "-");
    let parts: Vec<&str> = cleaned.split('-').filter(|p| !p.is_empty()).collect();
    if parts.len() == 3 {
        let y: i32 = parts[0].parse().ok()?;
        let m: u32 = parts[1].parse().ok()?;
        let d: u32 = parts[2].parse().ok()?;
        return NaiveDate::from_ymd_opt(y, m, d);
    }
    None
}

pub fn shift_date(s: &str, days: i64) -> Option<String> {
    let d = parse_date(s)?;
    Some((d + Duration::days(days)).format("%Y-%m-%d").to_string())
}

pub fn days_between(a: &str, b: &str) -> Option<i64> {
    let da = parse_date(a)?;
    let db = parse_date(b)?;
    Some((db - da).num_days())
}

pub fn compute_age(birth: NaiveDate, at: NaiveDate) -> i32 {
    let mut age = at.year() - birth.year();
    if (at.month(), at.day()) < (birth.month(), birth.day()) {
        age -= 1;
    }
    age
}

use chrono::Datelike;

pub fn age_band(age: i32, width: i32) -> String {
    if width <= 0 {
        return age.to_string();
    }
    if age < 0 {
        return "未知".into();
    }
    if age >= 90 {
        return "90岁以上".into();
    }
    let start = (age / width) * width;
    let end = start + width - 1;
    format!("{}-{}岁", start, end)
}

pub fn band_midpoint(band: &str) -> Option<f64> {
    if band.contains("90") && band.contains("以上") {
        return Some(92.0);
    }
    let core = band.trim_end_matches('岁');
    let mut it = core.split('-');
    let a: f64 = it.next()?.parse().ok()?;
    let b: f64 = it.next()?.parse().ok()?;
    Some((a + b) / 2.0)
}

fn id_weights() -> [i32; 17] {
    [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
}

pub fn id_card_valid(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() == 18 {
        let mut sum = 0i32;
        for i in 0..17 {
            let d = match chars[i].to_digit(10) {
                Some(d) => d as i32,
                None => return false,
            };
            sum += d * id_weights()[i];
        }
        let check = "10X98765432"
            .chars()
            .nth((sum % 11) as usize)
            .unwrap_or('X');
        if chars[17].to_ascii_uppercase() != check {
            return false;
        }
        // plausible birth date
        let birth: String = chars[6..14].iter().collect();
        if let Some(d) = parse_date(&format!(
            "{}-{}-{}",
            &birth[0..4],
            &birth[4..6],
            &birth[6..8]
        )) {
            let now = chrono::Local::now().date_naive();
            return d >= NaiveDate::from_ymd_opt(1900, 1, 1).unwrap() && d <= now;
        }
        false
    } else if chars.len() == 15 {
        chars.iter().all(|c| c.is_ascii_digit())
            && parse_date(&format!(
                "19{}-{}-{}",
                &s[6..8],
                &s[8..10],
                &s[10..12]
            ))
            .is_some()
    } else {
        false
    }
}

pub fn id_card_birth(s: &str) -> Option<NaiveDate> {
    if s.len() == 18 {
        parse_date(&format!("{}-{}-{}", &s[6..10], &s[10..12], &s[12..14]))
    } else if s.len() == 15 {
        parse_date(&format!("19{}-{}-{}", &s[6..8], &s[8..10], &s[10..12]))
    } else {
        None
    }
}

pub fn id_card_gender(s: &str) -> Option<&'static str> {
    if s.len() == 18 {
        let d = s.chars().nth(16)?.to_digit(10)?;
        Some(if d % 2 == 1 { "男" } else { "女" })
    } else if s.len() == 15 {
        let d = s.chars().nth(14)?.to_digit(10)?;
        Some(if d % 2 == 1 { "男" } else { "女" })
    } else {
        None
    }
}

/// Generate a valid 18-digit ID card with the given region, birth and gender.
pub fn make_id_card(region: &str, birth: NaiveDate, seq: u32, male: bool) -> String {
    let base = format!(
        "{}{:02}{:02}{:02}{:03}",
        region,
        birth.year(),
        birth.month(),
        birth.day(),
        seq % 1000
    );
    let mut chars: Vec<char> = base.chars().collect();
    if chars.len() > 14 {
        let last = chars[14];
        if let Some(d) = last.to_digit(10) {
            // 17th digit controls gender
            chars[14] = std::char::from_digit(if male { (d | 1) % 10 } else { (d & 8) % 10 }, 10)
                .unwrap_or('0');
        }
    }
    let body: String = chars.iter().take(17).collect();
    let mut sum = 0i32;
    for (i, c) in body.chars().enumerate().take(17) {
        sum += c.to_digit(10).unwrap_or(0) as i32 * id_weights()[i];
    }
    let check = "10X98765432"
        .chars()
        .nth((sum % 11) as usize)
        .unwrap_or('X');
    format!("{}{}", body, check)
}

pub fn mask_value(v: &str) -> String {
    let n = v.chars().count();
    if n <= 2 {
        "*".repeat(n)
    } else {
        let keep = 1;
        let mut out: String = v.chars().take(keep).collect();
        out.push_str(&"*".repeat(n - keep));
        out
    }
}

pub fn norm_header(h: &str) -> String {
    h.trim()
        .trim_start_matches('\u{feff}')
        .replace([' ', '\u{3000}', '_', '-', '（', '）', '(', ')'], "")
        .to_lowercase()
}

pub fn now_iso() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn new_id(prefix: &str) -> String {
    format!(
        "{}_{}",
        prefix,
        &uuid::Uuid::new_v4().simple().to_string()[..10]
    )
}

pub fn csv_escape(v: &str) -> String {
    if v.contains(',') || v.contains('"') || v.contains('\n') || v.contains('\r') {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_string()
    }
}

pub fn truncate_chars(s: &str, n: usize) -> String {
    let mut out: String = s.chars().take(n).collect();
    if s.chars().count() > n {
        out.push('…');
    }
    out
}
