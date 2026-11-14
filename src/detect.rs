//! Field-level identifier recognition + free-text identifier extraction.
//!
//! Structured columns are scored by header keyword + value-pattern evidence.
//! Free text is scanned by regex, dictionary and context heuristics; every
//! match carries a type, a span and a confidence used for the P/R report.

use crate::models::{ColumnKind, PiiType};
use crate::util::{id_card_valid, parse_date};
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

#[derive(Serialize, Clone, Debug)]
pub struct TextMatch {
    pub pii_type: PiiType,
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub rule: String,
    pub confidence: f32,
}

#[derive(Serialize, Clone, Debug)]
pub struct ColDetection {
    pub kind: ColumnKind,
    pub confidence: f64,
    pub sample: String,
    pub evidence: String,
}

/// Accept only regex matches that are not embedded in a longer token.
fn bounded(m: &regex::Match, text: &str, is_word_char: impl Fn(char) -> bool) -> bool {
    let before = text[..m.start()].chars().next_back();
    let after = text[m.end()..].chars().next();
    !before.map(&is_word_char).unwrap_or(false) && !after.map(&is_word_char).unwrap_or(false)
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("valid regex")
}

// ---------- shared value regexes ----------

pub fn phone_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?:1[3-9]\d[\s-]?\d{4}[\s-]?\d{4}|1[3-9]\d{9}|0\d{2,3}-\d{7,8}(?:-\d{1,6})?|0\d{2,3}\s\d{7,8})")
    })
}

pub fn idcard_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?:[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]|\d{15})")
    })
}

pub fn date_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?:\d{4}[-/.年]\d{1,2}[-/.月]\d{1,2}日?|\d{4}年\d{1,2}月)")
    })
}

fn mrn_label_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| re(r"(?:病案号|住院号|门诊号|就诊卡号|就诊号|患者编号|病历号|患者ID)\s*[：:]?\s*([A-Za-z0-9\-]{4,20})"))
}

fn address_label_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?:家庭住址|现住址|户籍地址|户籍地|联系地址|工作单位地址|住址|地址|居住地)\s*[：:\s]\s*([^\n\r；;。]{3,80})")
    })
}

fn address_inline_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?:居住在|家住于|家住|居于|现住)([^\n\r，,；;。]{3,60})")
    })
}

fn labelled_name_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?:患者姓名|病人姓名|患者名|姓名|名字|联系人)\s*[：:]\s*([\u{4e00}-\u{9fa5}·]{2,8})|(?:患者|病人|病员)\s*[：:]\s*([\u{4e00}-\u{9fa5}·]{2,8})")
    })
}

fn relation_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?:女儿|儿子|配偶|妻子|丈夫|母亲|父亲|家属|哥哥|姐姐|弟弟|妹妹|孙子|孙女|外孙)\s*[：:]?\s*([\u{4e00}-\u{9fa5}]{2,4})")
    })
}

fn role_label_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"(?:查房医师|上级医师|主治医师|住院医师|手术医师|记录医师|医师|医生|护士|主任|记录者|术者|术者签名|签名)\s*[：:]\s*([\u{4e00}-\u{9fa5}]{2,4})")
    })
}

fn patient_prefix_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"患者([\u{4e00}-\u{9fa5}]{2,3})([，,。、；;（(\s]|精神|神志|诉|主诉|入院|出院|于|因|自|今|现|目|无|有|可|曾|已|行|转|复|随|在|向)")
    })
}

fn suffix_name_regex() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        re(r"([\u{4e00}-\u{9fa5}]{2,3})(先生|女士|阿姨|大爷|大叔|大妈|同志|师傅|老师)")
    })
}

// ---------- free-text extraction ----------

pub struct TextExtractor {
    surnames: HashSet<char>,
    compound_surnames: Vec<&'static str>,
    denylist: HashSet<&'static str>,
}

impl TextExtractor {
    pub fn new() -> Self {
        let surnames: HashSet<char> = "王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾肖田董袁潘于蒋蔡余杜叶程苏魏吕丁任沈姚卢姜崔钟谭陆汪范金石廖贾夏韦付方白邹孟熊秦邱江尹薛闫段雷侯龙史陶黎贺顾毛郝龚邵万钱严覃武戴莫孔向汤常温康施文牛樊葛邢安齐易乔伍庞颜倪庄聂章鲁岳翟殷詹申欧耿关兰焦俞左柳甘祝包宁尚符舒阮柯纪梅童凌毕单季裴霍涂成苗谷盛曲翁冉骆蓝路游辛靳管柴蒙鲍华喻祁蒲房滕屈饶解牟艾尤阳时穆农司卓古吉缪简车项连芦麦褚娄窦戚岑景党宫费卜冷晏席卫米柏宗瞿桂全佟应臧闵苟邬边卞姬师和仇栾隋商刁沙荣巫寇桑郎甄丛仲虞敖巩明佘池查麻苑迟邝"
            .chars()
            .collect();
        let compound_surnames = vec!["欧阳", "司马", "上官", "诸葛", "东方", "皇甫", "尉迟", "公孙", "慕容"];
        // words that begin with a surname character but are not names
        let deny: &[&str] = &[
            "患者", "病人", "病员", "医师", "医生", "护士", "主任", "教授", "专家", "家属", "本人",
            "入院", "出院", "门诊", "住院", "急诊", "手术", "检查", "检验", "治疗", "诊断", "病案",
            "病历", "科室", "病房", "床位", "护士站", "医生办公室", "主治", "上级", "下级",
            "白细", "红细", "血小", "白蛋", "高血", "高热", "高钾", "高钠", "高脂", "高敏",
            "周围", "淋巴", "罗音", "湿罗", "干罗", "黄疸", "黄色", "金属", "常规", "常见",
            "体温", "体重", "身高", "血压", "心率", "呼吸", "脉搏", "血氧", "血糖", "血脂",
            "左侧", "右侧", "双侧", "前方", "后方", "上方", "下方", "前方", "周围", "任何",
            "严重", "危重", "安静", "成人", "儿童", "老年", "青年", "中年", "单位", "纪录",
            "方法", "方式", "方可", "方案", "方向", "于是", "何时", "何时", "向前", "向后",
            "皮肤", "黏膜", "腹部", "胸部", "头部", "腰部", "背部", "四肢", "关节", "颈部",
            "明显", "未见", "无明", "无特", "无殊", "正常", "阳性", "阴性", "可疑", "提示",
            "考虑", "建议", "注意", "休息", "饮食", "运动", "复查", "随访", "转归", "好转",
            "加重", "缓解", "恢复", "稳定", "平稳", "持续", "间断", "反复", "逐渐", "明显",
            "妇科", "产科", "儿科", "内科", "外科", "骨科", "眼科", "口腔", "耳鼻", "皮肤科",
            "中医", "西医", "麻醉", "影像", "超声", "放射", "病理", "化验", "核磁", "心电",
            "人民", "中心", "大学", "医院", "研究", "中国", "国家", "卫生", "健康", "医疗",
            "省市", "区县", "街道", "社区", "小区", "号楼", "单元", "病房", "床号",
            "上午", "下午", "晚上", "凌晨", "今日", "昨日", "明日", "当天", "次日",
            "高血压", "低血压", "冠心病", "糖尿病", "白蛋白", "球蛋白", "血红蛋", "白细胞",
            "红细胞", "血小板", "中性粒", "淋巴", "单核", "嗜酸", "嗜碱", "网织红",
            "肌酐", "尿素氮", "尿酸", "胆红素", "转氨酶", "胆固醇", "甘油三", "电解质",
            "血钾", "血钠", "血氯", "血钙", "血糖", "血脂", "血气", "凝血", "纤维蛋",
            "程记录", "病程", "出院小", "入院记", "查体", "查房", "房医师", "院医师",
            "林治疗", "疗，注意", "等治疗", "治疗", "复查", "随访", "观察", "监测",
            "指标", "结果", "回报", "提示", "未见", "显示", "影像", "心电图", "超声",
            "胸部CT", "头颅CT", "腹部", "盆腔", "四肢", "脊柱", "关节", "软组织",
        ];
        TextExtractor {
            surnames,
            compound_surnames,
            denylist: deny.iter().copied().collect(),
        }
    }

    pub fn extract(&self, text: &str) -> Vec<TextMatch> {
        let mut out: Vec<TextMatch> = Vec::new();

        // 1. ID cards (checksum-validated)
        for m in idcard_regex().find_iter(text) {
            if !bounded(&m, text, |c| c.is_ascii_alphanumeric()) {
                continue;
            }
            if id_card_valid(m.as_str()) {
                out.push(TextMatch {
                    pii_type: PiiType::IdCard,
                    start: m.start(),
                    end: m.end(),
                    text: m.as_str().to_string(),
                    rule: "idcard_checksum".into(),
                    confidence: 0.99,
                });
            }
        }

        // 2. phones
        for m in phone_regex().find_iter(text) {
            if !bounded(&m, text, |c| c.is_ascii_digit()) {
                continue;
            }
            if overlaps(&out, m.start(), m.end()) {
                continue;
            }
            out.push(TextMatch {
                pii_type: PiiType::Phone,
                start: m.start(),
                end: m.end(),
                text: m.as_str().to_string(),
                rule: "phone_pattern".into(),
                confidence: 0.95,
            });
        }

        // 3. addresses with explicit labels
        for cap in address_label_regex().captures_iter(text) {
            if let Some(v) = cap.get(1) {
                if let Some((s, e, val)) = clean_address_span(text, v.start(), v.end()) {
                    if !overlaps(&out, s, e) {
                        out.push(TextMatch {
                            pii_type: PiiType::Address,
                            start: s,
                            end: e,
                            text: val,
                            rule: "address_label".into(),
                            confidence: 0.92,
                        });
                    }
                }
            }
        }

        // 4. addresses introduced inline
        for cap in address_inline_regex().captures_iter(text) {
            if let Some(v) = cap.get(1) {
                if let Some((s, e, val)) = clean_address_span(text, v.start(), v.end()) {
                    if !overlaps(&out, s, e) {
                        out.push(TextMatch {
                            pii_type: PiiType::Address,
                            start: s,
                            end: e,
                            text: val,
                            rule: "address_inline".into(),
                            confidence: 0.86,
                        });
                    }
                }
            }
        }

        // 5. labelled names
        for cap in labelled_name_regex().captures_iter(text) {
            let v = cap.get(1).or_else(|| cap.get(2));
            if let Some(v) = v {
                let val = v.as_str().to_string();
                if !self.denylist.contains(val.as_str()) && !overlaps(&out, v.start(), v.end()) {
                    out.push(TextMatch {
                        pii_type: PiiType::Name,
                        start: v.start(),
                        end: v.end(),
                        text: val,
                        rule: "name_label".into(),
                        confidence: 0.93,
                    });
                }
            }
        }

        // 5b. names behind a clinical role title
        for cap in role_label_regex().captures_iter(text) {
            if let Some(v) = cap.get(1) {
                if let Some((s, e, val)) = self.trim_to_name(v.start(), v.end(), text) {
                    if !overlaps(&out, s, e) {
                        out.push(TextMatch {
                            pii_type: PiiType::Name,
                            start: s,
                            end: e,
                            text: val,
                            rule: "name_role".into(),
                            confidence: 0.9,
                        });
                    }
                }
            }
        }

        // 5c. names directly after 患者
        for cap in patient_prefix_regex().captures_iter(text) {
            if let Some(v) = cap.get(1) {
                if let Some((s, e, val)) = self.trim_to_name(v.start(), v.end(), text) {
                    if !overlaps(&out, s, e) {
                        out.push(TextMatch {
                            pii_type: PiiType::Name,
                            start: s,
                            end: e,
                            text: val,
                            rule: "name_patient_prefix".into(),
                            confidence: 0.86,
                        });
                    }
                }
            }
        }

        // 6. names after a kinship word
        for cap in relation_regex().captures_iter(text) {
            if let Some(v) = cap.get(1) {
                let val = v.as_str().to_string();
                if self.looks_like_name(&val) && !overlaps(&out, v.start(), v.end()) {
                    out.push(TextMatch {
                        pii_type: PiiType::Name,
                        start: v.start(),
                        end: v.end(),
                        text: val,
                        rule: "name_kinship".into(),
                        confidence: 0.82,
                    });
                }
            }
        }

        // 7. names followed by an honorific
        for cap in suffix_name_regex().captures_iter(text) {
            if let Some(v) = cap.get(1) {
                let val = v.as_str().to_string();
                if self.looks_like_name(&val) && !overlaps(&out, v.start(), v.end()) {
                    out.push(TextMatch {
                        pii_type: PiiType::Name,
                        start: v.start(),
                        end: v.end(),
                        text: val,
                        rule: "name_honorific".into(),
                        confidence: 0.8,
                    });
                }
            }
        }

        // 8. MRNs behind a label
        for cap in mrn_label_regex().captures_iter(text) {
            if let Some(v) = cap.get(1) {
                if !overlaps(&out, v.start(), v.end()) {
                    out.push(TextMatch {
                        pii_type: PiiType::Mrn,
                        start: v.start(),
                        end: v.end(),
                        text: v.as_str().to_string(),
                        rule: "mrn_label".into(),
                        confidence: 0.88,
                    });
                }
            }
        }

        // 9. dates
        for m in date_regex().find_iter(text) {
            if !bounded(&m, text, |c| c.is_ascii_digit()) {
                continue;
            }
            if overlaps(&out, m.start(), m.end()) || parse_date(m.as_str()).is_none() {
                continue;
            }
            out.push(TextMatch {
                pii_type: PiiType::Date,
                start: m.start(),
                end: m.end(),
                text: m.as_str().to_string(),
                rule: "date_pattern".into(),
                confidence: 0.9,
            });
        }

        // 10. bare names in narrative context (lowest confidence)
        self.detect_bare_names(text, &mut out);

        out.sort_by_key(|m| m.start);
        out
    }

    /// From a captured Chinese-character run, pick the longest prefix that
    /// forms a plausible personal name (labels are greedy and may swallow the
    /// following verb).
    fn trim_to_name(&self, start: usize, end: usize, text: &str) -> Option<(usize, usize, String)> {
        let run = &text[start..end];
        let chars: Vec<char> = run.chars().collect();
        // Prefer the shortest candidate whose following character is a clear
        // boundary (punctuation/space) or the start of a common verb phrase.
        // This avoids swallowing "赵明指示继续" into "赵明指".
        let verbs = [
            "指示", "表示", "诉", "述", "称", "告知", "主诉", "入院", "出院", "精神",
            "神志", "继续", "给予", "建议", "查体", "饮", "睡", "自", "于", "因", "今",
            "现", "目", "无", "有", "可", "曾", "已", "行", "转", "术", "复", "随",
            "今晨", "昨日", "昨晚", "近日", "目前", "既往", "近日来", "自诉", "诉及",
        ];
        let mut fallback: Option<(usize, usize, String)> = None;
        for len in 2..=chars.len().min(4) {
            let cand: String = chars[..len].iter().collect();
            if !self.looks_like_name(&cand) || self.denylist.contains(cand.as_str()) {
                continue;
            }
            let byte_end = start + cand.len();
            let rest = &text[byte_end..];
            let is_boundary = rest
                .chars()
                .next()
                .map(|c| {
                    c.is_whitespace()
                        || c.is_ascii_digit()
                        || "，,。、；;：:（()）【】[]\"'".contains(c)
                        || c == '\n'
                        || c == '\t'
                })
                .unwrap_or(true);
            if is_boundary || verbs.iter().any(|v| rest.starts_with(v)) {
                return Some((start, byte_end, cand));
            }
            if fallback.is_none() {
                fallback = Some((start, byte_end, cand));
            }
        }
        fallback
    }

    fn looks_like_name(&self, cand: &str) -> bool {
        let chars: Vec<char> = cand.chars().collect();
        let n = chars.len();
        if !(2..=4).contains(&n) {
            return false;
        }
        if self.denylist.contains(cand) {
            return false;
        }
        let start = if n >= 3 && self.compound_surnames.iter().any(|c| cand.starts_with(c)) {
            2
        } else if self.surnames.contains(&chars[0]) {
            1
        } else {
            return false;
        };
        let given = &chars[start..];
        // given name is 1-2 characters; longer, or containing function words,
        // is almost certainly a verb/noun phrase captured by a greedy label.
        if given.is_empty() || given.len() > 2 {
            return false;
        }
        given.iter().all(|c| ('\u{4e00}'..='\u{9fa5}').contains(c))
            && !given
                .iter()
                .any(|c| "的了是在和与及或为也就都而但等这那之其指示继续给与后并且即把将被让使".contains(*c))
    }

    fn detect_bare_names(&self, text: &str, out: &mut Vec<TextMatch>) {
        let chars: Vec<char> = text.chars().collect();
        let mut idx = 0usize;
        while idx < chars.len() {
            if !self.surnames.contains(&chars[idx]) {
                idx += 1;
                continue;
            }
            let compound = self
                .compound_surnames
                .iter()
                .find(|c| {
                    let cc: Vec<char> = c.chars().collect();
                    idx + cc.len() <= chars.len() && chars[idx..idx + cc.len()] == cc[..]
                })
                .copied();
            let sur_len = compound.map(|c| c.chars().count()).unwrap_or(1);

            let mut matched: Option<(usize, f32)> = None;
            for given_len in [2usize, 1usize] {
                let end = idx + sur_len + given_len;
                if end > chars.len() {
                    continue;
                }
                let cand: String = chars[idx..end].iter().collect();
                if !self.looks_like_name(&cand) || self.denylist.contains(cand.as_str()) {
                    continue;
                }
                if let Some(conf) = self.context_confidence(&chars, idx, end) {
                    matched = Some((end, conf));
                    break;
                }
            }

            if let Some((end, conf)) = matched {
                let s = char_to_byte(text, idx);
                let e = char_to_byte(text, end);
                if !overlaps(out, s, e) {
                    out.push(TextMatch {
                        pii_type: PiiType::Name,
                        start: s,
                        end: e,
                        text: text[s..e].to_string(),
                        rule: "name_bare".into(),
                        confidence: conf,
                    });
                    idx = end;
                    continue;
                }
            }
            idx += 1;
        }
    }

    /// Returns Some(confidence) when the surrounding text supports a person name.
    fn context_confidence(&self, chars: &[char], start: usize, end: usize) -> Option<f32> {
        let before: String = chars[start.saturating_sub(4)..start].iter().collect();
        let after: String = chars[end..(end + 5).min(chars.len())].iter().collect();
        let next = after.chars().next();

        let delims = ['，', ',', '。', '、', '；', ';', '：', ':', '（', '(', '）', ')', ' ', '\n', '\t'];
        let verbs = [
            "说", "诉", "述", "表示", "告知", "称", "主诉", "入院", "出院", "因", "于", "在",
            "自", "系", "为", "无", "有", "可", "曾", "已", "行", "今", "现", "既往", "发病",
            "出现", "症状", "家属", "女儿", "儿子", "配偶", "先", "女", "男", "岁", "年", "月",
            "日", "上", "下", "转", "术", "复查", "门诊", "住院",
        ];
        let role_suffix = ["医师", "医生", "主任", "护士", "教授", "老师", "先生", "女士"];

        let mut score = 0.0f32;
        if next.map(|c| delims.contains(&c)).unwrap_or(false) {
            score += 0.4;
        }
        if verbs.iter().any(|v| after.starts_with(v)) {
            score += 0.4;
        }
        if role_suffix.iter().any(|v| after.starts_with(v)) {
            score += 0.3;
        }
        // "由/请/经/和/与/及/向/给/让/被 + NAME + verb" pattern
        if before
            .chars()
            .last()
            .map(|c| "由请经和与及向给让被".contains(c))
            .unwrap_or(false)
            && verbs.iter().any(|v| after.starts_with(v))
        {
            score += 0.5;
        }
        // "NAME，男/女，45岁" — classic case opening
        if after.starts_with('，')
            && after.chars().nth(1).map(|c| c == '男' || c == '女').unwrap_or(false)
        {
            score += 0.5;
        }
        if score >= 0.6 {
            Some((0.52 + score * 0.15).min(0.75))
        } else {
            None
        }
    }
}

fn char_to_byte(s: &str, char_idx: usize) -> usize {
    s.char_indices().nth(char_idx).map(|(b, _)| b).unwrap_or(s.len())
}

fn overlaps(matches: &[TextMatch], s: usize, e: usize) -> bool {
    matches.iter().any(|m| !(e <= m.start || s >= m.end))
}

/// Trim punctuation and leading verbs from an address capture.
fn clean_address_span(text: &str, s: usize, e: usize) -> Option<(usize, usize, String)> {
    let raw = &text[s..e];
    let trimmed_end = raw.trim_end_matches(|c: char| "。，,；;）) ".contains(c));
    let raw = trimmed_end;
    let mut val = raw;
    let mut start = s;
    for p in ["居住在", "家住于", "家住", "居于", "现住", "地址", "住址", "：", ":"] {
        if val.starts_with(p) && val.len() > p.len() {
            start += p.len();
            val = &val[p.len()..];
        }
    }
    let val = val.trim();
    if val.chars().count() < 3 {
        return None;
    }
    let start = start + (text[start..].find(val).unwrap_or(0));
    Some((start, start + val.len(), val.to_string()))
}

// ---------- structured column detection ----------

pub fn detect_column(header: &str, values: &[String], free_text_cols: &[String]) -> ColDetection {
    let h = crate::util::norm_header(header);
    let sample: Vec<&str> = values
        .iter()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .take(40)
        .collect();
    let sample_str = sample.first().map(|s| s.to_string()).unwrap_or_default();
    let n = sample.len().max(1);

    if free_text_cols.iter().any(|c| crate::util::norm_header(c) == h) {
        return ColDetection {
            kind: ColumnKind::FreeText,
            confidence: 0.99,
            sample: crate::util::truncate_chars(&sample_str, 40),
            evidence: "字段名匹配自由文本列".into(),
        };
    }

    let has = |needles: &[&str]| needles.iter().any(|n| h.contains(n));

    // value-shape evidence (authoritative for direct identifiers)
    let id_ok = sample.iter().filter(|v| id_card_valid(v)).count();
    if id_ok > 0 && id_ok * 2 > n {
        return ColDetection {
            kind: ColumnKind::IdCard,
            confidence: (0.65 + 0.34 * id_ok as f64 / n as f64).min(0.99),
            sample: crate::util::truncate_chars(&sample_str, 8),
            evidence: format!("{}/{} 样本通过身份证校验位", id_ok, sample.len()),
        };
    }
    let phone_ok = sample
        .iter()
        .filter(|v| {
            let d: String = v.chars().filter(|c| c.is_ascii_digit()).collect();
            (d.len() == 11 && d.starts_with('1')) || (d.len() >= 10 && d.len() <= 12 && d.starts_with('0'))
        })
        .count();
    if phone_ok > 0 && phone_ok * 2 > n && !has(&["邮编", "病案", "住院号", "编号"]) {
        return ColDetection {
            kind: ColumnKind::Phone,
            confidence: (0.6 + 0.36 * phone_ok as f64 / n as f64).min(0.97),
            sample: crate::util::truncate_chars(&sample_str, 6),
            evidence: format!("{}/{} 样本符合手机/固话格式", phone_ok, sample.len()),
        };
    }

    // header evidence
    let mut hit: Option<(ColumnKind, f64, String)> = None;
    if has(&["身份证", "证件号", "证件号码", "idcard", "id_number"]) {
        hit = Some((ColumnKind::IdCard, 0.95, "字段名含身份证".into()));
    } else if has(&["手机", "电话", "联系方式", "mobile", "phone", "tel"]) {
        hit = Some((ColumnKind::Phone, 0.9, "字段名含电话/手机".into()));
    } else if has(&["姓名", "患者名", "病人名", "联系人"]) || (h == "name" || h.ends_with("name")) {
        hit = Some((ColumnKind::Name, 0.9, "字段名含姓名".into()));
    } else if has(&["住址", "地址", "户籍", "address", "addr"]) {
        hit = Some((ColumnKind::Address, 0.86, "字段名含地址".into()));
    } else if has(&["病案号", "住院号", "门诊号", "就诊卡号", "就诊号", "病历号", "mrn", "患者编号"]) {
        hit = Some((ColumnKind::Mrn, 0.92, "字段名含病案/住院/门诊号".into()));
    } else if has(&["邮编", "邮政编码", "postcode", "zip"]) {
        hit = Some((ColumnKind::Postcode, 0.9, "字段名含邮编".into()));
    } else if has(&["出生日期", "出生年月", "birth", "dob"]) {
        hit = Some((ColumnKind::BirthDate, 0.92, "字段名含出生日期".into()));
    } else if has(&["年龄", "age"]) {
        hit = Some((ColumnKind::Age, 0.9, "字段名含年龄".into()));
    } else if has(&["性别", "sex", "gender"]) {
        hit = Some((ColumnKind::Gender, 0.9, "字段名含性别".into()));
    } else if has(&["诊断", "icd", "疾病", "diagnosis"]) {
        hit = Some((ColumnKind::Diagnosis, 0.88, "字段名含诊断".into()));
    } else if has(&["日期", "时间", "入院时间", "出院时间", "手术时间", "date"]) && !h.contains("年龄") {
        hit = Some((ColumnKind::Date, 0.86, "字段名含日期/时间".into()));
    }

    // value-shape for dates and postcode can strengthen a header hit
    let date_ok = sample.iter().filter(|v| parse_date(v).is_some()).count();
    if hit.is_none() && date_ok > 0 && date_ok * 2 > n {
        let all_numeric = sample.iter().all(|v| v.parse::<f64>().is_ok());
        if !all_numeric {
            hit = Some((
                ColumnKind::Date,
                0.85,
                format!("{}/{} 样本可解析为日期", date_ok, sample.len()),
            ));
        }
    }
    if hit.is_none() {
        let postcode_ok = sample
            .iter()
            .filter(|v| v.len() == 6 && v.chars().all(|c| c.is_ascii_digit()) && !v.starts_with('0'))
            .count();
        if postcode_ok * 2 > n && n > 3 && !has(&["编号", "号", "码"]) {
            hit = Some((
                ColumnKind::Postcode,
                0.72,
                format!("{}/{} 样本为 6 位数字", postcode_ok, sample.len()),
            ));
        }
    }

    // free-text header keywords
    if hit.is_none()
        && has(&[
            "出院小结", "病程记录", "主诉", "现病史", "既往史", "查体", "体格检查", "手术记录",
            "会诊记录", "护理记录", "note", "text", "文本", "内容", "记录", "描述", "摘要",
        ])
    {
        return ColDetection {
            kind: ColumnKind::FreeText,
            confidence: 0.9,
            sample: crate::util::truncate_chars(&sample_str, 40),
            evidence: "字段名匹配临床文本".into(),
        };
    }

    if let Some((kind, conf, ev)) = hit {
        // Age header with all-integer plausible values stays Age
        return ColDetection {
            kind,
            confidence: conf,
            sample: crate::util::truncate_chars(&sample_str, 32),
            evidence: ev,
        };
    }

    // residual free-text by shape
    let avg_len = sample.iter().map(|s| s.chars().count()).sum::<usize>() / n;
    if avg_len > 30 {
        let extractor = TextExtractor::new();
        let found: usize = sample.iter().map(|s| extractor.extract(s).len()).sum();
        if found > 0 {
            return ColDetection {
                kind: ColumnKind::FreeText,
                confidence: 0.72,
                sample: crate::util::truncate_chars(&sample_str, 40),
                evidence: format!("长文本且检出 {} 处标识", found),
            };
        }
        return ColDetection {
            kind: ColumnKind::FreeText,
            confidence: 0.55,
            sample: crate::util::truncate_chars(&sample_str, 40),
            evidence: "长文本字段".into(),
        };
    }

    let distinct: HashMap<&str, usize> = sample.iter().fold(HashMap::new(), |mut m, v| {
        *m.entry(*v).or_insert(0) += 1;
        m
    });
    let all_numeric = sample.iter().all(|v| v.parse::<f64>().is_ok());
    if all_numeric && n > 0 {
        return ColDetection {
            kind: ColumnKind::Numeric,
            confidence: 0.6,
            sample: crate::util::truncate_chars(&sample_str, 16),
            evidence: "样本均为数值".into(),
        };
    }
    // low-cardinality strings are categorical (drug names, doses, departments)
    let distinct_ratio = if sample.is_empty() { 1.0 } else { distinct.len() as f64 / sample.len() as f64 };
    if distinct.len() <= 40 && distinct_ratio < 0.6 && sample.iter().all(|v| v.chars().count() <= 24) {
        return ColDetection {
            kind: ColumnKind::Categorical,
            confidence: 0.7,
            sample: crate::util::truncate_chars(&sample_str, 16),
            evidence: format!("{} 个不同取值，占比 {:.0}%", distinct.len(), distinct_ratio * 100.0),
        };
    }
    ColDetection {
        kind: ColumnKind::Unknown,
        confidence: 0.3,
        sample: crate::util::truncate_chars(&sample_str, 16),
        evidence: "无匹配规则".into(),
    }
}

/// Address prefix length used for generalization (province / city / district).
pub fn address_prefix_len(value: &str, level: &str) -> usize {
    let chars: Vec<char> = value.chars().collect();
    let mut province_end = None;
    let mut city_end = None;
    let mut district_end = None;
    for (i, c) in chars.iter().enumerate() {
        match *c {
            '省' if province_end.is_none() => province_end = Some(i + 1),
            '市' | '州' if city_end.is_none() && province_end.is_some() => city_end = Some(i + 1),
            '区' | '县' if district_end.is_none() && city_end.is_some() => district_end = Some(i + 1),
            _ => {}
        }
    }
    // municipalities: 北京市朝阳区...
    if province_end.is_none() {
        for (i, c) in chars.iter().enumerate() {
            if *c == '市' {
                city_end = Some(i + 1);
                break;
            }
        }
    }
    match level {
        "province" => province_end.or(city_end).unwrap_or(chars.len()).min(chars.len()),
        "city" => city_end.or(province_end).unwrap_or(chars.len()).min(chars.len()),
        _ => district_end
            .or(city_end)
            .or(province_end)
            .unwrap_or(chars.len())
            .min(chars.len()),
    }
}
