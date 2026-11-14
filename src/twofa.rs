//! 两步验证（TOTP）：RFC 6238 / RFC 4226，HMAC-SHA1、6 位、30 秒一步。
//!
//! 密钥只进 Windows 凭据管理器（与邮箱授权码同一套做法），`twofa.json` 里只有名称与账号，
//! 所以备份数据目录看不到可用于生成动态码的内容。时间由调用方传入（`App` 用 `Env::t`），
//! 录屏能逐帧复现同一组动态码。

use std::collections::HashMap;

pub const SERVICE: &str = "Daozai.TwoFactor";
pub const PERIOD: u64 = 30;
pub const DIGITS: usize = 6;

/// 一条验证器记录；密钥按 `id` 存在凭据管理器里。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub id: String,
    pub issuer: String,
    pub label: String,
}

impl Account {
    /// 列表主标题：有服务名用服务名，否则用账号。
    pub fn title(&self) -> &str {
        if self.issuer.trim().is_empty() { self.label.trim() } else { self.issuer.trim() }
    }

    /// 列表副标题：主标题已经是账号时留空，避免同一行出现两次。
    pub fn subtitle(&self) -> &str {
        if self.issuer.trim().is_empty() { "" } else { self.label.trim() }
    }
}

fn accounts_path() -> std::path::PathBuf {
    crate::model::config_dir().join("twofa.json")
}

pub fn decode_accounts(raw: &[u8]) -> Vec<Account> {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    json.as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let id = item.get("id")?.as_str()?.trim().to_string();
            if id.is_empty() {
                return None;
            }
            let issuer = item.get("issuer").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            let label = item.get("label").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
            if issuer.is_empty() && label.is_empty() {
                return None;
            }
            Some(Account { id, issuer, label })
        })
        .collect()
}

pub fn encode_accounts(items: &[Account]) -> Vec<u8> {
    let list: Vec<_> = items
        .iter()
        .map(|a| serde_json::json!({"id": a.id, "issuer": a.issuer, "label": a.label}))
        .collect();
    serde_json::to_vec(&list).unwrap_or_default()
}

pub fn load_accounts() -> Vec<Account> {
    match std::fs::read(accounts_path()) {
        Ok(raw) => decode_accounts(&raw),
        Err(_) => Vec::new(),
    }
}

pub fn save_accounts(items: &[Account]) {
    let data = encode_accounts(items);
    let path = accounts_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = crate::model::atomic_write(&path, &data);
}

// ---------------------------------------------------------------- Base32

/// 接受大小写、空格与 `-` 分隔的 Base32；返回去掉填充的规范形式。
pub fn normalize_secret(raw: &str) -> Result<String, String> {
    let mut cleaned = String::new();
    for ch in raw.chars() {
        let ch = ch.to_ascii_uppercase();
        if ch.is_ascii_whitespace() || ch == '-' {
            continue;
        }
        if ch == '=' {
            break;
        }
        cleaned.push(ch);
    }
    if cleaned.is_empty() {
        return Err("请填写 2FA 密钥".into());
    }
    base32_decode(&cleaned)?;
    Ok(cleaned)
}

pub fn base32_decode(raw: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for ch in raw.trim_end_matches('=').chars() {
        let value = match ch {
            'A'..='Z' => (ch as u8 - b'A') as u32,
            'a'..='z' => (ch as u8 - b'a') as u32,
            '2'..='7' => (ch as u8 - b'2' + 26) as u32,
            _ => return Err("密钥只能包含 A–Z 和 2–7".into()),
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    if bytes.is_empty() {
        return Err("密钥太短".into());
    }
    Ok(bytes)
}

// ---------------------------------------------------------------- TOTP

fn hotp(secret: &[u8], counter: u64) -> String {
    let mut message = [0u8; 8];
    for (index, byte) in message.iter_mut().enumerate() {
        *byte = (counter >> (8 * (7 - index as u64))) as u8;
    }
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let mac = ring::hmac::sign(&key, &message);
    let digest = mac.as_ref();
    // RFC 4226 动态截断：用最后一个字节的低 4 位挑偏移，取 4 字节并去掉符号位。
    let offset = (digest[19] & 0x0f) as usize;
    let value = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | digest[offset + 3] as u32;
    format!("{:0width$}", value % 10u32.pow(DIGITS as u32), width = DIGITS)
}

/// 当前时间（Unix 秒，含小数）。
///
/// TOTP 必须对真实时钟计算：`Env::t` 是进程运行时长（从启动开始累加），
/// 用它算出来的是 1970 年前后的计数器，和任何认证器都对不上。
pub fn now() -> f64 {
    let nanos = chrono::Local::now().timestamp_nanos_opt().unwrap_or(0);
    nanos as f64 / 1_000_000_000.0
}

/// 取码窗口：`(counter, 剩余秒)`。
///
/// 动态码和进度条必须由同一个整秒窗口得出：`at` 先落到整秒（与 `code` 的计数器一致），
/// 剩余秒再带小数。这样跨窗口时“码变化”和“条回满”发生在同一帧，不会各自算各自的。
pub fn window(at: f64) -> (u64, f64) {
    let seconds = at.max(0.0).floor();
    let counter = (seconds / PERIOD as f64) as u64;
    let elapsed = (at.max(0.0) - counter as f64 * PERIOD as f64).clamp(0.0, PERIOD as f64);
    (counter, PERIOD as f64 - elapsed)
}

/// 当前动态码；密钥非法时返回 `None`。
pub fn code(secret: &str, at: f64) -> Option<String> {
    let key = base32_decode(secret).ok()?;
    Some(hotp(&key, window(at).0))
}

/// 这一步还剩几秒（1..=30，含小数）。
///
/// 保留小数是为了让进度条连续后退；只取整秒会让它每秒跳一格。
pub fn remaining(at: f64) -> f64 {
    window(at).1
}

/// 界面展示用：`123 456`，复制时仍用连续 6 位。
pub fn display(code: &str) -> String {
    if code.len() != DIGITS {
        return code.to_string();
    }
    format!("{} {}", &code[..3], &code[3..])
}

// ---------------------------------------------------------------- otpauth 链接

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).ok();
            if let Some(value) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(value);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 解析 `otpauth://totp/发行方:账号?secret=...&issuer=...`。
pub fn parse_uri(raw: &str) -> Result<(String, String, String), String> {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("otpauth://totp/") {
        return Err("只支持 otpauth://totp/ 开头的链接".into());
    }
    let rest = &trimmed["otpauth://totp/".len()..];
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label_path = percent_decode(path.trim_matches('/'));
    let (mut issuer, mut label) = ("".to_string(), label_path.clone());
    if let Some((left, right)) = label_path.split_once(':') {
        issuer = left.trim().to_string();
        label = right.trim().to_string();
    }
    let mut secret = String::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = percent_decode(value).trim().to_string(),
            "issuer" => {
                if issuer.is_empty() {
                    issuer = percent_decode(value).trim().to_string();
                }
            }
            "digits" if value.trim() != "6" => return Err("只支持 6 位动态码".into()),
            "period" if value.trim() != "30" => return Err("只支持 30 秒一步的动态码".into()),
            "algorithm" if !value.trim().eq_ignore_ascii_case("sha1") => return Err("只支持 SHA1 动态码".into()),
            _ => {}
        }
    }
    if secret.is_empty() {
        return Err("链接里没有 secret".into());
    }
    let secret = normalize_secret(&secret)?;
    if label.is_empty() {
        return Err("链接里没有账号名".into());
    }
    Ok((issuer, label, secret))
}

// ---------------------------------------------------------------- 存储

fn new_id(existing: &[Account]) -> String {
    let mut seed = chrono::Local::now().timestamp_nanos_opt().unwrap_or(0).unsigned_abs();
    loop {
        let id = format!("totp-{seed:x}");
        if !existing.iter().any(|account| account.id == id) {
            return id;
        }
        seed += 1;
    }
}

#[cfg(windows)]
pub mod secrets {
    /// 密钥只进 Windows 凭据管理器；键是记录 id，值是 Base32 密钥。
    pub fn save(id: &str, secret: &str) -> Result<(), String> {
        let entry = keyring::Entry::new(super::SERVICE, id).map_err(|e| format!("凭据管理器不可用：{e}"))?;
        entry.set_password(secret).map_err(|e| format!("保存 2FA 密钥失败：{e}"))
    }

    pub fn load(id: &str) -> Result<String, String> {
        let entry = keyring::Entry::new(super::SERVICE, id).map_err(|e| format!("凭据管理器不可用：{e}"))?;
        entry.get_password().map_err(|_| "本机没有保存这条密钥".to_string())
    }

    pub fn delete(id: &str) {
        if let Ok(entry) = keyring::Entry::new(super::SERVICE, id) {
            let _ = entry.delete_credential();
        }
    }
}

#[cfg(not(windows))]
pub mod secrets {
    pub fn save(_id: &str, _secret: &str) -> Result<(), String> {
        Err("仅支持 Windows 凭据管理器".into())
    }
    pub fn load(_id: &str) -> Result<String, String> {
        Err("仅支持 Windows 凭据管理器".into())
    }
    pub fn delete(_id: &str) {}
}

/// 验证器清单 + 密钥的内存副本（启动时读一次凭据管理器，避免逐帧读）。
#[derive(Clone, Debug, Default)]
pub struct Vault {
    pub accounts: Vec<Account>,
    secrets: HashMap<String, String>,
}

impl Vault {
    pub fn load() -> Self {
        let accounts = load_accounts();
        let mut secrets = HashMap::new();
        for account in &accounts {
            if let Ok(secret) = secrets::load(&account.id) {
                secrets.insert(account.id.clone(), secret);
            }
        }
        Self { accounts, secrets }
    }

    pub fn secret(&self, id: &str) -> Option<&str> {
        self.secrets.get(id).map(String::as_str)
    }

    /// 只放进内存（测试与恢复用），不写凭据管理器。
    pub(crate) fn remember(&mut self, id: &str, secret: &str) {
        self.secrets.insert(id.to_string(), secret.to_string());
    }

    /// 生成当前动态码；没密钥或密钥无效时给出可读原因。
    pub fn code(&self, account: &Account, at: f64) -> Result<String, String> {
        let secret = self.secret(&account.id).ok_or("本机没有保存这条密钥，请重新添加")?;
        code(secret, at).ok_or_else(|| "密钥无法解析，请重新添加".to_string())
    }

    pub fn add(&mut self, issuer: &str, label: &str, raw_secret: &str) -> Result<(), String> {
        let secret = normalize_secret(raw_secret)?;
        let issuer = issuer.trim();
        let label = label.trim();
        if label.is_empty() {
            return Err("请填写账号名，例如邮箱或用户名".into());
        }
        if issuer.chars().count() > 40 || label.chars().count() > 80 {
            return Err("服务名或账号太长".into());
        }
        if self.accounts.iter().any(|a| a.issuer == issuer && a.label == label) {
            return Err("这个账号已经添加过了".into());
        }
        let id = new_id(&self.accounts);
        secrets::save(&id, &secret)?;
        self.accounts.push(Account { id: id.clone(), issuer: issuer.to_string(), label: label.to_string() });
        self.secrets.insert(id, secret);
        self.save();
        Ok(())
    }

    /// 从 otpauth 链接添加。
    pub fn add_uri(&mut self, uri: &str) -> Result<(), String> {
        let (issuer, label, secret) = parse_uri(uri)?;
        self.add(&issuer, &label, &secret)
    }

    pub fn remove(&mut self, index: usize) {
        if index >= self.accounts.len() {
            return;
        }
        let account = self.accounts.remove(index);
        self.secrets.remove(&account.id);
        secrets::delete(&account.id);
        self.save();
    }

    pub fn save(&self) {
        save_accounts(&self.accounts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 附录 B 的 SHA-1 向量（种子是 ASCII "12345678901234567890"）。
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn totp_matches_rfc_6238_sha1_vectors() {
        for (at, expected) in [
            (59.0, "287082"),
            (1111111109.0, "081804"),
            (1111111111.0, "050471"),
            (1234567890.0, "005924"),
            (2000000000.0, "279037"),
            (20000000000.0, "353130"),
        ] {
            assert_eq!(code(RFC_SECRET, at).unwrap(), expected, "{at} 秒处应为 RFC 向量");
        }
    }

    /// 与参考实现 TokenGuardianGo（core/otp.go）同一套 HMAC-SHA1 + 动态截断，
    /// 用 Python 的 hmac 独立算出的近年时间点向量，防止只在 RFC 老向量上“碰巧正确”。
    #[test]
    fn matches_reference_implementation_at_modern_timestamps() {
        for (secret, at, expected) in [
            ("JBSWY3DPEHPK3PXP", 1_763_000_000.0, "038828"),
            ("JBSWY3DPEHPK3PXP", 1_800_000_000.0, "309848"),
            ("JBSWY3DPEHPK3PXP", 1_234_567_890.0, "742275"),
            (RFC_SECRET, 1_763_000_000.0, "049232"),
            (RFC_SECRET, 1_800_000_000.0, "768147"),
        ] {
            assert_eq!(code(secret, at).unwrap(), expected, "{secret} @ {at}");
        }
    }

    #[test]
    fn codes_are_computed_from_wall_clock_time() {
        let at = now();
        assert!((1_500_000_000.0..4_100_000_000.0).contains(&at), "now() 应给出 2017 年之后的 Unix 时间：{at}");
        assert!((0.0..=PERIOD as f64).contains(&remaining(at)), "剩余时间应落在 0..=30 秒");
        let real = code(RFC_SECRET, at).unwrap();
        assert_ne!(real, code(RFC_SECRET, 5.0).unwrap(), "进程运行时长不能当作 TOTP 时间");
    }

    #[test]
    fn windows_align_the_code_with_the_bar() {
        for at in [0.0, 0.05, 12.5, 29.9, 29.999, 30.0, 30.05, 59.9, 1234567890.05] {
            let (counter, left) = window(at);
            assert!(left > 0.0 && left <= PERIOD as f64, "{at} 的剩余秒 {left} 应在 (0,30]");
            let expected_left = PERIOD as f64 - (at - counter as f64 * PERIOD as f64);
            assert!((left - expected_left).abs() < 1e-9, "{at} 的剩余秒应直接由窗口起点得出");
            assert_eq!(code(RFC_SECRET, at), code(RFC_SECRET, counter as f64 * PERIOD as f64), "{at} 的码必须与窗口起点一致");
        }
        // 同一秒内码不变、条继续退；跨到下一个整秒才换码。
        assert_eq!(code(RFC_SECRET, 29.0), code(RFC_SECRET, 29.9));
        assert_ne!(code(RFC_SECRET, 29.9), code(RFC_SECRET, 30.0));
        assert!(remaining(29.9) < remaining(29.0));
    }

    #[test]
    fn codes_roll_on_the_thirty_second_boundary() {
        assert_eq!(code(RFC_SECRET, 29.0), code(RFC_SECRET, 0.0));
        assert_ne!(code(RFC_SECRET, 29.999), code(RFC_SECRET, 30.0));
        assert_eq!(remaining(0.0), 30.0);
        assert_eq!(remaining(29.0), 1.0);
        assert_eq!(remaining(30.0), 30.0);
        assert_eq!(remaining(59.0), 1.0);
        // 同一秒内也要连续变化，进度条才不会每秒跳一格。
        assert!((remaining(29.25) - 0.75).abs() < 1e-9);
        assert!((remaining(29.75) - 0.25).abs() < 1e-9);
        assert!(remaining(29.0) > remaining(29.5), "时间越往后，剩余越少");
    }

    #[test]
    fn secrets_accept_spaced_lowercase_base32() {
        assert_eq!(normalize_secret("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap(), RFC_SECRET);
        assert_eq!(normalize_secret("JBSWY3DPEHPK3PXP").unwrap(), "JBSWY3DPEHPK3PXP");
        assert!(normalize_secret("").is_err());
        assert!(normalize_secret("ABC1").is_err(), "1 不是合法 Base32 字符");
        assert_eq!(base32_decode("JBSWY3DP").unwrap(), b"Hello".to_vec());
    }

    #[test]
    fn display_splits_six_digits_without_changing_the_value() {
        assert_eq!(display("123456"), "123 456");
        assert_eq!(display("12345"), "12345");
    }

    #[test]
    fn otpauth_uri_carries_issuer_label_and_secret() {
        let (issuer, label, secret) = parse_uri("otpauth://totp/GitHub%3Azephyr?secret=JBSWY3DPEHPK3PXP&issuer=GitHub").unwrap();
        assert_eq!((issuer.as_str(), label.as_str()), ("GitHub", "zephyr"));
        assert_eq!(secret, "JBSWY3DPEHPK3PXP");
        // issuer 只在链接参数里出现时也能识别。
        let (issuer, label, _) = parse_uri("otpauth://totp/zephyr@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example").unwrap();
        assert_eq!((issuer.as_str(), label.as_str()), ("Example", "zephyr@example.com"));
        // 不带 issuer 也能添加。
        let (issuer, label, _) = parse_uri("otpauth://totp/zephyr@example.com?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!((issuer.as_str(), label.as_str()), ("", "zephyr@example.com"));
    }

    #[test]
    fn otpauth_uri_rejects_unsupported_parameters() {
        assert!(parse_uri("https://example.com").unwrap_err().contains("otpauth"));
        assert!(parse_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8").unwrap_err().contains("6 位"));
        assert!(parse_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=60").unwrap_err().contains("30 秒"));
        assert!(parse_uri("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256").unwrap_err().contains("SHA1"));
        assert!(parse_uri("otpauth://totp/x?issuer=GitHub").unwrap_err().contains("secret"));
    }

    #[test]
    fn accounts_json_round_trips_and_ignores_junk() {
        let items = vec![
            Account { id: "totp-1".into(), issuer: "GitHub".into(), label: "zephyr".into() },
            Account { id: "totp-2".into(), issuer: "".into(), label: "mail@example.com".into() },
        ];
        let raw = encode_accounts(&items);
        assert_eq!(decode_accounts(&raw), items);
        assert!(decode_accounts(b"not json").is_empty());
        assert!(decode_accounts(b"[{\"issuer\":\"x\"}]").is_empty(), "缺少 id 的记录要丢弃");
        assert!(decode_accounts(b"[{\"id\":\"a\",\"issuer\":\"\",\"label\":\"\"}]").is_empty(), "空账号要丢弃");
    }

    #[test]
    fn vault_reports_missing_and_invalid_secrets_without_panicking() {
        let account = Account { id: "totp-x".into(), issuer: "GitHub".into(), label: "zephyr".into() };
        let vault = Vault { accounts: vec![account.clone()], secrets: HashMap::new() };
        assert!(vault.code(&account, 59.0).unwrap_err().contains("没有保存"));
        let mut broken = Vault::default();
        broken.remember("totp-x", "ABC1");
        assert!(broken.code(&account, 59.0).unwrap_err().contains("无法解析"));
    }

    #[test]
    fn vault_add_validates_before_touching_the_credential_manager() {
        let mut vault = Vault::default();
        assert!(vault.add("GitHub", "", RFC_SECRET).unwrap_err().contains("账号"));
        assert!(vault.add("GitHub", "zephyr", "ABC1").unwrap_err().contains("A–Z"));
        assert!(vault.accounts.is_empty());
    }
}
