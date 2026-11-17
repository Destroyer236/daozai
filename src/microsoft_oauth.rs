//! Microsoft（Outlook / Hotmail / Microsoft 365）的登录：授权码 + PKCE + 本机回环。
//!
//! 只申请收信所需的 IMAP 委托权限（`IMAP.AccessAsUser.All`），不走 Microsoft Graph：
//! 换到的 access token 通过 IMAP 的 `AUTHENTICATE XOAUTH2` 交给 `outlook.office365.com`。
//! 凭据只保存 refresh token，和其它邮箱一样进 Windows 凭据管理器。

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use serde_json::Value;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

/// 应用注册（Microsoft Entra）里的客户端 ID。公共客户端，没有密钥。
pub const CLIENT_ID: &str = "0f9e7438-eeb1-46fb-a9be-d184a2b3c935";
const AUTHORIZE: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
const TOKEN: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
/// 只收信：IMAP 委托权限，加上取地址用的 openid/email。
const SCOPE: &str = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access openid email profile";
/// 用户在浏览器里登录的等待上限。
const WAIT: Duration = Duration::from_secs(300);
const PAGE: &str = "<!doctype html><meta charset=\"utf-8\"><title>岛仔</title>\
                     <body style=\"font:16px/1.6 system-ui;padding:40px\">岛仔：Microsoft 登录完成，可以关闭这个窗口回到岛仔。";

/// 一次成功的登录：账号地址与 refresh token。
pub struct SignedIn {
    pub email: String,
    pub refresh: String,
}

/// 已经开好回调端口、等浏览器回来的登录。
pub struct Pending {
    listener: TcpListener,
    redirect: String,
    state: String,
    verifier: String,
    url: String,
}

impl Pending {
    /// 交给系统浏览器打开的地址。
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// 开回调端口并拼出授权地址。`hint` 只是预填账号，用户仍可在浏览器里换账号。
pub fn begin(hint: &str) -> Result<Pending, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| format!("无法打开本机回调端口：{e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("回调端口不可用：{e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("回调端口不可用：{e}"))?
        .port();
    let redirect = format!("http://localhost:{port}");
    let state = random()?;
    let verifier = random()?;
    let challenge = URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, verifier.as_bytes()));
    let mut query = vec![
        ("client_id", CLIENT_ID.to_string()),
        ("response_type", "code".to_string()),
        ("redirect_uri", redirect.clone()),
        ("scope", SCOPE.to_string()),
        ("state", state.clone()),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256".to_string()),
        ("prompt", "select_account".to_string()),
    ];
    if !hint.trim().is_empty() {
        query.push(("login_hint", hint.trim().to_string()));
    }
    let url = format!(
        "{AUTHORIZE}?{}",
        query
            .iter()
            .map(|(key, value)| format!("{}={}", escape(key), escape(value)))
            .collect::<Vec<_>>()
            .join("&")
    );
    Ok(Pending { listener, redirect, state, verifier, url })
}

/// 阻塞等待浏览器回到本机，再用授权码换 token。由后台线程调用。
pub fn wait(pending: Pending) -> Result<SignedIn, String> {
    let deadline = Instant::now() + WAIT;
    loop {
        if Instant::now() >= deadline {
            return Err("登录等待超时，请重新点「用浏览器登录 Microsoft」".into());
        }
        match pending.listener.accept() {
            Ok((mut stream, _)) => {
                let Some(target) = target(&mut stream) else { continue };
                let query = target.split_once('?').map_or("", |(_, query)| query);
                let pair = |name: &str| {
                    url::form_urlencoded::parse(query.as_bytes())
                        .find(|(key, _)| key == name)
                        .map(|(_, value)| value.into_owned())
                };
                let code = pair("code");
                let error = pair("error");
                if code.is_none() && error.is_none() {
                    // 浏览器顺手请求的 favicon 等，回 404 继续等。
                    reply(&mut stream, "404 Not Found", "");
                    continue;
                }
                reply(&mut stream, "200 OK", PAGE);
                if pair("state").as_deref() != Some(pending.state.as_str()) {
                    return Err("回调缺少一致的 state，已中止这次登录".into());
                }
                if let Some(error) = error {
                    let detail = pair("error_description").unwrap_or_default();
                    return Err(if detail.is_empty() { error } else { format!("{error}：{detail}") });
                }
                let code = code.ok_or("回调里没有授权码")?;
                return exchange(&code, &pending.verifier, &pending.redirect);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(80));
            }
            Err(error) => return Err(format!("回调端口异常：{error}")),
        }
    }
}

/// 主进程用的 access token：同一个账号在有效期内复用，避免每次同步都换一次。
pub fn access_token(email: &str, refresh: &str) -> Result<String, String> {
    let key = email.trim().to_ascii_lowercase();
    if let Ok(map) = cache().lock() {
        if let Some((token, expiry)) = map.get(&key) {
            if *expiry > Instant::now() + Duration::from_secs(60) {
                return Ok(token.clone());
            }
        }
    }
    let tokens = renew(refresh)?;
    if let Some(next) = &tokens.refresh {
        // 微软会轮换 refresh token；写回凭据管理器，旧的就作废。写失败时下次仍能用旧值重试登录。
        let _ = crate::mail::secrets::save(&key, next);
    }
    if let Ok(mut map) = cache().lock() {
        map.insert(key, (tokens.access.clone(), Instant::now() + tokens.expires));
    }
    Ok(tokens.access)
}

/// XOAUTH2 的 SASL 初始响应（base64 之前）。
pub fn sasl(user: &str, token: &str) -> String {
    format!("user={user}\x01auth=Bearer {token}\x01\x01")
}

struct Tokens {
    access: String,
    refresh: Option<String>,
    email: Option<String>,
    expires: Duration,
}

fn cache() -> &'static Mutex<HashMap<String, (String, Instant)>> {
    static CACHE: OnceLock<Mutex<HashMap<String, (String, Instant)>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn exchange(code: &str, verifier: &str, redirect: &str) -> Result<SignedIn, String> {
    let tokens = request(&[
        ("grant_type", "authorization_code"),
        ("client_id", CLIENT_ID),
        ("code", code),
        ("code_verifier", verifier),
        ("redirect_uri", redirect),
    ])?;
    let refresh = tokens.refresh.ok_or("微软没有下发 refresh token，请重新登录")?;
    Ok(SignedIn { email: tokens.email.unwrap_or_default(), refresh })
}

fn renew(refresh: &str) -> Result<Tokens, String> {
    request(&[
        ("grant_type", "refresh_token"),
        ("client_id", CLIENT_ID),
        ("refresh_token", refresh),
    ])
}

/// 表单 POST 到 token 端点；非 200 时把微软的 error/error_description 原样带出来。
fn request(form: &[(&str, &str)]) -> Result<Tokens, String> {
    let agent: ureq::Agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(30))
        .build();
    let (status, body) = match agent.post(TOKEN).send_form(form) {
        Ok(response) => {
            let status = response.status();
            let body = response.into_string().map_err(|e| format!("读取微软登录响应失败：{e}"))?;
            (status, body)
        }
        Err(ureq::Error::Status(status, response)) => {
            let body = response.into_string().unwrap_or_default();
            (status, body)
        }
        Err(error) => return Err(format!("连接微软登录服务失败：{error}")),
    };
    let value: Value = serde_json::from_str(&body)
        .map_err(|_| format!("微软登录服务返回了无法识别的内容（HTTP {status}）"))?;
    if status != 200 {
        let error = value["error"].as_str().unwrap_or("sign_in_failed");
        let reason = value["error_description"].as_str().unwrap_or_default();
        let reason = reason.split('\n').next().unwrap_or_default();
        return Err(if reason.is_empty() {
            format!("微软拒绝登录（HTTP {status}，{error}）")
        } else {
            format!("微软拒绝登录：{reason}")
        });
    }
    Ok(Tokens {
        access: value["access_token"].as_str().ok_or("微软没有下发 access token")?.to_string(),
        refresh: value["refresh_token"].as_str().map(str::to_string),
        email: value["id_token"].as_str().and_then(claim),
        expires: Duration::from_secs(value["expires_in"].as_u64().unwrap_or(3600)),
    })
}

/// id_token 的地址声明。令牌是刚从 token 端点拿到的，这里只取用、不验签。
fn claim(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let value: Value = serde_json::from_slice(&bytes).ok()?;
    value["email"]
        .as_str()
        .or_else(|| value["preferred_username"].as_str())
        .map(|address| address.to_string())
}

fn random() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "无法生成安全随机数")?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// 只在授权的 query 上调用：除 unreserved 之外一律百分号编码。
fn escape(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// 读一个 GET 的请求行；其它请求或读不到时返回 None。
fn target(stream: &mut TcpStream) -> Option<String> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut head = Vec::new();
    let mut chunk = [0u8; 512];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(count) => head.extend_from_slice(&chunk[..count]),
        }
        if head.len() > 8192 {
            return None;
        }
    }
    let line = head.split(|byte| *byte == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim_end();
    let mut parts = line.split(' ');
    match (parts.next(), parts.next()) {
        (Some("GET"), Some(route)) => Some(route.to_string()),
        _ => None,
    }
}

fn reply(stream: &mut TcpStream, status: &str, body: &str) {
    let text = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(text.as_bytes());
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_values_are_percent_encoded() {
        assert_eq!(escape("a b/c&d=é~"), "a%20b%2Fc%26d%3D%C3%A9~");
    }

    #[test]
    fn sasl_initial_response_matches_xoauth2() {
        assert_eq!(sasl("user@outlook.com", "tok-1"), "user=user@outlook.com\u{1}auth=Bearer tok-1\u{1}\u{1}");
    }

    #[test]
    fn begin_opens_a_loopback_redirect_with_pkce() {
        let pending = begin("user@outlook.com").expect("本机端口应可用");
        let url = pending.url();
        assert!(url.starts_with(AUTHORIZE), "{url}");
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A"), "{url}");
        assert!(url.contains("code_challenge_method=S256"), "{url}");
        assert!(url.contains("login_hint=user%40outlook.com"), "{url}");
        assert!(url.contains(&format!("state={}", pending.state)), "{url}");
        assert_eq!(pending.state.len(), 43, "32 字节的 base64url 应无填充");
        assert_eq!(pending.verifier.len(), 43);
    }
}
