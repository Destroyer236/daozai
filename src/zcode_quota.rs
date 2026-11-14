use super::{Account, Snapshot, Window};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::{aead,digest};
use serde_json::Value;
use std::{io::Read,path::{Path,PathBuf}};

pub(crate) fn path()->Option<PathBuf>{
    Some(PathBuf::from(std::env::var_os("USERPROFILE")?).join(".zcode/v2/credentials.json"))
}
const V2_SECRET_ENV:&str="ZCODE_CREDENTIAL_SECRET";
/// v2 凭据在 Windows 凭据管理器里的服务名；账户名是凭据文件绝对路径的 SHA-256。
const OS_SERVICE:&str="ZCode Credential Encryption";
const UNREADABLE:&str="无法读取 ZCode 登录凭据，请在客户端重新登录";

fn hex(bytes:&[u8])->String{bytes.iter().map(|b|format!("{b:02x}")).collect()}
fn b64(text:&str)->Option<Vec<u8>>{
    let text=text.trim().trim_end_matches('=');
    (!text.is_empty()).then(||URL_SAFE_NO_PAD.decode(text).ok()).flatten()
}
/// 密钥指纹：sha256(密钥) 前 12 字节的十六进制，对应 `enc:v2:os:` 里的 24 位前缀。
fn fingerprint(key:&[u8])->String{let digest=digest::digest(&digest::SHA256,key);hex(&digest.as_ref()[..12])}
fn open(key:&[u8],iv:&[u8],tag:&[u8],cipher:&[u8])->Option<String>{
    if key.len()!=32||iv.len()!=12||tag.len()!=16{return None;}
    let mut bytes=cipher.to_vec();bytes.extend_from_slice(tag);
    let key=aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM,key).ok()?);
    let plain=key.open_in_place(aead::Nonce::try_assume_unique_for_key(iv).ok()?,aead::Aad::empty(),&mut bytes).ok()?;
    std::str::from_utf8(plain).ok().map(str::to_owned)
}
/// v2 明文格式：`<来源>:<密钥指纹>:<iv>.<tag>.<密文>`，三段都是无填充 base64url。
/// 来源 `os` 的密钥在 Windows 凭据管理器（客户端 2026-11 起的默认），`env` 为环境变量。
fn open_v2(body:&str,keys:&[Vec<u8>])->Result<String,String>{
    let mut parts=body.splitn(3,':');
    let (Some(source),Some(expected),Some(payload))=(parts.next(),parts.next(),parts.next()) else{return Err(UNREADABLE.into());};
    if !matches!(source,"os"|"env"){return Err(UNREADABLE.into());}
    let parts=payload.split('.').map(b64).collect::<Option<Vec<_>>>().ok_or(UNREADABLE)?;
    let [iv,tag,cipher]=parts.as_slice() else{return Err(UNREADABLE.into());};
    keys.iter().filter(|key|fingerprint(key)==expected).find_map(|key|open(key,iv,tag,cipher)).ok_or_else(||UNREADABLE.into())
}
fn decode_v2(body:&str,path:Option<&Path>)->Result<String,String>{open_v2(body,&key_candidates(path))}
#[cfg(windows)]
fn utf16(bytes:&[u8])->Option<String>{
    if bytes.len()%2!=0{return None;}
    let units:Vec<u16>=bytes.chunks_exact(2).map(|c|u16::from_le_bytes([c[0],c[1]])).collect();
    let text=String::from_utf16(&units).ok()?.trim_end_matches('\0').to_owned();
    (!text.is_empty()).then_some(text)
}
/// 凭据管理器条目的账户名按客户端 `path.resolve` 的结果计算：绝对化并统一用反斜杠。
#[cfg(windows)]
fn full_name(path:&Path)->String{
    let absolute=std::path::absolute(path).unwrap_or_else(|_|path.to_path_buf());
    absolute.to_string_lossy().replace('/',"\\")
}
/// 读 Windows 凭据管理器里的 ZCode 加密密钥；读不到返回 None，最终由指纹校验决定是否可用。
#[cfg(windows)]
fn keyring_secret(path:&Path)->Option<String>{
    use windows::core::HSTRING;
    use windows::Win32::Security::Credentials::{CredFree,CredReadW,CREDENTIALW,CRED_TYPE_GENERIC};
    let name=hex(digest::digest(&digest::SHA256,full_name(path).as_bytes()).as_ref());
    let target=format!("{name}.{OS_SERVICE}");
    let mut credential:*mut CREDENTIALW=std::ptr::null_mut();
    unsafe{CredReadW(&HSTRING::from(target.as_str()),CRED_TYPE_GENERIC,0,&mut credential).ok()?};
    let cred=unsafe{&*credential};
    let bytes=unsafe{std::slice::from_raw_parts(cred.CredentialBlob,cred.CredentialBlobSize as usize)};
    let text=utf16(bytes).or_else(||std::str::from_utf8(bytes).ok().map(|s|s.trim_end_matches('\0').to_owned()).filter(|s|!s.is_empty()));
    unsafe{CredFree(credential as *const _)};
    text
}
#[cfg(not(windows))]
fn keyring_secret(_path:&Path)->Option<String>{None}
/// 候选密钥：环境变量、凭据文件旁的 credential-secret、以及 Windows 凭据管理器。
/// 每条原始秘密按 base64url 解码与 sha256 两种方式派生，再由指纹挑出正确的一条。
fn key_candidates(path:Option<&Path>)->Vec<Vec<u8>>{
    let mut secrets=Vec::new();
    if let Some(secret)=std::env::var(V2_SECRET_ENV).ok().filter(|s|!s.trim().is_empty()){secrets.push(secret);}
    if let Some(path)=path{
        if let Ok(text)=std::fs::read_to_string(path.with_file_name("credential-secret")){
            let text=text.trim().to_owned();
            if (32..=4096).contains(&text.len()){secrets.push(text);}
        }
        if let Some(text)=keyring_secret(path){secrets.push(text);}
    }
    let mut keys=Vec::new();
    for secret in secrets{
        let secret=secret.trim();
        if let Some(key)=b64(secret){keys.push(key);}
        keys.push(digest::digest(&digest::SHA256,secret.as_bytes()).as_ref().to_vec());
    }
    keys
}
fn decode_v1(encoded:&str)->Result<String,String>{
    let secret=std::env::var(V2_SECRET_ENV).ok().filter(|s|!s.trim().is_empty()).unwrap_or_else(||format!(
        "zcode-credential-fallback:win32:{}:{}",std::env::var("USERPROFILE").unwrap_or_default(),std::env::var("USERNAME").unwrap_or_default()));
    let key=digest::digest(&digest::SHA256,secret.trim().as_bytes());
    let error="无法读取当前 Windows 用户的 ZCode 登录，请在客户端重新登录";
    let parts=encoded.split('.').map(b64).collect::<Option<Vec<_>>>().ok_or(error)?;
    let [iv,tag,cipher]=parts.as_slice() else{return Err(error.into());};
    open(key.as_ref(),iv,tag,cipher).ok_or_else(||error.into())
}
fn value(root:&Value,name:&str,path:Option<&Path>)->Result<String,String>{
    let raw=root[name].as_str().ok_or("请先在 ZCode 中登录个人账号")?;
    if let Some(body)=raw.strip_prefix("enc:v2:"){return decode_v2(body,path);}
    if let Some(encoded)=raw.strip_prefix("enc:v1:"){return decode_v1(encoded);}
    Ok(raw.into())
}
struct Login { family:String, slot:String, subject:String, jwt:String }
fn login(root:&Value,path:&Path)->Result<Login,String>{
    let family=value(root,"oauth:active_provider",Some(path))?;
    if !matches!(family.as_str(),"zai"|"bigmodel"){return Err(format!("暂不支持 ZCode 登录区域「{family}」"));}
    let jwt=value(root,"zcodejwttoken",Some(path))?;
    let payload=jwt.split('.').nth(1).and_then(|s|URL_SAFE_NO_PAD.decode(s).ok()).and_then(|s|serde_json::from_slice::<Value>(&s).ok()).ok_or("ZCode 账号标识无效")?;
    let id=payload["sub"].as_str().or_else(||payload["user_id"].as_str()).ok_or("ZCode 未返回账号标识")?;
    let slot=digest::digest(&digest::SHA256,format!("{family}/{id}").as_bytes()).as_ref().iter().map(|b|format!("{b:02x}")).collect();
    Ok(Login{family,slot,subject:id.to_owned(),jwt})
}
pub(crate) fn add(config:&mut super::Config,path:&Path,alias:&str)->Result<(),String>{
    let l=login(&super::login_json(path)?,path)?;
    if config.accounts.iter().any(|a|a.provider==super::Provider::ZCode&&a.slot.as_ref()==Some(&l.slot)){return Ok(());}
    config.accounts.push(Account{id:format!("ZCode-{}",l.slot),provider:super::Provider::ZCode,alias:if alias.trim().is_empty(){"智谱 ZCode".into()}else{alias.trim().into()},source:path.to_owned(),slot:Some(l.slot),enabled:true,pinned:false});Ok(())
}
fn read(agent:&ureq::Agent,url:&str,auth:&str,device_mid:Option<&str>)->Result<Value,String>{
    let mut request=agent.get(url).set("Authorization",auth).set("Accept","application/json");
    if let Some(mid)=device_mid{request=request.set("X-Device-Mid",mid);}
    let response=request.call().map_err(|e|match e{
        ureq::Error::Status(401|403,_)=>"ZCode 授权被拒绝，请在客户端确认登录".into(),
        ureq::Error::Status(code,_)=>format!("ZCode 用量服务返回 {code}"),
        _=>"无法连接 ZCode 用量服务".into(),
    })?;
    serde_json::from_reader(response.into_reader().take(1024*1024)).map_err(|_|"ZCode 用量响应无效".into())
}
fn success(v:&Value)->bool{ matches!(v["code"].as_i64(),Some(0|200)) || (v["code"].is_null()&&v["success"]==true) }
pub(super) fn coding(v:&Value)->Result<Snapshot,String>{
    let mut snapshot=Snapshot{plan:"Coding Plan".into(),at:chrono::Utc::now().timestamp(),..Default::default()};
    for row in v["data"]["limits"].as_array().into_iter().flatten(){
        let Some(used)=super::number(&row["percentage"]).filter(|v|(0.0..=100.0).contains(v)) else{continue;};
        let multiplier=match row["unit"].as_i64(){Some(1)=>Some(86400),Some(3)=>Some(3600),Some(5)=>Some(60),Some(6)=>Some(604800),_=>None};
        let seconds=row["number"].as_i64().filter(|n|*n>0).zip(multiplier).and_then(|(n,m)|n.checked_mul(m));
        let kind=row["type"].as_str().unwrap_or_default();
        let label=if kind=="TIME_LIMIT"{"工具调用".into()}else{super::cadence(seconds)};
        let reset=row["nextResetTime"].as_i64().filter(|x|*x>0).map(|x|if x>10_000_000_000{x/1000}else{x});
        let window=Window{starts_on_use:false,label,seconds,remaining:(100.0-used) as f32,reset,amount:None};
        match kind{"TOKENS_LIMIT"|"CREDIT_LIMIT"=>snapshot.windows.push(window),"TIME_LIMIT"=>snapshot.extra.push(window),_=>{}}
    }
    if snapshot.windows.is_empty(){std::mem::swap(&mut snapshot.windows,&mut snapshot.extra);}
    if snapshot.windows.is_empty(){return Err("ZCode 未提供可显示的套餐比例".into());}
    Ok(snapshot)
}
fn start(v:&Value)->Result<Snapshot,String>{
    let mut snapshot=Snapshot{plan:"Start Plan".into(),at:chrono::Utc::now().timestamp(),..Default::default()};
    let buckets=v["data"]["balances"].as_array().ok_or("ZCode 响应缺少体验额度明细")?;
    if buckets.is_empty(){snapshot.plan="暂无体验额度".into();return Ok(snapshot);}
    for bucket in buckets{
        let Some(total)=super::number(&bucket["total_units"]).filter(|n|*n>0.0) else{continue;};
        let Some(left)=super::number(&bucket["remaining_units"]).filter(|n|*n>=0.0) else{continue;};
        let reset=super::number(&bucket["expires_at"]).map(|n|n as i64);
        if reset.is_some_and(|t|t<=snapshot.at){continue;}
        snapshot.windows.push(Window{starts_on_use:false,label:bucket["show_name"].as_str().filter(|s|!s.is_empty()).unwrap_or("体验额度").into(),seconds:None,remaining:(left/total*100.0).clamp(0.0,100.0) as f32,reset,amount:None});
    }
    if snapshot.windows.is_empty(){return Err("当前 ZCode 账号暂无有效体验额度".into());}
    Ok(snapshot)
}
pub(super) fn fetch(agent:&ureq::Agent,a:&Account)->Result<Snapshot,String>{
    let root=super::login_json(&a.source)?;let l=login(&root,&a.source)?;
    if a.slot.as_ref()!=Some(&l.slot){return Err("ZCode 已切换账号，请重新识别本机账号".into());}
    let key=format!("account-provider:coding-plan:account:{}-individual-coding-plan:account:{}:api-key",l.family,l.subject);
    let mut no_coding_plan=false;
    if root.get(&key).is_some(){
        let url=if l.family=="zai"{"https://api.z.ai/api/monitor/usage/quota/limit"}else{"https://bigmodel.cn/api/monitor/usage/quota/limit"};
        let v=read(agent,url,&value(&root,&key,Some(&a.source))?,None)?;
        if success(&v){return coding(&v);}
        let msg=v["msg"].as_str().or_else(||v["message"].as_str()).unwrap_or("").to_lowercase();
        if !(msg.contains("不存在coding plan")||msg.contains("不存在 coding plan")||msg.contains("no coding plan")){return Err(format!("ZCode 编程套餐查询失败（{}）",v["code"]));}
        no_coding_plan=true;
    }
    let mut url=url::Url::parse("https://zcode.z.ai/api/v1/zcode-plan/billing/balance").unwrap();
    // 客户端按版本发布运行时，官网使用 app_version 判断体验套餐能力。
    if let Some(runtime)=a.source.parent().map(|p|p.join("runtime/provider/windows-x86_64")){
        let versions=std::fs::read_dir(runtime).into_iter().flatten().flatten().filter_map(|dir|{
            let name=dir.file_name().into_string().ok()?;
            let parts=name.split('.').map(str::parse::<u32>).collect::<Result<Vec<_>,_>>().ok()?;
            (parts.len()==3).then_some((parts,name))
        });
        if let Some((_,v))=versions.max(){url.query_pairs_mut().append_pair("app_version",&v);}
    }
    let telemetry=a.source.with_file_name("telemetry-state.json");
    let device=super::login_json(&telemetry).ok();
    let mid=device.as_ref().and_then(|v|v["deviceMid"].as_str()).filter(|s|!s.is_empty() && s.bytes().all(|b|b.is_ascii_graphic())).ok_or("请打开 ZCode，等待客户端初始化设备信息")?;
    let v=read(agent,url.as_str(),&format!("Bearer {}",l.jwt),Some(mid)).map_err(|e|if no_coding_plan{format!("未开通 Coding Plan；体验套餐查询失败：{e}")}else{e})?;
    if !success(&v){return Err(format!("ZCode 体验额度暂不可用（{}）",v["code"]));}
    start(&v)
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn empty_entitlements_are_valid_but_missing_data_is_an_error(){
        assert!(start(&serde_json::json!({"data":{"balances":[]}})).unwrap().windows.is_empty());
        assert!(start(&serde_json::json!({"data":{}})).is_err());
    }
    #[test]fn zcode_distinguishes_used_percentage_and_remaining_units(){
        let c=coding(&serde_json::json!({"data":{"limits":[{"type":"TOKENS_LIMIT","percentage":31,"unit":3,"number":5,"nextResetTime":1900000000000i64}]}})).unwrap();
        assert_eq!(c.windows[0].remaining,69.0);assert_eq!(c.windows[0].reset,Some(1900000000));
        let s=start(&serde_json::json!({"data":{"balances":[{"total_units":"800","remaining_units":"200","available_units":"100"}]}})).unwrap();assert_eq!(s.windows[0].remaining,25.0);
    }
    /// 造一条与客户端 v2 信封同格式的记录（来源、指纹、iv、tag、密文都能伪造，密钥除外）。
    fn seal(key:&[u8],text:&str)->String{
        let iv=[0x24u8;12];
        let cipher=aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM,key).unwrap());
        let mut bytes=text.as_bytes().to_vec();
        let tag=cipher.seal_in_place_separate_tag(aead::Nonce::assume_unique_for_key(iv),aead::Aad::empty(),&mut bytes).unwrap();
        format!("enc:v2:os:{}:{}.{}.{}",fingerprint(key),URL_SAFE_NO_PAD.encode(iv),URL_SAFE_NO_PAD.encode(tag.as_ref()),URL_SAFE_NO_PAD.encode(&bytes))
    }
    fn body(envelope:&str)->&str{envelope.strip_prefix("enc:v2:").unwrap()}
    #[test]fn v2_os_envelope_decrypts_with_the_matching_key(){
        let envelope=seal(&[7u8;32],"zai");
        assert_eq!(open_v2(body(&envelope),&[[7u8;32].to_vec()]).unwrap(),"zai");
    }
    #[test]fn v2_os_envelope_rejects_a_key_with_another_fingerprint(){
        let envelope=seal(&[7u8;32],"zai");
        assert!(open_v2(body(&envelope),&[[9u8;32].to_vec()]).is_err(),"指纹不符的密钥不能解密");
    }
    #[test]fn v2_envelope_from_an_unknown_source_is_not_trusted(){
        let envelope=seal(&[7u8;32],"zai").replace("enc:v2:os:","enc:v2:file:");
        assert!(open_v2(body(&envelope),&[[7u8;32].to_vec()]).is_err(),"只接受 os / env 两种来源");
        assert!(open_v2("os:386d7eebed21d0c0f0ceb4b7:dymZIgQp8Ty_gcw2.",&[]).is_err(),"缺少 tag / 密文的记录应拒绝");
    }
    #[test]fn plain_values_and_v1_are_still_readable(){
        let root=serde_json::json!({"zcodejwttoken":"a.b.c"});
        assert_eq!(value(&root,"zcodejwttoken",None).unwrap(),"a.b.c");
    }
    /// 读本机真实登录，验证 `enc:v2:os:` 能解开；没有本机账号时直接跳过。
    #[cfg(windows)]
    #[test]
    #[ignore="读取本机真实 ZCode 登录，需要时手动运行"]
    fn local_zcode_login_is_readable(){
        let Some(path)=path().filter(|p|p.is_file()) else{return;};
        let root=super::super::login_json(&path).unwrap();
        let l=match login(&root,&path){Ok(l)=>l,Err(e)=>panic!("{}（凭据条目 {}）",e,full_name(&path))};
        assert!(matches!(l.family.as_str(),"zai"|"bigmodel"),"登录区域应可读");
        assert!(!l.subject.is_empty()&&!l.jwt.is_empty());assert_eq!(l.slot.len(),64);
    }
}
