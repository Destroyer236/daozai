//! Cursor 会员额度。直接读取本机 Cursor 客户端的登录态，不再走浏览器授权：
//! `%APPDATA%\Cursor\User\globalStorage\state.vscdb` 里 `cursorAuth/accessToken`
//! 是 `cursor-safe-storage:v1:` 密封串，用 `Local State` 的 Chromium OSCrypt 主密钥
//! （DPAPI 解保护）走 AES-256-GCM 解封，再带 Bearer 调
//! `api2.cursor.sh` 的 DashboardService/GetCurrentPeriodUsage。
//! 令牌只进 Windows 凭据管理器，不写配置文件。
use super::{Account,Snapshot,Window};
use base64::{engine::general_purpose::{STANDARD,URL_SAFE_NO_PAD},Engine};
use ring::digest;
use serde_json::Value;
use std::{collections::HashMap,io::Read,path::{Path,PathBuf},sync::mpsc};

const BACKEND:&str="https://api2.cursor.sh";
const SAFE_PREFIX:&str="cursor-safe-storage:v1:";
/// 缺省的客户端版本；本机装了 Cursor 时会读到真实版本。
const FALLBACK_VERSION:&str="0.48.0";
const AUTH_ERROR:&str="Cursor 登录已失效，请在 Cursor 客户端重新登录";
const NOT_LOCAL:&str="本机没有找到 Cursor 登录，请先在 Cursor 客户端登录";
const BLOCKED:&str="无法连接 Cursor 服务，请检查网络或代理设置";

/// 手动粘贴时的规范化：去掉 Cookie 名、取分号前的值，并还原 `%3A` 这类百分号编码。
pub(crate) fn normalize(raw:&str)->String{
    let mut text=raw.trim().to_owned();
    if let Some((_,rest))=text.split_once("WorkosCursorSessionToken="){text=rest.split(';').next().unwrap_or_default().trim().to_owned();}
    percent_decode(&text)
}
fn percent_decode(text:&str)->String{
    let mut out=String::new();let mut chars=text.chars().peekable();
    while let Some(c)=chars.next(){
        if c=='%'{
            let pair:String=chars.by_ref().take(2).collect();
            if let Ok(byte)=u8::from_str_radix(&pair,16){out.push(byte as char);continue;}
            out.push('%');out.push_str(&pair);continue;
        }
        out.push(c);
    }
    out
}
/// `user_xxx::<jwt>` 形式取 JWT 部分；纯 JWT 原样返回。
fn bearer(token:&str)->&str{token.rsplit_once("::").map(|(_,jwt)|jwt).unwrap_or(token)}
fn claims(token:&str)->Option<Value>{
    let payload=bearer(token).split('.').nth(1)?;
    let raw=URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&raw).ok()
}
/// 账号槽位取令牌主体，同一账号换令牌后仍认作同一个账号。
fn slot_of(token:&str)->String{
    let identity=claims(token).and_then(|v|v["sub"].as_str().or_else(||v["user_id"].as_str()).map(str::to_owned)).unwrap_or_else(||bearer(token).to_owned());
    digest::digest(&digest::SHA256,identity.as_bytes()).as_ref().iter().map(|b|format!("{b:02x}")).collect()
}
fn label_of(alias:&str,slot:&str)->String{
    if !alias.trim().is_empty(){return alias.trim().into();}
    load(slot).ok().and_then(|token|claims(&token.access)?.get("email")?.as_str().map(str::to_owned)).map(|email|format!("Cursor · {email}")).unwrap_or_else(||"Cursor".into())
}

#[derive(Default)]
#[derive(serde::Serialize,serde::Deserialize)]
struct Token {#[serde(default)]access:String, #[serde(default)]refresh:String}

#[cfg(windows)]
fn credential(slot:&str)->Result<keyring::Entry,String>{
    if slot.len()!=64||!slot.bytes().all(|b|b.is_ascii_hexdigit()){return Err(AUTH_ERROR.into());}
    keyring::Entry::new("Daozai.Cursor",slot).map_err(|_|"无法打开 Windows 凭据管理器".into())
}
#[cfg(windows)]
fn save(slot:&str,token:&Token)->Result<(),String>{
    let text=serde_json::to_string(token).map_err(|_|"无法序列化 Cursor 登录".to_owned())?;
    credential(slot)?.set_password(&text).map_err(|_|"无法安全保存 Cursor 登录".into())
}
#[cfg(windows)]
fn load(slot:&str)->Result<Token,String>{
    let text=credential(slot)?.get_password().map_err(|_|AUTH_ERROR.to_owned())?;
    serde_json::from_str(&text).map_err(|_|AUTH_ERROR.to_owned())
}
#[cfg(not(windows))]
fn save(_slot:&str,_token:&Token)->Result<(),String>{Err("当前系统暂不支持安全保存 Cursor 登录".into())}
#[cfg(not(windows))]
fn load(_slot:&str)->Result<Token,String>{Err(AUTH_ERROR.to_owned())}
pub fn forget(account:&Account){
    #[cfg(windows)]
    if let Some(slot)=&account.slot{if let Ok(entry)=credential(slot){let _=entry.delete_credential();}}
    #[cfg(not(windows))] let _=account;
}

/// Cursor 的数据目录；`DAOZAI_CURSOR_HOME` 仅供测试覆盖。
fn cursor_home()->PathBuf{
    std::env::var_os("DAOZAI_CURSOR_HOME").map(PathBuf::from).filter(|p|p.is_dir())
        .or_else(||std::env::var_os("APPDATA").map(|base|PathBuf::from(base).join("Cursor")))
        .unwrap_or_default()
}
fn client_version(home:&Path)->String{
    let base=std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(||home.parent().map(Path::to_path_buf).unwrap_or_default());
    for dir in ["Programs/cursor","Programs/Cursor"]{
        let manifest=base.join(dir).join("resources").join("app").join("package.json");
        if let Ok(text)=std::fs::read_to_string(&manifest){
            if let Ok(value)=serde_json::from_str::<Value>(&text){
                if let Some(version)=value["version"].as_str().filter(|v|!v.is_empty()){return version.to_owned();}
            }
        }
    }
    FALLBACK_VERSION.into()
}
/// 客户端的 device id，写在 `<Cursor>/machineid`；请求头里的校验和就是固定前缀加它。
fn machine_id(home:&Path)->Option<String>{
    let id=std::fs::read_to_string(home.join("machineid")).ok()?.trim().to_owned();
    (!id.is_empty()).then_some(id)
}
fn checksum(home:&Path)->Option<String>{machine_id(home).map(|id|format!("00000000{id}"))}

/// 客户端的请求头：类型、版本、隐私位、请求号与校验和。
fn headers(request:ureq::Request,access:Option<&str>)->ureq::Request{
    let home=cursor_home();
    let id=super::grok::uuid();
    let mut request=request.set("x-cursor-client-type","ide").set("x-cursor-client-version",&client_version(&home))
        .set("x-ghost-mode","false").set("x-new-onboarding-completed","false").set("Accept","application/json")
        .set("x-request-id",&id);
    if let Some(sum)=checksum(&home){request=request.set("x-cursor-checksum",&sum);}
    match access{Some(access)=>request.set("Authorization",&format!("Bearer {}",bearer(access))),None=>request}
}
fn read(response:ureq::Response)->Result<Value,String>{
    let mut body=Vec::new();response.into_reader().take(1024*1024+1).read_to_end(&mut body).map_err(|_|String::from("读取 Cursor 响应失败"))?;
    if body.len()>1024*1024{return Err("Cursor 响应过大".into());}
    serde_json::from_slice(&body).map_err(|_|"Cursor 未返回有效数据".into())
}
fn http_error(error:ureq::Error)->(String,u64){match error{
    ureq::Error::Status(401,_)=>(format!("{AUTH_ERROR}；若刚登录过，说明该账号不被官方额度接口接受"),0),
    ureq::Error::Status(403,_)=>("Cursor 拒绝了这次额度请求（403），请确认账号权限".into(),60),
    ureq::Error::Status(429,response)=>("请求过于频繁，稍后自动重试".into(),response.header("Retry-After").and_then(|s|s.parse().ok()).unwrap_or(180).clamp(30,3600)),
    ureq::Error::Status(code,_)=>(format!("Cursor 额度服务暂不可用（{code}）"),60),
    _=>(BLOCKED.into(),30),
}}

fn ts(value:&Value)->Option<i64>{let n=super::reset(value)?;Some(if n>10_000_000_000{n/1000}else{n})}
fn period(v:&Value)->(Option<i64>,Option<i64>){
    let key=|names:[&str;3]|names.iter().find_map(|name|ts(&v[name]));
    (key(["billingCycleStart","currentPeriodStart","cycleStart"]),key(["billingCycleEnd","nextResetTimestampUtc","cycleEnd"]))
}
/// 客户端的百分比口径：0 到 1 之间的小数按 1% 处理，其余夹到 0..100，保留小数供环形绘制。
fn percent(value:&Value)->Option<f64>{
    let used=super::number(value)?;
    Some(if used>0.0&&used<1.0{1.0}else{used.clamp(0.0,100.0)})
}
fn snapshot(v:&Value,used:f64)->Snapshot{
    let(start,reset)=period(v);let seconds=start.zip(reset).and_then(|(a,b)|b.checked_sub(a)).filter(|n|*n>0);
    Snapshot{kiro:None,relay:None,credits:None,wallet:None,antigravity:None,plan:v["displayMessage"].as_str().unwrap_or_default().into(),at:chrono::Utc::now().timestamp(),
        windows:vec![Window{starts_on_use:false,label:super::cadence(seconds),seconds,remaining:(100.0-used).clamp(0.0,100.0) as f32,reset,amount:None}],extra:vec![]}
}
/// 解析 GetCurrentPeriodUsage：优先 total/api/auto 百分比，其次按 limit 与 remaining
/// （单位是美分）折算，最后兼容旧版按模型统计的请求数。
pub fn parse(v:&Value)->Result<Snapshot,String>{
    let root=if v["planUsage"].is_object(){v}else{v.get("data").filter(|d|d.is_object()).unwrap_or(v)};
    let usage=&root["planUsage"];
    let used=percent(&usage["totalPercentUsed"])
        .or_else(||percent(&usage["apiPercentUsed"]))
        .or_else(||percent(&usage["autoPercentUsed"]))
        .or_else(||{let limit=super::number(&usage["limit"])?;let remaining=super::number(&usage["remaining"])?;(limit>0.0).then(||((limit-remaining.min(limit))/limit*100.0).clamp(0.0,100.0))});
    if let Some(used)=used{return Ok(snapshot(root,used));}
    let mut used=0.0;let mut total=0.0;let mut found=false;
    for (key,row) in root.as_object().into_iter().flatten(){
        let Some(all)=super::number(&row["numRequestsTotal"]).filter(|n|*n>0.0) else{continue;};
        let Some(count)=super::number(&row["numRequests"]).filter(|n|*n>=0.0) else{continue;};
        used+=count;total+=all;found|=key.as_str()!="startOfMonth";
    }
    if found{return Ok(snapshot(root,(used/total*100.0).clamp(0.0,100.0)));}
    Err("Cursor 没有返回可显示的套餐额度".into())
}

fn usage(agent:&ureq::Agent,access:&str)->Result<Snapshot,(String,u64)>{
    let request=headers(agent.post(&format!("{BACKEND}/aiserver.v1.DashboardService/GetCurrentPeriodUsage")),Some(access))
        .set("Content-Type","application/json").set("Connect-Protocol-Version","1");
    let value=match request.send_string("{}"){
        Ok(response)=>read(response).map_err(|error|(error,60))?,
        Err(error)=>return Err(http_error(error)),
    };
    parse(&value).map_err(|error|(error,60))
}

/// 读本机 Cursor 登录态：邮箱、套餐、令牌。
struct Local{pub email:String,pub plan:String,pub token:Token}

/// Chromium OSCrypt 主密钥：`Local State` 里的 `os_crypt.encrypted_key` 去掉 `DPAPI`
/// 前缀后由当前 Windows 用户的 DPAPI 解保护，得到 32 字节 AES 密钥。
#[cfg(windows)]
fn master_key(home:&Path)->Result<Vec<u8>,String>{
    let text=std::fs::read_to_string(home.join("Local State")).map_err(|_|"无法读取 Cursor 的加密配置（Cursor 可能没在本机登录过）".to_owned())?;
    let value:Value=serde_json::from_str(&text).map_err(|_|"Cursor 的加密配置已损坏".to_owned())?;
    let encoded=value["os_crypt"]["encrypted_key"].as_str().ok_or_else(||"Cursor 的加密配置缺少密钥".to_owned())?;
    let raw=STANDARD.decode(encoded).map_err(|_|"Cursor 的加密密钥格式异常".to_owned())?;
    let body=raw.strip_prefix(b"DPAPI").ok_or_else(||"Cursor 的加密密钥不是本机 DPAPI 格式".to_owned())?;
    dpapi(body).ok_or_else(||"无法解密 Cursor 的加密密钥（可能不是当前 Windows 用户写入的）".to_owned())
}
#[cfg(not(windows))]
fn master_key(_home:&Path)->Result<Vec<u8>,String>{Err(NOT_LOCAL.into())}

#[cfg(windows)]
fn dpapi(data:&[u8])->Option<Vec<u8>>{
    use windows::Win32::{Foundation::LocalFree,Security::Cryptography::{CryptUnprotectData,CRYPT_INTEGER_BLOB}};
    unsafe{
        let input=CRYPT_INTEGER_BLOB{cbData:data.len() as u32,pbData:data.as_ptr() as *mut u8};
        let mut output=CRYPT_INTEGER_BLOB::default();
        CryptUnprotectData(&input,None,None,None,None,0,&mut output).ok()?;
        let plain=std::slice::from_raw_parts(output.pbData,output.cbData as usize).to_vec();
        let _=LocalFree(windows::Win32::Foundation::HLOCAL(output.pbData as *mut core::ffi::c_void));
        Some(plain)
    }
}

/// 解封 `cursor-safe-storage:v1:`：`v10` 三字节标记 + 12 字节 nonce + 密文（尾部含 GCM tag）。
fn unseal(key:&[u8],text:&str)->Result<String,String>{
    if !text.starts_with(SAFE_PREFIX){return Ok(text.to_owned());}
    let blob=STANDARD.decode(&text[SAFE_PREFIX.len()..]).map_err(|_|"Cursor 的登录数据格式异常".to_owned())?;
    if key.len()!=32{return Err("Cursor 的加密密钥长度异常".into());}
    if blob.len()<3+12+16{return Err("Cursor 的登录数据不完整".into());}
    let mut body=blob[3..].to_vec();
    let(nonce,cipher)=body.split_at_mut(12);
    let nonce:[u8;12]=nonce.try_into().map_err(|_|"Cursor 的登录数据格式异常".to_owned())?;
    let mut raw=[0u8;32];raw.copy_from_slice(key);
    let key=ring::aead::LessSafeKey::new(ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM,&raw).map_err(|_|"无法初始化 Cursor 解密".to_owned())?);
    key.open_in_place(ring::aead::Nonce::assume_unique_for_key(nonce),ring::aead::Aad::empty(),cipher)
        .map(|plain|String::from_utf8_lossy(plain).into_owned())
        .map_err(|_|"无法解密 Cursor 的登录数据".to_owned())
}

/// ItemTable 是 SQLite 表；系统自带的 `winsqlite3.dll` 够用，不额外引入 sqlite crate。
#[cfg(windows)]
fn item_table(db:&Path)->Result<Vec<(String,String)>,String>{
    mod ffi{
        use std::{ffi::c_void,iter::once,os::windows::ffi::OsStrExt,path::Path,sync::OnceLock};
        use windows::core::{PCSTR,PCWSTR};
        use windows::Win32::System::LibraryLoader::{GetProcAddress,LoadLibraryW};
        type Handle=*mut c_void;
        type Open=unsafe extern "system" fn(*const u8,*mut Handle,i32,*const u8)->i32;
        type Prepare=unsafe extern "system" fn(Handle,*const u8,i32,*mut Handle,*mut *const u8)->i32;
        type Step=unsafe extern "system" fn(Handle)->i32;
        type Text=unsafe extern "system" fn(Handle,i32)->*const u8;
        type Finish=unsafe extern "system" fn(Handle)->i32;
        type Close=unsafe extern "system" fn(Handle)->i32;
        struct Api{open:Open,prepare:Prepare,step:Step,text:Text,finish:Finish,close:Close}
        // SAFETY: 函数指针指向系统 DLL 的代码段，进程生命周期内有效。
        unsafe impl Send for Api{} unsafe impl Sync for Api{}
        fn wide(text:&str)->Vec<u16>{std::ffi::OsStr::new(text).encode_wide().chain(once(0)).collect()}
        fn ansi(text:&str)->Vec<u8>{text.bytes().chain(once(0)).collect()}
        fn api()->Result<&'static Api,String>{
            static API:OnceLock<Result<Api,String>>=OnceLock::new();
            API.get_or_init(||unsafe{
                let module=LoadLibraryW(PCWSTR(wide("winsqlite3.dll").as_ptr())).map_err(|_|"系统缺少 SQLite 组件（winsqlite3.dll）".to_owned())?;
                let pick=|name:PCSTR|GetProcAddress(module,name).ok_or_else(||"winsqlite3.dll 缺少所需函数".to_owned());
                Ok(Api{
                    open:std::mem::transmute::<_,Open>(pick(PCSTR(b"sqlite3_open_v2\0".as_ptr()))?),
                    prepare:std::mem::transmute::<_,Prepare>(pick(PCSTR(b"sqlite3_prepare_v2\0".as_ptr()))?),
                    step:std::mem::transmute::<_,Step>(pick(PCSTR(b"sqlite3_step\0".as_ptr()))?),
                    text:std::mem::transmute::<_,Text>(pick(PCSTR(b"sqlite3_column_text\0".as_ptr()))?),
                    finish:std::mem::transmute::<_,Finish>(pick(PCSTR(b"sqlite3_finalize\0".as_ptr()))?),
                    close:std::mem::transmute::<_,Close>(pick(PCSTR(b"sqlite3_close\0".as_ptr()))?),
                })
            }).as_ref().map_err(|error|error.clone())
        }
        pub(super) fn rows(db:&Path)->Result<Vec<(String,String)>,String>{
            let api=api()?;
            let name=ansi(&db.to_string_lossy());
            let sql=ansi("SELECT key, value FROM ItemTable");
            let mut handle:Handle=std::ptr::null_mut();
            unsafe{
                if (api.open)(name.as_ptr(),&mut handle,0x2,std::ptr::null())!=0{return Err("无法打开 Cursor 状态数据库".into());}
                let mut stmt:Handle=std::ptr::null_mut();
                if (api.prepare)(handle,sql.as_ptr(),-1,&mut stmt,std::ptr::null_mut())!=0{let _=(api.close)(handle);return Err("无法查询 Cursor 状态数据库".into());}
                let read=|p:*const u8|{let mut n=0usize;while *p.add(n)!=0{n+=1;}String::from_utf8_lossy(std::slice::from_raw_parts(p,n)).into_owned()};
                let mut out=Vec::new();
                while (api.step)(stmt)==100{
                    let(key,value)=((api.text)(stmt,0),(api.text)(stmt,1));
                    if key.is_null()||value.is_null(){continue;}
                    out.push((read(key),read(value)));
                }
                let _=(api.finish)(stmt);let _=(api.close)(handle);
                Ok(out)
            }
        }
    }
    ffi::rows(db)
}
#[cfg(not(windows))]
fn item_table(_db:&Path)->Result<Vec<(String,String)>,String>{Err(NOT_LOCAL.into())}

/// WAL 里有最新的写入，必须连 `-wal`、`-shm` 一起复制到临时目录再读。
fn snapshot_table(db:&Path)->Result<HashMap<String,String>,String>{
    let dir=std::env::temp_dir().join(format!("daozai-cursor-{}",std::process::id()));
    let _=std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|_|"无法创建 Cursor 临时目录".to_owned())?;
    let target=dir.join("state.vscdb");
    let result=(||{
        std::fs::copy(db,&target).map_err(|_|"无法读取 Cursor 状态数据库（它可能正被其他进程占用）".to_owned())?;
        for suffix in ["-wal","-shm"]{
            let from=PathBuf::from(format!("{}{suffix}",db.display()));
            if from.is_file(){let _=std::fs::copy(&from,dir.join(format!("state.vscdb{suffix}")));}
        }
        item_table(&target)
    })();
    let _=std::fs::remove_dir_all(&dir);
    Ok(result?.into_iter().collect())
}

fn read_local()->Result<Local,String>{
    let home=cursor_home();
    let db=home.join("User").join("globalStorage").join("state.vscdb");
    if !db.is_file(){return Err(NOT_LOCAL.into());}
    let key=master_key(&home)?;
    let table=snapshot_table(&db)?;
    let access=table.get("cursorAuth/accessToken").filter(|value|!value.is_empty())
        .ok_or_else(||"本机 Cursor 没有保存登录令牌，请在 Cursor 客户端登录一次".to_owned())?;
    let access=unseal(&key,access)?;
    if access.is_empty(){return Err(AUTH_ERROR.into());}
    let refresh=table.get("cursorAuth/refreshToken").map(|value|unseal(&key,value)).transpose()?.unwrap_or_default();
    let email=table.get("cursorAuth/cachedEmail").cloned().unwrap_or_default();
    let plan=table.get("cursorAuth/stripeMembershipType").cloned().unwrap_or_default();
    Ok(Local{email,plan,token:Token{access,refresh}})
}

pub struct Connected {pub slot:String,pub label:String,pub snapshot:Snapshot}
pub struct Connect {rx:mpsc::Receiver<Result<Connected,String>>}
impl Connect {
    /// 读本机 Cursor 客户端的登录态：不打开浏览器、不需要粘贴。
    pub fn start_local(alias:String)->Self{
        let(tx,rx)=mpsc::channel();
        std::thread::spawn(move||{let _=tx.send(connect(&alias,read_local()));});
        Self{rx}
    }
    /// 兜底：仍然允许粘贴网页会话值，成功后同样写进凭据管理器。
    pub fn start_token(alias:String,raw:String)->Self{
        let(tx,rx)=mpsc::channel();
        std::thread::spawn(move||{
            let result=(||{
                let access=normalize(&raw);
                if access.is_empty()||access.chars().any(char::is_whitespace){return Err("请粘贴 Cursor 的 accessToken 或会话 Cookie".into());}
                connect(&alias,Ok(Local{email:String::new(),plan:String::new(),token:Token{access,refresh:String::new()}}))
            })();
            let _=tx.send(result);
        });
        Self{rx}
    }
    pub fn poll(&self)->Option<Result<Connected,String>>{self.rx.try_recv().ok()}
}
fn connect(alias:&str,local:Result<Local,String>)->Result<Connected,String>{
    let local=local?;
    let slot=slot_of(&local.token.access);
    let snapshot=usage(&super::http_agent(),&local.token.access).map_err(|error|{
        // 连不上额度时也要把读到的账号说清楚，避免用户以为没识别到本机登录。
        if local.email.is_empty(){error.0}else{
            let plan=if local.plan.is_empty(){String::new()}else{format!("，{}",local.plan)};
            format!("已读到本机 Cursor 账号 {}{plan}：{}",local.email,error.0)
        }
    })?;
    save(&slot,&local.token)?;
    let label=if !alias.trim().is_empty(){alias.trim().to_owned()}
        else if !local.email.is_empty(){
            let plan=if local.plan.is_empty(){String::new()}else{format!(" · {}",local.plan)};
            format!("Cursor · {}{plan}",local.email)
        }else{label_of("",&slot)};
    Ok(Connected{slot,label,snapshot})
}
pub fn fetch(agent:&ureq::Agent,account:&Account)->Result<Snapshot,(String,u64)>{
    let slot=account.slot.as_deref().ok_or_else(||("请连接 Cursor 账号".to_owned(),0))?;
    let token=load(slot).map_err(|error|(error,0))?;
    if slot_of(&token.access)!=slot{return Err(("Cursor 已切换账号，请重新连接".into(),0));}
    usage(agent,&token.access)
}

#[cfg(test)]
mod tests{
    use super::*;
    use serde_json::json;
    #[test]fn cookie_values_are_normalized_before_use(){
        assert_eq!(normalize("WorkosCursorSessionToken=user_1%3A%3AeyJhbGciOi; Path=/"),"user_1::eyJhbGciOi");
        assert_eq!(normalize("  user_1::eyJhbGciOi  "),"user_1::eyJhbGciOi");
        assert_eq!(normalize("%3A"),":");
        assert_eq!(normalize("%ZZ"),"%ZZ");
        assert_eq!(normalize(""),"");
    }
    #[test]fn bearer_keeps_only_the_jwt_part(){
        assert_eq!(bearer("user_1::eyJhbGciOiJIUzI1NiJ9.e30.sig"),"eyJhbGciOiJIUzI1NiJ9.e30.sig");
        assert_eq!(bearer("eyJhbGciOiJIUzI1NiJ9.e30.sig"),"eyJhbGciOiJIUzI1NiJ9.e30.sig");
    }
    #[test]fn sealed_values_round_trip_through_aes_gcm(){
        let key:Vec<u8>=(0..32u8).collect();let nonce=[7u8;12];let plain="{\"accessToken\":\"eyJhbGciOiJIUzI1NiJ9\"}";
        let key_ref=ring::aead::LessSafeKey::new(ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM,&key).unwrap());
        let mut body=plain.as_bytes().to_vec();
        key_ref.seal_in_place_append_tag(ring::aead::Nonce::assume_unique_for_key(nonce),ring::aead::Aad::empty(),&mut body).unwrap();
        let mut blob=vec![b'v',b'1',b'0'];blob.extend_from_slice(&nonce);blob.extend_from_slice(&body);
        let sealed=format!("{SAFE_PREFIX}{}",STANDARD.encode(blob));
        assert_eq!(unseal(&key,&sealed).unwrap(),plain);
        assert_eq!(unseal(&[9u8;32],&sealed).unwrap_err(),"无法解密 Cursor 的登录数据");
        // 没有密封前缀的明文令牌原样返回，兼容旧版 Cursor 写入的格式。
        assert_eq!(unseal(&key,"plain-token").unwrap(),"plain-token");
        assert_eq!(unseal(&key,&format!("{SAFE_PREFIX}AAAA")).unwrap_err(),"Cursor 的登录数据不完整");
    }
    #[test]fn current_period_usage_reports_the_remaining_fraction_and_the_cycle(){
        let s=parse(&json!({"billingCycleStart":1764547200,"billingCycleEnd":1765152000,"planUsage":{"totalPercentUsed":37.6,"limit":2000,"remaining":1248},"enabled":true})).unwrap();
        assert_eq!(s.windows.len(),1);assert_eq!(s.windows[0].remaining,62.4);assert_eq!(s.windows[0].seconds,Some(604800));assert_eq!(s.windows[0].label,"本周");
        assert_eq!(s.windows[0].reset,Some(1765152000));assert!(s.windows[0].amount.is_none());
    }
    #[test]fn cents_are_converted_when_only_the_amounts_are_returned(){
        let s=parse(&json!({"planUsage":{"limit":2000,"remaining":500}})).unwrap();
        assert_eq!(s.windows[0].remaining,25.0);
        // 客户端把 0..1 的小数当作极小用量，按 1% 处理，避免显示成 0.4%。
        let s=parse(&json!({"planUsage":{"totalPercentUsed":0.4}})).unwrap();
        assert_eq!(s.windows[0].remaining,99.0);
    }
    #[test]fn legacy_and_percent_style_payloads_are_still_readable(){
        let p=parse(&json!({"data":{"planUsage":{"apiPercentUsed":12.5}}})).unwrap();assert_eq!(p.windows[0].remaining,87.5);
        let l=parse(&json!({"gpt-4":{"numRequests":30,"numRequestsTotal":300},"gpt-4-mini":{"numRequests":10,"numRequestsTotal":100}})).unwrap();
        assert_eq!(l.windows[0].remaining,90.0);
    }
    #[test]fn unknown_payloads_and_zero_limits_are_never_shown_as_unused(){
        for value in [json!({}),json!([]),json!(null),json!("ok"),json!({"planUsage":{"limit":0,"remaining":0}}),json!({"planUsage":{"totalPercentUsed":"NaN"}})]{
            assert!(parse(&value).is_err(),"不能把无法识别的响应当成满额度：{value}");
        }
    }
    #[test]fn errors_distinguish_expired_login_from_blocked_network(){
        let response=ureq::Response::new(401,"Unauthorized","private-response").unwrap();
        let(message,_)=http_error(ureq::Error::Status(401,response));assert!(message.contains("重新登录"));assert!(message.contains("官方额度接口"));
        let response=ureq::Response::new(403,"Forbidden","private-response").unwrap();
        let(message,_)=http_error(ureq::Error::Status(403,response));assert!(message.contains("403"));
        assert!(BLOCKED.contains("网络"));
    }
    #[test]fn slots_follow_the_token_subject_so_relogin_does_not_duplicate_accounts(){
        let token=|sub:&str|format!("user::{}.{}.sig",URL_SAFE_NO_PAD.encode(json!({"sub":sub}).to_string()),URL_SAFE_NO_PAD.encode(json!({}).to_string()));
        assert_eq!(slot_of(&token("user_a")),slot_of(&token("user_a")));
        assert_ne!(slot_of(&token("user_a")),slot_of(&token("user_b")));
        assert_eq!(slot_of("not-a-jwt").len(),64);
    }
    /// 手动诊断：`cargo test --lib -- --ignored read_the_local_cursor_account --nocapture`
    #[test]
    #[ignore]
    fn read_the_local_cursor_account(){
        let local=read_local().expect("本机应能读出 Cursor 登录");
        assert!(!local.token.access.is_empty());
        println!("email={} plan={} token={} 字符",local.email,local.plan,local.token.access.len());
    }
}
