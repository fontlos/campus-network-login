use base64::alphabet::Alphabet;
use base64::engine::{Engine, GeneralPurpose, GeneralPurposeConfig};
use hmac::{Hmac, Mac};
use md5::Md5;
use reqwest::Client;
use sha1::{Sha1, Digest};

use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CampusNetworkConfig<'a> {
    pub client: &'a Client,
    pub username: &'a str,
    pub password: &'a str,
    pub main_url: &'a str,
    pub challenge_url: &'a str,
    pub login_url: &'a str,
    pub with_res: bool
}

#[derive(Debug)]
pub enum CampusNetworkError{
    BadChallengeURL,
    LoginError(String),
    NoACID,
    NoToken,
    RequestError(reqwest::Error),
}

impl<'a> CampusNetworkConfig<'a> {
    /// # Campus Network Login
    /// ```rust
    /// use campus_network_login::CampusNetworkConfig;
    /// use reqwest::Client;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let client = Client::new();
    ///     let config = CampusNetworkConfig {
    ///         client: &client,
    ///         username: "username",
    ///         password: "password",
    ///         main_url: "http://gw.buaa.edu.cn",
    ///         challenge_url: "https://gw.buaa.edu.cn/cgi-bin/get_challenge",
    ///         login_url: "https://gw.buaa.edu.cn/cgi-bin/srun_portal",
    ///         with_res: false,
    ///     };
    ///     match config.login().await {
    ///        Ok(_) => println!("[Info]: Login successfully, Please wait a few seconds for the server to respond"),
    ///        Err(e) => eprintln!("[Info]: Login failed: {:?}", e),
    ///     }
    /// }
    /// ```
    pub async fn login(&self) -> Result<(), CampusNetworkError> {
        let un = self.username;
        let pw = self.password;
        let client = self.client;
        // 获取本机 IP
        let ip = match get_ip() {
            Some(s) => s,
            None => return Err(CampusNetworkError::LoginError(String::from("Cannot get IP address")))
        };

        // 从重定向 URL 中获取 ACID
        // 接入点, 不知道具体作用但是关系到登录之后能否使用网络, 如果用固定值可能出现登陆成功但网络不可用
        let res = match self.client.get(self.main_url).send().await {
            Ok(r) => r,
            Err(e) => return Err(CampusNetworkError::RequestError(e))
        };

        let url = res.url().as_str();
        let ac_id = match get_value_by_lable(url, "ac_id=", "&") {
            Some(s) => s,
            None => return Err(CampusNetworkError::NoACID)
        };

        // 获取 Challenge Token
        let time = &get_time().to_string()[..];
        let params= [
            ("callback", time),
            ("username", un),
            ("ip", &ip),
            ("_", time),
        ];
        let res = match client.get(self.challenge_url).query(&params).send().await {
            Ok(r) => r,
            Err(e) => return Err(CampusNetworkError::RequestError(e))
        };
        let token = if res.status().is_success() {
            let html = match res.text().await {
                Ok(s) => s,
                Err(e) => return Err(CampusNetworkError::RequestError(e))
            };
            match get_value_by_lable(&html, "\"challenge\":\"", "\"") {
                Some(s) => s,
                None => return Err(CampusNetworkError::NoToken)
            }
        } else {
            return Err(CampusNetworkError::BadChallengeURL);
        };

        // 计算登录信息
        // 注意因为是直接格式化字符串而非通过json库转成标准json, 所以必须保证格式完全正确, 无空格, 键值对都带双引号
        let data = format!(r#"{{"username":"{un}","password":"{pw}","ip":"{ip}","acid":"{ac_id}","enc_ver":"srun_bx1"}}"#);
        // 自带前缀
        let info = x_encode(&data, &token);

        // 计算加密后的密码, 并且后补前缀
        let mut hmac = Hmac::<Md5>::new_from_slice(token.as_bytes()).unwrap();
        hmac.update(pw.as_bytes());
        let res = hmac.finalize().into_bytes();
        let password_md5 = hex::encode(&res);

        // 计算校验和, 参数顺序如下
        //                             token username token password_md5 token ac_id token ip token n token type token info
        let check_str = format!("{token}{un}{token}{password_md5}{token}{ac_id}{token}{ip}{token}200{token}1{token}{info}");
        let hash = Sha1::digest(check_str.as_bytes());
        let chk_sum = hex::encode(&hash);

        // 构造登录 URL 并登录
        // 暂时不知道后面五个参数有无修改必要
        let params= [
            ("callback", time),
            ("action", "login"),
            ("username", un),
            ("password", &format!("{{MD5}}{password_md5}")),
            ("ac_id", &ac_id),
            ("ip", &ip),
            ("chksum", &chk_sum),
            ("info", &info),
            ("n", "200"),
            ("type", "1"),
            ("os", "Windows+10"),
            ("name", "Windows"),
            ("double_stack", "0"),
            ("_", time),
        ];
        let res = match client.get(self.login_url).query(&params).send().await {
            Ok(r) => r,
            Err(e) => return Err(CampusNetworkError::RequestError(e))
        };
        let res = match res.text().await {
            Ok(s) => s,
            Err(e) => return Err(CampusNetworkError::RequestError(e))
        };
        if res.contains("Login is successful"){
            return Ok(())
        } else {
            return Err(CampusNetworkError::LoginError(format!("Response: {res}")))
        }
    }
}

fn get_ip() -> Option<String> {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return None
    };
    match socket.connect("8.8.8.8:80") {
        Ok(()) => (),
        Err(_) => return None
    }
    match socket.local_addr() {
        Ok(a) => Some(a.ip().to_string()),
        Err(_) => None
    }
}

pub fn get_time() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

pub fn get_value_by_lable(text: &str, right: &str, left: &str) -> Option<String> {
    if let Some(start) = text.find(right) {
        // 计算开始位置
        let value_start = start + right.len();
        // 查找结束位置
        if let Some(end) = text[value_start..].find(left) {
            // 提取值
            Some(String::from(&text[value_start..value_start + end]))
        } else {
            // 理论上不可能出错
            None
        }
    } else {
        None
    }
}

/// 将字符串字节数组每四位转换后合并成一个新的数组
fn str2vec(a: &str) -> Vec<u32> {
    let c = a.len();
    let mut v = Vec::new();
    for i in (0..c).step_by(4) {
        let mut value: u32 = 0;
        if i < c {
            value |= a.as_bytes()[i] as u32;
        }
        if i + 1 < c {
            value |= (a.as_bytes()[i + 1] as u32) << 8;
        }
        if i + 2 < c {
            value |= (a.as_bytes()[i + 2] as u32) << 16;
        }
        if i + 3 < c {
            value |= (a.as_bytes()[i + 3] as u32) << 24;
        }
        v.push(value);
    }

    v
}

/// 一个自定义编码, 最后一步经过 Base64 编码
fn x_encode(str: &str, key: &str) -> String {
    if str.is_empty() {
        return String::new();
    }

    let mut pw = str2vec(str);
    let mut pwdkey = str2vec(key);

    let n = pw.len() as u32;

    pw.push(str.len() as u32);
    if pwdkey.len() < 4 {
        pwdkey.resize(4, 0);
    }

    let mut z = str.len() as u32;
    let mut y;
    let c = 2654435769;
    let mut m;
    let mut e;
    let mut p;
    let q = (6 + 52 / (n + 1)) as u32;
    let mut d = 0u32;

    for _ in 0..q {
        d = d.wrapping_add(c);
        e = (d >> 2) & 3;
        p = 0;
        while p < n {
            y = pw[(p + 1) as usize];
            m = (z >> 5 ^ y << 2)
                .wrapping_add((y >> 3 ^ z << 4) ^ (d ^ y))
                .wrapping_add(pwdkey[(p & 3) as usize ^ e as usize] ^ z);
            pw[p as usize] = pw[p as usize].wrapping_add(m);
            z = pw[p as usize];
            p += 1;
        }
        y = pw[0];
        m = (z >> 5 ^ y << 2)
            .wrapping_add((y >> 3 ^ z << 4) ^ (d ^ y))
            .wrapping_add(pwdkey[(p & 3) as usize ^ e as usize] ^ z);
        pw[n as usize] = pw[n as usize].wrapping_add(m);
        z = pw[n as usize];
    }

    let mut bytes = Vec::new();
    for i in pw{
        bytes.push((i & 0xff) as u8);
        bytes.push((i >> 8 & 0xff) as u8);
        bytes.push((i >> 16 & 0xff) as u8);
        bytes.push((i >> 24 & 0xff) as u8);
    }
    let alphabet = Alphabet::new("LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA").unwrap();
    let engine = GeneralPurpose::new(&alphabet, GeneralPurposeConfig::new());
    format!("{{SRBX1}}{}",engine.encode(bytes))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::File;

    use super::*;
    pub fn env() -> HashMap<String, String> {
        let env_str = File::open(".env").unwrap();
        let env: HashMap<String, String> = serde_json::from_reader(env_str).unwrap();
        env
    }
    #[tokio::test]
    async fn test_login() {
        let env = env();
        let username = env.get("USERNAME").unwrap();
        let password = env.get("PASSWORD").unwrap();
        let client = Client::new();

        let config = CampusNetworkConfig {
            client: &client,
            username: &username,
            password: &password,
            main_url: "http://gw.buaa.edu.cn",
            challenge_url: "https://gw.buaa.edu.cn/cgi-bin/get_challenge",
            login_url: "https://gw.buaa.edu.cn/cgi-bin/srun_portal",
            with_res: false,
        };
        match config.login().await {
            Ok(_) => (),
            Err(e) => eprintln!("{:?}", e)
        }
    }

    #[test]
    fn test_get_ip() {
        let s = get_ip().unwrap();
        println!("{}",s)
    }

    #[test]
    fn test_xencoder() {
        let env = env();
        let username = env.get("USERNAME").unwrap();
        let password = env.get("PASSWORD").unwrap();
        let ip = env.get("IP").unwrap();
        let data = format!("{{\"username\":\"{username}\",\"password\":\"{password}\",\"ip\":\"{ip}\",\"acid\":\"62\",\"enc_ver\":\"srun_bx1\"}}");
        let res = x_encode(&data,"8e4e83f094924913acc6a9d5149015aafc898bd38ba8f45be6bd0f9edd450403");
        assert_eq!(
            &res,
            "{SRBX1}p00873sYXXqOdVgJGG3pnnRbF99gDX6b03gBghCUqOXfT9du5GeouZ+H/uR78LqlLg+LJm9XZet3JZYnyZGQciC5GtboAz1QQVvkx07f/pht93EBRF9fdqNYRJIiWE3KzRWQozPndYgz1GTkUpzph+=="
        );
    }
}

