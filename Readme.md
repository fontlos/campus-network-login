# A crate for login to a variety of campus networks

When I reverse-engineered the login interface of the campus network, I found that many schools seem to use the same encryption scheme, such as the following

- [Mmx233/BitSrunLoginGo](https://github.com/Mmx233/BitSrunLoginGo)
- [https://pastebin.com/uqsL06jF](https://pastebin.com/uqsL06jF)

So I split it into a standalone crate and as part of [buaa-api](https://github.com/fontlos/buaa-api)

# Example

Open the browser debugging tool, check any XHR breakpoint, click Login, if you see three URLs similar to the following during the debugging process, then your campus network can most likely use this crate to login

```sh
// Your campus network login page, with 'ac_id'
// and `main_url` is `https://gw.buaa.edu.cn`
https://gw.buaa.edu.cn/srun_portal_pc?ac_id={ac_id}&theme=buaa

// The URL that appears during debugging

// with 'timestamp' and 'username'
// and `challenge_url` is `https://gw.buaa.edu.cn/cgi-bin/get_challenge`
https://gw.buaa.edu.cn/cgi-bin/get_challenge?callback={timestamp}&username={username}&ip={ip}&_={timestamp}

// with 'timestamp' and 'username' '{MD5}password' 'ac_id' 'ip' '{SRBX1}info'
// and `login_url` is `https://gw.buaa.edu.cn/cgi-bin/srun_portal`
https://gw.buaa.edu.cn/cgi-bin/srun_portal?callback={timestamp}&action=login&username={username}&password={{MD5}password}&ac_id={ac_id}&ip={ip}&chksum={chksum}&info={{SRBX1}info}&n=200&type=1&os=Windows%2B10&name=Windows&double_stack=0&_={timestamp}
```

```rust
use campus_network_login::CampusNetworkConfig;
use reqwest::Client;

#[tokio::main]
async fn main() {
    let client = Client::new();
    let config = CampusNetworkConfig {
        client: &client,
        username: "username",
        password: "password",
        main_url: "http://gw.buaa.edu.cn",
        challenge_url: "https://gw.buaa.edu.cn/cgi-bin/get_challenge",
        login_url: "https://gw.buaa.edu.cn/cgi-bin/srun_portal",
        with_res: false,
    };
    match config.login().await {
        Ok(_) => println!("[Info]: Login successfully, Please wait a few seconds for the server to respond"),
        Err(e) => eprintln!("[Info]: Login failed: {:?}", e),
    }
}
```