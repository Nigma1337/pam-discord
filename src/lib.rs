use hyper::{Request, Response, Body};
use hyper::service::{make_service_fn, service_fn};
use pam::constants::{PamFlag, PamResultCode, PAM_TEXT_INFO, PAM_ERROR_MSG};
use pam::conv::Conv;
use pam::items::RHost;
use pam::module::{PamHandle, PamHooks};
use tokio::sync::Notify;
use std::collections::HashMap;
use std::ffi::CStr;
use std::time::Duration;
use pam::pam_try;
use tokio::time::sleep;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::convert::Infallible;
use tokio::runtime::Runtime;
use std::net::TcpListener;

struct PamDiscord;
pam::pam_hooks!(PamDiscord);

const API_ENDPOINT: &str = "https://discord.com/api";

impl PamHooks for PamDiscord {
    // This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode { 
        println!("test");
        let args: Vec<_> = args
            .iter()
            .map(|s| s.to_string_lossy())
            .collect();
        let args: HashMap<&str, &str> = args
            .iter()
            .map(|s| {
                let mut parts = s.splitn(2, '=');
                (parts.next().unwrap(), parts.next().unwrap_or(""))
            })
            .collect();
        let client_id: &str = match args.get("client_id") {
            Some(client_id) => client_id,
            None => return PamResultCode::PAM_AUTH_ERR,
        };
        let client_secret: &str = match args.get("client_secret") {
            Some(client_secret) => client_secret,
            None => return PamResultCode::PAM_AUTH_ERR,
        };
        let guild_id: &str = match args.get("guild") {
            Some(guild) => guild,
            None => return PamResultCode::PAM_AUTH_ERR,
        };
        let role: &str = match args.get("role") {
            Some(role) => role,
            None => return PamResultCode::PAM_AUTH_ERR,
        };
        let conv = match pamh.get_item::<Conv>() {
            Ok(Some(conv)) => conv,
            Ok(None) => {
                unreachable!("No conv available");
            }
            Err(err) => {
                println!("Couldn't get pam_conv");
                return err;
            }
        };
        let state: &&str = &"unknown";
        let rhost = match pamh.get_item::<RHost>() {
            Ok(Some(rhost)) => rhost,
            Ok(None) => {
                unreachable!("No rhost available");
            }
            Err(err) => {
                println!("Couldn't get pam_rhost");
                return err;
            }
        };
        let port = match get_free_tcp() {
            Some(port) => port,
            None => 0,
        };
        let authorize_url = format!("{}/oauth2/authorize?response_type=code&client_id={}&scope=guilds.members.read&state=fart&redirect_uri=http://{}:{}", API_ENDPOINT, client_id, rhost.to_str().unwrap(), port);    
        pam_try!(conv.send(PAM_TEXT_INFO, &authorize_url));
        let rt = Runtime::new().unwrap();
        let gang = rt.block_on(generate_new_token(state, port));
        let access_token = rt.block_on(get_access_token(client_id, client_secret, gang, format!("http://127.0.0.1:{}",port).to_string())).unwrap();
        let actual_token_json = json::parse(&access_token).unwrap();
        let actual_token = actual_token_json["access_token"].as_str().unwrap();
        let member = rt.block_on(get_guild_member(actual_token, guild_id)).unwrap();
        let member_json = json::parse(&member).unwrap();
        if member_json["roles"].contains(role){
            return PamResultCode::PAM_SUCCESS
        }
        pam_try!(conv.send(PAM_ERROR_MSG, "You do not have the required role!"));
        PamResultCode::PAM_PERM_DENIED
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("set credentials");
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("account management");
        PamResultCode::PAM_SUCCESS
    }
}

async fn generate_new_token(state: &str, port: u16) -> String {
    let addr = ([0, 0, 0, 0], port).into();

    let notify = Arc::new(Notify::new());
    let token = Arc::new(Mutex::new(None::<String>));
    let make_svc = make_service_fn({
        let notify = notify.clone();
        let token = token.clone();
        move |_| {
            let notify = notify.clone();
            let token = token.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                    let notify = notify.clone();
                    let token = token.clone();
                    async move {
                        let code = req
                          .uri()
                          .query()
                          .map(|query|
                            url::form_urlencoded::parse(query.as_bytes())
                          )
                          .and_then(|mut query|
                            query.find(|(name, _)| name.to_string() == "code")
                          )
                          .map(|(_, code)| code.into_owned());
                        if let (Some(code), token @ None) = (code, &mut *token.lock().await) {
                          notify.notify_one();
                          *token = Some(code);
                        }
                        Ok::<_, Infallible>(Response::new(Body::from(
                            "fuck you",
                        )))
                    }
                }))
            }
        }
    });
    let server = hyper::Server::bind(&addr)
        .serve(make_svc)
        .with_graceful_shutdown(async move { tokio::select! {
          _ = notify.notified() => (),
          _ = sleep(Duration::from_secs(60 * 1)) => (),
        }});
    server.await.unwrap();

    let mut lock = token.lock().await;
    lock.take().unwrap()
}

async fn get_access_token(client_id: &str, client_secret: &str, code: String, url: String) -> Result<std::string::String, reqwest::Error> {
    let data = [("client_id", client_id), ("client_secret", client_secret), ("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", &url)];
    let client = reqwest::Client::new();
    let res = client.post(format!("{}/v10/oauth2/token", API_ENDPOINT))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&data)
            .send()
            .await?;
    return res.text().await;
}

async fn get_guild_member(access_token: &str, guild_id: &str) -> Result<std::string::String, reqwest::Error> {
    let url: String = format!("{}/v10/users/@me/guilds/{}/member", API_ENDPOINT, guild_id);
    let client = reqwest::Client::new();
    let res = client
    .get(url)
    .header("Authorization", format!("Bearer {}", access_token))
    .send()
    .await?;
    return res.text().await
}

pub fn get_free_tcp() -> Option<u16> {
    (10050..10060)
        .find(|port| port_is_available(*port))
}

pub fn port_is_available(port: u16) -> bool {
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(_) => true,
        Err(_) => false,
    }
}