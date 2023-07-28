use hyper::{Request, Response, Body};
use hyper::service::{make_service_fn, service_fn};
use pam::constants::{PamFlag, PamResultCode, PAM_TEXT_INFO, PAM_ERROR_MSG};
use pam::conv::Conv;
use pam::items::RHost;
use pam::module::{PamHandle, PamHooks};
use rand::SeedableRng;
use serde::Deserialize;
use tokio::sync::Notify;
use std::collections::HashMap;
use std::error::Error;
use std::ffi::CStr;
use std::time::Duration;
use pam::pam_try;
use tokio::time::sleep;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::convert::Infallible;
use tokio::runtime::Runtime;
use std::net::TcpListener;
use rand_chacha::ChaCha20Rng;
use rand::Rng;
use rand::distributions::Alphanumeric;

#[derive(Deserialize)]
struct OauthCreds{
    access_token: String,
}

#[derive(Deserialize)]
struct GuildMember{
    roles: Vec<String>,
}

// Macro which generates the `extern "C"` entrypoint bindings needed by PAM
struct PamDiscord;
pam::pam_hooks!(PamDiscord);

const API_ENDPOINT: &str = "https://discord.com/api";

impl PamHooks for PamDiscord {
    // This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode { 
        let args: Vec<_> = args
            .iter()
            .map(|s| s.to_string_lossy())
            .collect();
        let args: HashMap<&str, &str> = args
            .iter()
            .map(|s| {
                let mut parts = s.splitn(2, '=');
                (parts.next().unwrap(), parts.next().expect("Invalid PAM config"))
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
                eprintln!("Couldn't get pam_conv");
                return err;
            }
        };
        let rhost = match pamh.get_item::<RHost>() {
            Ok(Some(rhost)) => rhost.to_str().unwrap(),
            Ok(None) => {
                unreachable!("No rhost available");
            }
            Err(err) => {
                eprintln!("Couldn't get pam_rhost");
                return err;
            }
        };
        // Init CSRNG, generate random state
        let rand = ChaCha20Rng::from_entropy();
        let state: String = rand.sample_iter(&Alphanumeric).take(32).map(char::from).collect();

        // Get a port, and return authorize url through pam conv
        let port = get_free_tcp().unwrap_or(0);
        let authorize_url = format!("{}/oauth2/authorize?response_type=code&client_id={}&scope=guilds.members.read&state={}&redirect_uri=http://{}:{}", API_ENDPOINT, client_id, state, rhost, port);    
        pam_try!(conv.send(PAM_TEXT_INFO, &authorize_url));

        // Create async runtime, get oauth2 token, and use it to generate an access token
        match verify_member(state, port, client_id, client_secret, guild_id, role){
            Ok(true) => PamResultCode::PAM_SUCCESS,
            Ok(false) => {
                pam_try!(conv.send(PAM_ERROR_MSG, "You do not have the required role!"));
                PamResultCode::PAM_PERM_DENIED
            }
            Err(err) => {
                pam_try!(conv.send(PAM_ERROR_MSG, &err.to_string()));
                PamResultCode::PAM_AUTH_ERR
            }
        }

    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        // This function just needs to exist and be callable, otherwise pam hooks will fail
        println!("set credentials");
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        // This function just needs to exist and be callable as well, otherwise pam hooks will fail
        println!("account management");
        PamResultCode::PAM_SUCCESS
    }
}

async fn generate_new_token(state: String, port: u16) -> String {
    let addr = ([0, 0, 0, 0], port).into();

    let notify = Arc::new(Notify::new());
    let token = Arc::new(Mutex::new(String::new()));
    let make_svc = make_service_fn({
        let notify = notify.clone();
        let token = token.clone();
        move |_| {
            let notify = notify.clone();
            let token = token.clone();
            let state = state.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                    let notify = notify.clone();
                    let token = token.clone();
                    let state = state.clone();
                    async move {
                        let code = req
                          .uri()
                          .query()
                          .map(|query|
                            url::form_urlencoded::parse(query.as_bytes())
                          )
                          .and_then(|mut query|
                            query.find(|(name, _)| *name == "code")
                          )
                          .map(|(_, code)| code.into_owned());
                        let rstate = req
                            .uri()
                            .query()
                            .map(|query|
                              url::form_urlencoded::parse(query.as_bytes())
                            )
                            .and_then(|mut query|
                              query.find(|(name, _)| *name == "state")
                            )
                            .map(|(_, rstate)| rstate.into_owned())
                            .unwrap();
                        if rstate != state {
                            return Ok::<_, Infallible>(Response::new(Body::from(
                                "Invalid CSRF token!",
                            )));
                        }
                        if let (Some(code), token) = (code, &mut *token.lock().await) {
                          notify.notify_one();
                          *token = code;
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

    let lock = token.lock().await;
    lock.to_string()
}

async fn get_access_token(client_id: &str, client_secret: &str, code: &str, url: String) -> Result<OauthCreds, reqwest::Error> {
    let data = [("client_id", client_id), ("client_secret", client_secret), ("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", &url)];
    let client = reqwest::Client::new();
    let res = client.post(format!("{}/v10/oauth2/token", API_ENDPOINT))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(&data)
            .send()
            .await?
            .json::<OauthCreds>()
            .await?;
    return Ok(res);
}

async fn get_guild_member(access_token: &str, guild_id: &str) -> Result<GuildMember, reqwest::Error> {
    let mut map = HashMap::new();
    map.insert("lang", "rust");
    let url: String = format!("{}/v10/users/@me/guilds/{}/member", API_ENDPOINT, guild_id);
    let client = reqwest::Client::new();
    let res = client
    .get(url)
    .header("Authorization", format!("Bearer {}", access_token))
    .send()
    .await?
    .json::<GuildMember>()
    .await?;
    return Ok(res);
}

//// This `derive` requires the `serde` dependency.
//#[derive(Deserialize)]
//struct Ip {
//    origin: String,
//}
//
//let ip = reqwest::get("http://httpbin.org/ip")
//    .await?
//    .json::<Ip>()
//    .await?;
//
//println!("ip: {}", ip.origin);
//Erro

pub fn verify_member(state: String, port: u16, client_id: &str, client_secret: &str, guild_id: &str, role: &str) -> Result<bool, Box<dyn Error>>{
    let rt = Runtime::new()?;
    let oauth_token = rt.block_on(generate_new_token(state, port));
    let access_token = rt.block_on(get_access_token(client_id, client_secret, oauth_token.as_str(), format!("http://127.0.0.1:{}",port)))?;
    
    // Parse token and check if user has role
    let actual_token = &access_token.access_token;
    let member = rt.block_on(get_guild_member(actual_token, guild_id))?;
    if member.roles.contains(&role.to_string()){
        return Ok(true)
    }
    return Ok(false)
}

pub fn get_free_tcp() -> Option<u16> {
    // Discord has a limit of 10 redirect urls, so limit to range 10050 to 10060
    (10050..10060)
        .find(|port| port_is_available(*port))
}

pub fn port_is_available(port: u16) -> bool {
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(_) => true,
        Err(_) => false,
    }
}