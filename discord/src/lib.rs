use hyper::{Request, Response, Body};
use hyper::service::{make_service_fn, service_fn};
use pam::constants::{PamFlag, PamResultCode, PAM_RADIO_TYPE, PAM_PROMPT_ECHO_OFF, PAM_TEXT_INFO, PAM_ERROR_MSG, PAM_SILENT, PAM_BINARY_PROMPT};
use pam::conv::Conv;
use pam::items::RHost;
use pam::module::{PamHandle, PamHooks};
use tokio::sync::Notify;
use std::collections::HashMap;
use std::ffi::CStr;
use std::io::{self, Write};
use std::time::Duration;
use pam::pam_try;
use tokio::time::sleep;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::convert::Infallible;
use tokio::runtime::Runtime;
use url::form_urlencoded::parse;

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

        let client_secret: &str = match args.get("client_secret") {
            Some(client_id) => client_id,
            None => return PamResultCode::PAM_AUTH_ERR,
        };
        let state: &&str = &"unknown";
        let port: u16 = 10050;
        unsafe{
            let state = match pamh.get_data::<&str>("state") {
                Ok(state) => state,
                Err(err) => {
                    println!("Couldn't get state");
                    return err;
                }
            };
            let port = match pamh.get_data::<u16>("port") {
                Ok(port) => port,
                Err(err) => {
                    println!("Couldn't get port!");
                    return err;
                }
            };
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
        let rt = Runtime::new().unwrap();
        let gang = rt.block_on(generate_new_token(state, port));
        pam_try!(conv.send(PAM_TEXT_INFO, gang));
        PamResultCode::PAM_SUCCESS
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

async fn generate_new_token(state: &str, port: u16) -> (String, String) {
    let addr = ([0, 0, 0, 0], port).into();

    let notify = Arc::new(Notify::new());
    let token = Arc::new(Mutex::new(None::<(String, String)>));
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
                    let params: HashMap<String, String> = req
                    .uri()
                    .query()
                    .map(|v| {
                        url::form_urlencoded::parse(v.as_bytes())
                            .into_owned()
                            .collect()
                    })
                    .unwrap_or_else(HashMap::new);
                    let test = match params.get("code") {
                        Some(test) => test.to_string(),
                        None => "jk,".to_string()
                    };
                    async move {
                        // TODO: Parse URL and get token
                        Ok::<_, Infallible>(Response::new(Body::from(
                            test,
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
