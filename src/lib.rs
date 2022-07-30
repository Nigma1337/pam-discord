extern crate pam;
extern crate tokio;
extern crate hyper;

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
                (parts.next().unwrap(), parts.next().unwrap_or(""))
            })
            .collect();

        let client_id: &str = match args.get("client_id") {
            Some(client_id) => client_id,
            None => return PamResultCode::PAM_AUTH_ERR,
        };
        
        let client_secret: &str = match args.get("client_secret") {
            Some(client_id) => client_id,
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
        pam_try!(conv.send(PAM_TEXT_INFO, "HELP ME"));
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
        pam_try!(conv.send(PAM_TEXT_INFO, "fart ME"));
        let rt = Runtime::new().unwrap();
        pam_try!(conv.send(PAM_TEXT_INFO, "fart"));
        //pam_try!(conv.send(PAM_RADIO_TYPE, "ma"));
        let authorize_url = format!("{}/oauth2/authorize?response_type=code&client_id={}&scope=identify&state=fart", API_ENDPOINT, client_id);
        pam_try!(conv.send(PAM_ERROR_MSG, &authorize_url));
        
        // Flush moment
        pam_try!(conv.send(PAM_RADIO_TYPE, &authorize_url));
        let gang = rt.block_on(generate_new_token(client_id, "fart"));
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

async fn generate_new_token(client_id: &str, state: &str) -> (String, String) {
    let addr = ([0, 0, 0, 0], 8312).into();

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
                    async move {
                        // TODO: Parse URL and get token
                        Ok::<_, Infallible>(Response::new(Body::from(
                            "Follow the link shown in your terminal",
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
          _ = sleep(Duration::from_secs(60 * 5)) => (),
        }});
    server.await.unwrap();

    let mut lock = token.lock().await;
    lock.take().unwrap()
}