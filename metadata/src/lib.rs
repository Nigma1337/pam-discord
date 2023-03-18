use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use pam::constants::{PamFlag, PamResultCode, PAM_TEXT_INFO, PAM_ERROR_MSG, PAM_PROMPT_ECHO_ON};
use pam::conv::Conv;
use pam::items::RHost;
use pam::module::{PamHandle, PamHooks};
use std::collections::HashMap;
use std::ffi::CStr;
use pam::pam_try;

const API_ENDPOINT: &str = "https://discord.com/api";
struct PamMetadata;
pam::pam_hooks!(PamMetadata);

impl PamHooks for PamMetadata {
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
        let client_id: &str = match args.get("client_id") {
            Some(client_id) => client_id,
            None => return PamResultCode::PAM_AUTH_ERR,
        };
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
        if port == 0 {
            pam_try!(conv.send(PAM_ERROR_MSG, "There seem no be no free ports :-("));
            return PamResultCode::PAM_OPEN_ERR
        }
        pam_try!(pamh.set_data("port", Box::new(port)));
        pam_try!(pamh.set_data("state", Box::new("fart")));
        let authorize_url = format!("{}/oauth2/authorize?response_type=code&client_id={}&scope=identify&state=fart&redirect_uri=http://{}:{}", API_ENDPOINT, client_id, rhost.to_str().unwrap(), port);    

        pam_try!(conv.send(PAM_TEXT_INFO, &authorize_url));
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