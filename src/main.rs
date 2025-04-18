use log::{error, info};
use std::{env, process::exit};
use thiserror::Error;

const SET: &str = "set";
const UNSET: &str = "unset";

#[derive(Error, Debug)]
pub enum ArgError {
    #[error("invalid action - {0}")]
    InvalidAction(String),
    #[error("invalid domain - {0}")]
    InvalidDomain(String),
    #[error("invalid challenge DNS name - {0}")]
    InvalidChallengeDNS(String),
    #[error("invalid token - {0}")]
    InvalidToken(String),
}

#[derive(Debug)]
enum Action {
    Set,
    Unset,
}

fn validate_action(action: &str) -> Result<Action, ArgError> {
    match action {
        SET => Ok(Action::Set),
        UNSET => Ok(Action::Unset),
        _ => Err(ArgError::InvalidAction(action.to_string())),
    }
}

fn validate_domain<'a>(domain: &'a str) -> Result<&'a str, ArgError> {
    match addr::parse_domain_name(domain) {
        Ok(_) => Ok(domain),
        Err(e) => Err(ArgError::InvalidDomain(e.to_string())),
    }
}

fn validate_challenge_dns<'a>(dns: &'a str) -> Result<&'a str, ArgError> {
    match addr::parse_dns_name(dns) {
        Ok(_) => Ok(dns),
        Err(e) => Err(ArgError::InvalidChallengeDNS(e.to_string())),
    }
}

fn validate_token<'a>(token: &'a str) -> Result<&'a str, ArgError> {
    match base64_url::decode(token) {
        Ok(_) => Ok(token),
        Err(e) => Err(ArgError::InvalidChallengeDNS(e.to_string())),
    }
}

fn conf_logger() -> () {
    fern::Dispatch::new()
        // Perform allocation-free log formatting
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{} {} {}] {}",
                humantime::format_rfc3339(std::time::SystemTime::now()),
                record.level(),
                record.target(),
                message
            ))
        })
        // Add blanket level filter -
        .level(log::LevelFilter::Debug)
        .chain(std::io::stdout())
        // Apply globally
        .apply()
        .unwrap()
}

fn main() {
    conf_logger();

    let args: Vec<String> = env::args().collect();

    if args.len() != 5 {
        println!(
            "Usage: {} <action> <domain> <challenge_dns> <token>",
            args[0]
        );
        exit(1);
    }

    let action = match validate_action(&args[1]) {
        Ok(action) => action,
        Err(e) => {
            error!("{}", e.to_string());
            exit(1);
        }
    };
    let domain = match validate_domain(&args[2]) {
        Ok(domain) => domain,
        Err(e) => {
            error!("{}", e.to_string());
            exit(1);
        }
    };
    let challenge_dns = match validate_challenge_dns(&args[3]) {
        Ok(challenge_dns) => challenge_dns,
        Err(e) => {
            error!("{}", e.to_string());
            exit(1);
        }
    };
    let token = match validate_token(&args[4]) {
        Ok(token) => token,
        Err(e) => {
            error!("{}", e.to_string());
            exit(1);
        }
    };

    info!("Action: {:?}", action);
    info!("Domain: {:?}", domain);
    info!("Challenge DNS: {:?}", challenge_dns);
    info!("Token: {:?}", token);
}
