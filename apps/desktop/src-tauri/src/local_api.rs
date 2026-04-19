use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::time::Duration;
#[cfg(test)]
use std::net::SocketAddr;

const MAX_LOCAL_API_RESPONSE_BODY_BYTES: usize = 256 * 1024;
const MAX_LOCAL_API_AUTH_BEARER_BYTES: usize = 4096;

#[derive(Clone, Debug)]
pub struct LocalApiConfig {
    pub base_url: String,
    pub timeout_sec: u64,
    pub allow_remote: bool,
    pub auth_bearer: Option<String>,
    pub allow_update_mutations: bool,
    pub allow_service_mutations: bool,
}

impl LocalApiConfig {
    pub fn from_env() -> Result<Self, String> {
        let base_url = first_non_empty_env(&["GPM_LOCAL_API_BASE_URL", "TDPN_LOCAL_API_BASE_URL"])
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .unwrap_or_else(|| "http://127.0.0.1:8095".to_string());
        let base_url_display = redact_url_for_display(&base_url);

        let timeout_sec = first_non_empty_env(&["GPM_LOCAL_API_TIMEOUT_SEC", "TDPN_LOCAL_API_TIMEOUT_SEC"])
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(20);

        let allow_remote =
            parse_optional_bool_env_any(&["GPM_LOCAL_API_ALLOW_REMOTE", "TDPN_LOCAL_API_ALLOW_REMOTE"])?
                .unwrap_or(false);
        let allow_update_mutations = parse_optional_bool_env_any(&[
            "GPM_LOCAL_API_ALLOW_UPDATE_MUTATIONS",
            "TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS",
        ])?
        .unwrap_or(false);
        let allow_service_mutations = parse_optional_bool_env_any(&[
            "GPM_LOCAL_API_ALLOW_SERVICE_MUTATIONS",
            "TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS",
        ])?
        .unwrap_or(false);

        let auth_bearer =
            first_non_empty_env(&["GPM_LOCAL_API_AUTH_BEARER", "TDPN_LOCAL_API_AUTH_BEARER"]);
        if let Some(token) = auth_bearer.as_deref() {
            validate_auth_bearer(token)?;
        }

        let parsed = reqwest::Url::parse(&base_url).map_err(|e| {
            format!(
                "invalid TDPN_LOCAL_API_BASE_URL '{base_url_display}': {e} (expected absolute URL like http://127.0.0.1:8095)"
            )
        })?;

        match parsed.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(format!(
                    "invalid TDPN_LOCAL_API_BASE_URL '{base_url_display}': unsupported scheme '{scheme}' (allowed: http, https)"
                ));
            }
        }

        if parsed.host_str().is_none() {
            return Err(format!(
                "invalid TDPN_LOCAL_API_BASE_URL '{base_url_display}': missing host"
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(format!(
                "invalid TDPN_LOCAL_API_BASE_URL '{base_url_display}': userinfo is not allowed"
            ));
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(format!(
                "invalid TDPN_LOCAL_API_BASE_URL '{base_url_display}': query and fragment are not allowed"
            ));
        }

        let is_literal_loopback = is_literal_loopback_host(&parsed);
        if !allow_remote && !is_literal_loopback {
            let host = parsed.host_str().unwrap_or("<missing-host>");
            return Err(format!(
                "TDPN_LOCAL_API_BASE_URL host '{host}' is not a literal loopback IP (use 127.0.0.1 or ::1); set TDPN_LOCAL_API_ALLOW_REMOTE=1 to allow remote hosts"
            ));
        }

        if allow_remote && !is_literal_loopback {
            if auth_bearer.is_none() {
                return Err(
                    "TDPN_LOCAL_API_ALLOW_REMOTE=1 requires TDPN_LOCAL_API_AUTH_BEARER for non-loopback hosts"
                        .to_string(),
                );
            }
            if parsed.scheme() != "https" {
                return Err(format!(
                    "TDPN_LOCAL_API_BASE_URL '{base_url_display}' must use https when TDPN_LOCAL_API_ALLOW_REMOTE=1 targets non-loopback hosts"
                ));
            }
        }
        if (allow_update_mutations || allow_service_mutations) && auth_bearer.is_none() {
            return Err(
                "desktop mutation controls require TDPN_LOCAL_API_AUTH_BEARER (set token before enabling TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS or TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS)"
                    .to_string(),
            );
        }

        Ok(Self {
            base_url,
            timeout_sec,
            allow_remote,
            auth_bearer,
            allow_update_mutations,
            allow_service_mutations,
        })
    }

    fn endpoint(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("{}{}", self.base_url, path)
        } else {
            format!("{}/{}", self.base_url, path)
        }
    }

    pub fn redacted_base_url(&self) -> String {
        redact_url_for_display(&self.base_url)
    }
}

#[derive(Clone)]
pub struct LocalApiClient {
    config: LocalApiConfig,
    client: reqwest::Client,
}

impl LocalApiClient {
    pub fn new(config: LocalApiConfig) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_sec))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|e| format!("failed to build local API client: {e}"))?;
        Ok(Self { config, client })
    }

    pub fn config(&self) -> &LocalApiConfig {
        &self.config
    }

    pub async fn get_json(&self, path: &str) -> Result<Value, String> {
        let request = self.client.get(self.config.endpoint(path));
        let response = self
            .with_optional_auth(request)
            .send()
            .await
            .map_err(|e| format!("GET {path} failed: {e}"))?;
        self.parse_response(path, response).await
    }

    pub async fn post_json<T: Serialize + ?Sized>(&self, path: &str, payload: &T) -> Result<Value, String> {
        let request = self.client.post(self.config.endpoint(path)).json(payload);
        let response = self
            .with_optional_auth(request)
            .send()
            .await
            .map_err(|e| format!("POST {path} failed: {e}"))?;
        self.parse_response(path, response).await
    }

    pub async fn post_empty(&self, path: &str) -> Result<Value, String> {
        self.post_json(path, &json!({})).await
    }

    fn with_optional_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = self.config.auth_bearer.as_deref() {
            request.bearer_auth(token)
        } else {
            request
        }
    }

    async fn parse_response(&self, path: &str, mut response: reqwest::Response) -> Result<Value, String> {
        let status = response.status();
        let body = read_limited_response_body(path, &mut response).await?;

        if !status.is_success() {
            let reason = status.canonical_reason().unwrap_or("request failed");
            eprintln!("local API {} {} for {}", status.as_u16(), reason, path);
            return Err(format!("local API {} {} for {}", status.as_u16(), reason, path));
        }

        if body.trim().is_empty() {
            return Ok(json!({ "ok": true }));
        }

        match serde_json::from_str::<Value>(&body) {
            Ok(value) => Ok(value),
            Err(_) => {
                eprintln!("local API returned non-JSON response for {}", path);
                Err(format!("local API returned non-JSON response for {}", path))
            }
        }
    }
}

fn is_literal_loopback_host(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    match host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

#[cfg(test)]
fn is_loopback_host_with_resolver<F, I>(url: &reqwest::Url, mut resolve: F) -> bool
where
    F: FnMut(&str, u16) -> std::io::Result<I>,
    I: IntoIterator<Item = SocketAddr>,
{
    let Some(host) = url.host_str() else {
        return false;
    };
    match host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => {
            let Some(port) = url.port_or_known_default() else {
                return false;
            };
            let resolved = match resolve(host, port) {
                Ok(addresses) => addresses,
                Err(_) => return false,
            };
            let mut saw_address = false;
            for address in resolved {
                saw_address = true;
                if !address.ip().is_loopback() {
                    return false;
                }
            }
            saw_address
        }
    }
}

fn redact_url_for_display(raw: &str) -> String {
    let parsed = match reqwest::Url::parse(raw) {
        Ok(url) => url,
        Err(_) => return "<invalid-url>".to_string(),
    };

    let mut out = format!("{}://", parsed.scheme());
    if let Some(host) = parsed.host_str() {
        out.push_str(host);
    }
    if let Some(port) = parsed.port() {
        out.push(':');
        out.push_str(&port.to_string());
    }
    out
}

async fn read_limited_response_body(path: &str, response: &mut reqwest::Response) -> Result<String, String> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("reading response body for {path} failed: {e}"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_LOCAL_API_RESPONSE_BODY_BYTES {
            return Err(format!(
                "local API response for {} exceeded {} bytes",
                path, MAX_LOCAL_API_RESPONSE_BODY_BYTES
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).to_string())
}

fn parse_optional_bool_env_any(names: &[&str]) -> Result<Option<bool>, String> {
    for name in names {
        if let Some(raw) = std::env::var(name).ok() {
            let value = raw.trim();
            if value.is_empty() {
                continue;
            }
            let normalized = value.to_ascii_lowercase();
            return match normalized.as_str() {
                "1" | "true" | "yes" | "on" => Ok(Some(true)),
                "0" | "false" | "no" | "off" => Ok(Some(false)),
                _ => Err(format!(
                    "invalid {name} value '{value}' (allowed: 1, true, yes, on, 0, false, no, off)"
                )),
            };
        }
    }
    Ok(None)
}

fn first_non_empty_env(names: &[&str]) -> Option<String> {
    for name in names {
        if let Ok(raw) = std::env::var(name) {
            let value = raw.trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn validate_auth_bearer(value: &str) -> Result<(), String> {
    if value.len() > MAX_LOCAL_API_AUTH_BEARER_BYTES {
        return Err(format!(
            "TDPN_LOCAL_API_AUTH_BEARER must be <= {MAX_LOCAL_API_AUTH_BEARER_BYTES} chars"
        ));
    }
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(
            "TDPN_LOCAL_API_AUTH_BEARER contains invalid whitespace/control characters"
                .to_string(),
        );
    }
    if value.chars().any(|c| !is_valid_bearer_token_char(c)) {
        return Err(
            "TDPN_LOCAL_API_AUTH_BEARER must use only token68 characters [A-Za-z0-9-._~+/=]"
                .to_string(),
        );
    }
    Ok(())
}

fn is_valid_bearer_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '+' | '/' | '=')
}

fn default_path_profile() -> String {
    "2hop".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub bootstrap_directory: String,
    pub invite_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    #[serde(default = "default_path_profile")]
    pub path_profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_wait_sec: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready_timeout_sec: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_preflight: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prod_profile: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_route: Option<bool>,
}

impl ConnectRequest {
    pub fn validate(&self) -> Result<(), String> {
        let bootstrap = self.bootstrap_directory.trim();
        let invite_key = self.invite_key.trim();
        let session_token = self
            .session_token
            .as_deref()
            .map(str::trim)
            .unwrap_or("");

        let has_bootstrap = !bootstrap.is_empty();
        let has_invite = !invite_key.is_empty();
        let has_session = !session_token.is_empty();
        if !has_session && (!has_bootstrap || !has_invite) {
            return Err("connect requires either bootstrap_directory+invite_key or session_token".to_string());
        }

        if has_bootstrap {
            if bootstrap.len() > 2048 {
                return Err("bootstrap_directory must be <= 2048 chars".to_string());
            }
            let parsed = reqwest::Url::parse(bootstrap).map_err(|_| {
                "bootstrap_directory must be an absolute URL with http or https scheme".to_string()
            })?;
            match parsed.scheme() {
                "http" | "https" => {}
                _ => return Err("bootstrap_directory scheme must be http or https".to_string()),
            }
            if parsed.host_str().is_none() {
                return Err("bootstrap_directory host is required".to_string());
            }
            if parsed.scheme() == "http" && !is_literal_loopback_host(&parsed) {
                return Err(
                    "bootstrap_directory must use https for non-loopback hosts (http allowed only for literal loopback IPs 127.0.0.1 or ::1)"
                        .to_string(),
                );
            }
            if !parsed.username().is_empty() || parsed.password().is_some() {
                return Err("bootstrap_directory userinfo is not allowed".to_string());
            }
            if parsed.query().is_some() || parsed.fragment().is_some() {
                return Err("bootstrap_directory query/fragment are not allowed".to_string());
            }
        }

        if has_invite {
            if invite_key.len() > 512 {
                return Err("invite_key must be <= 512 chars".to_string());
            }
            if invite_key.chars().any(|c| c.is_control()) {
                return Err("invite_key contains invalid control characters".to_string());
            }
        }

        if has_session {
            if session_token.len() > 4096 {
                return Err("session_token must be <= 4096 chars".to_string());
            }
            if session_token.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err("session_token contains invalid control/whitespace characters".to_string());
            }
        }

        let effective_profile = self
            .policy_profile
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(self.path_profile.as_str());
        if !is_valid_path_profile(effective_profile) {
            return Err("path_profile must be one of: 1hop, 2hop, 3hop".to_string());
        }
        if let Some(interface) = self.interface.as_deref() {
            let interface = interface.trim();
            if !interface.is_empty() && !is_valid_interface_name(interface) {
                return Err(
                    "interface must start with wg, use only [A-Za-z0-9_.-], and be <= 15 chars"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileRequest {
    pub path_profile: String,
}

impl ProfileRequest {
    pub fn validate(&self) -> Result<(), String> {
        if !is_valid_path_profile(&self.path_profile) {
            return Err("path_profile must be one of: 1hop, 2hop, 3hop".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPMWalletChallengeRequest {
    pub wallet_address: String,
    pub wallet_provider: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPMWalletVerifyRequest {
    pub wallet_address: String,
    pub wallet_provider: String,
    pub challenge_id: String,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPMSessionStatusRequest {
    pub session_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPMClientRegisterRequest {
    pub session_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_profile: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPMOperatorApplyRequest {
    pub session_token: String,
    pub chain_operator_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_label: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPMOperatorStatusRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPMOperatorApproveRequest {
    pub wallet_address: String,
    pub approved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_token: Option<String>,
}

fn is_valid_path_profile(path_profile: &str) -> bool {
    matches!(path_profile, "1hop" | "2hop" | "3hop")
}

fn is_valid_interface_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 15 {
        return false;
    }
    if !value.starts_with("wg") {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn with_env<T>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(key, _)| (key.to_string(), std::env::var(key).ok()))
            .collect();
        for (key, value) in vars {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        let out = f();
        for (key, value) in saved {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        out
    }

    fn with_env_vars<T>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
        let _guard = env_lock().lock().expect("env lock");
        with_env(vars, f)
    }

    #[test]
    fn from_env_uses_safe_defaults() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", None),
                ("TDPN_LOCAL_API_TIMEOUT_SEC", None),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", None),
                ("TDPN_LOCAL_API_AUTH_BEARER", None),
                ("TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS", None),
                ("TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS", None),
            ],
            || {
                let cfg = LocalApiConfig::from_env().expect("from_env");
                assert_eq!(cfg.base_url, "http://127.0.0.1:8095");
                assert_eq!(cfg.timeout_sec, 20);
                assert!(!cfg.allow_remote);
                assert_eq!(cfg.auth_bearer, None);
                assert!(!cfg.allow_update_mutations);
                assert!(!cfg.allow_service_mutations);
            },
        );
    }

    #[test]
    fn from_env_rejects_non_http_schemes() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("ftp://127.0.0.1:8095")),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", Some("1")),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected scheme error");
                assert!(err.contains("unsupported scheme"), "{err}");
            },
        );
    }

    #[test]
    fn from_env_rejects_remote_host_by_default() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("http://100.64.0.10:8095")),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", None),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected loopback guard");
                assert!(err.contains("literal loopback IP"), "{err}");
            },
        );
    }

    #[test]
    fn from_env_rejects_localhost_without_remote_opt_in() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("http://localhost:8095")),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", None),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected literal loopback guard");
                assert!(err.contains("literal loopback IP"), "{err}");
            },
        );
    }

    #[test]
    fn from_env_rejects_userinfo_in_base_url() {
        with_env_vars(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("http://user:pass@127.0.0.1:8095")),
                ("TDPN_LOCAL_API_TIMEOUT_SEC", None),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", None),
                ("TDPN_LOCAL_API_AUTH_BEARER", None),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected userinfo rejection");
                assert!(err.contains("userinfo is not allowed"), "unexpected error: {err}");
            },
        );
    }

    #[test]
    fn from_env_rejects_query_and_fragment_in_base_url() {
        with_env_vars(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("http://127.0.0.1:8095?token=secret#frag")),
                ("TDPN_LOCAL_API_TIMEOUT_SEC", None),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", None),
                ("TDPN_LOCAL_API_AUTH_BEARER", None),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected query/fragment rejection");
                assert!(
                    err.contains("query and fragment are not allowed"),
                    "unexpected error: {err}"
                );
            },
        );
    }

    #[test]
    fn redacted_base_url_hides_sensitive_url_components() {
        let cfg = LocalApiConfig {
            base_url: "https://user:pass@example.com:8443/path?token=secret#frag".to_string(),
            timeout_sec: 20,
            allow_remote: true,
            auth_bearer: Some("token".to_string()),
            allow_update_mutations: false,
            allow_service_mutations: false,
        };
        assert_eq!(cfg.redacted_base_url(), "https://example.com:8443");
    }

    #[test]
    fn from_env_rejects_invalid_allow_remote_value() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("http://127.0.0.1:8095")),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", Some("maybe")),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected bool parse error");
                assert!(err.contains("invalid TDPN_LOCAL_API_ALLOW_REMOTE value"), "{err}");
            },
        );
    }

    #[test]
    fn from_env_rejects_remote_host_without_auth_when_opted_in() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("https://100.64.0.10:8095")),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", Some("true")),
                ("TDPN_LOCAL_API_AUTH_BEARER", None),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected auth requirement");
                assert!(err.contains("requires TDPN_LOCAL_API_AUTH_BEARER"), "{err}");
            },
        );
    }

    #[test]
    fn from_env_rejects_remote_host_without_https_when_opted_in() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("http://100.64.0.10:8095")),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", Some("1")),
                ("TDPN_LOCAL_API_AUTH_BEARER", Some("token")),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected https requirement");
                assert!(err.contains("must use https"), "{err}");
            },
        );
    }

    #[test]
    fn from_env_rejects_remote_opt_in_loopback_hostname_without_auth() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("http://localhost:8095")),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", Some("1")),
                ("TDPN_LOCAL_API_AUTH_BEARER", None),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected auth requirement");
                assert!(err.contains("requires TDPN_LOCAL_API_AUTH_BEARER"), "{err}");
            },
        );
    }

    #[test]
    fn from_env_rejects_remote_opt_in_loopback_hostname_without_https() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("http://localhost:8095")),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", Some("1")),
                ("TDPN_LOCAL_API_AUTH_BEARER", Some("token")),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected https requirement");
                assert!(err.contains("must use https"), "{err}");
            },
        );
    }

    #[test]
    fn from_env_allows_remote_host_when_opted_in() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("https://100.64.0.10:8095")),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", Some("1")),
                ("TDPN_LOCAL_API_AUTH_BEARER", Some("  test-token  ")),
            ],
            || {
                let cfg = LocalApiConfig::from_env().expect("from_env");
                assert_eq!(cfg.base_url, "https://100.64.0.10:8095");
                assert!(cfg.allow_remote);
                assert_eq!(cfg.auth_bearer.as_deref(), Some("test-token"));
            },
        );
    }

    #[test]
    fn from_env_rejects_auth_bearer_with_whitespace() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("https://100.64.0.10:8095")),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", Some("1")),
                ("TDPN_LOCAL_API_AUTH_BEARER", Some("token with-space")),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected auth bearer validation");
                assert!(
                    err.contains("invalid whitespace/control"),
                    "unexpected error: {err}"
                );
            },
        );
    }

    #[test]
    fn from_env_rejects_auth_bearer_with_control_chars() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("https://100.64.0.10:8095")),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", Some("1")),
                ("TDPN_LOCAL_API_AUTH_BEARER", Some("token\nbad")),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected auth bearer validation");
                assert!(
                    err.contains("invalid whitespace/control"),
                    "unexpected error: {err}"
                );
            },
        );
    }

    #[test]
    fn from_env_rejects_auth_bearer_over_limit() {
        let _guard = env_lock().lock().expect("env lock");
        let long_token = "t".repeat(MAX_LOCAL_API_AUTH_BEARER_BYTES + 1);
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("https://100.64.0.10:8095")),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", Some("1")),
                ("TDPN_LOCAL_API_AUTH_BEARER", Some(long_token.as_str())),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected auth bearer length validation");
                assert!(err.contains("must be <="), "unexpected error: {err}");
            },
        );
    }

    #[test]
    fn from_env_rejects_auth_bearer_with_non_token68_chars() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("https://100.64.0.10:8095")),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", Some("1")),
                ("TDPN_LOCAL_API_AUTH_BEARER", Some("token:bad")),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected auth bearer charset validation");
                assert!(err.contains("token68"), "unexpected error: {err}");
            },
        );
    }

    #[test]
    fn from_env_allows_auth_bearer_with_token68_chars() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("https://100.64.0.10:8095")),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", Some("1")),
                ("TDPN_LOCAL_API_AUTH_BEARER", Some("Abc-._~+/=123")),
            ],
            || {
                let cfg = LocalApiConfig::from_env().expect("from_env");
                assert_eq!(cfg.auth_bearer.as_deref(), Some("Abc-._~+/=123"));
            },
        );
    }

    #[test]
    fn from_env_parses_mutation_gate_flags() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("http://127.0.0.1:8095")),
                ("TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS", Some("1")),
                ("TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS", Some("true")),
                ("TDPN_LOCAL_API_AUTH_BEARER", Some("token")),
            ],
            || {
                let cfg = LocalApiConfig::from_env().expect("from_env");
                assert!(cfg.allow_update_mutations);
                assert!(cfg.allow_service_mutations);
            },
        );
    }

    #[test]
    fn from_env_rejects_mutation_gates_without_auth_token() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("http://127.0.0.1:8095")),
                ("TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS", Some("1")),
                ("TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS", Some("0")),
                ("TDPN_LOCAL_API_AUTH_BEARER", None),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected auth requirement");
                assert!(
                    err.contains("desktop mutation controls require TDPN_LOCAL_API_AUTH_BEARER"),
                    "{err}"
                );
            },
        );
    }

    #[test]
    fn from_env_rejects_invalid_mutation_gate_flag_value() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("http://127.0.0.1:8095")),
                ("TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS", Some("maybe")),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected bool parse error");
                assert!(
                    err.contains("invalid TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS value"),
                    "{err}"
                );
            },
        );
    }

    #[test]
    fn connect_request_requires_credentials_or_session() {
        let mut req = ConnectRequest {
            bootstrap_directory: "".to_string(),
            invite_key: "".to_string(),
            session_token: None,
            path_profile: "2hop".to_string(),
            policy_profile: None,
            interface: None,
            discovery_wait_sec: None,
            ready_timeout_sec: None,
            run_preflight: None,
            prod_profile: None,
            install_route: None,
        };
        let err_bootstrap = req.validate().expect_err("missing bootstrap");
        assert!(err_bootstrap.contains("session_token"), "{err_bootstrap}");

        req.bootstrap_directory = "http://127.0.0.1:8081".to_string();
        let err_invite = req.validate().expect_err("missing invite");
        assert!(err_invite.contains("session_token"), "{err_invite}");

        req.bootstrap_directory.clear();
        req.session_token = Some("testsession".to_string());
        req.validate().expect("session token connect should be accepted");
    }

    #[test]
    fn path_profile_validation_is_strict() {
        let bad_connect = ConnectRequest {
            bootstrap_directory: "http://127.0.0.1:8081".to_string(),
            invite_key: "inv-test".to_string(),
            session_token: None,
            path_profile: "private".to_string(),
            policy_profile: None,
            interface: None,
            discovery_wait_sec: None,
            ready_timeout_sec: None,
            run_preflight: None,
            prod_profile: None,
            install_route: None,
        };
        let err = bad_connect.validate().expect_err("invalid path profile");
        assert!(err.contains("1hop, 2hop, 3hop"), "{err}");

        let bad_profile = ProfileRequest {
            path_profile: "balanced".to_string(),
        };
        let profile_err = bad_profile.validate().expect_err("invalid set_profile");
        assert!(profile_err.contains("1hop, 2hop, 3hop"), "{profile_err}");
    }

    #[test]
    fn connect_request_rejects_bootstrap_with_query() {
        let req = ConnectRequest {
            bootstrap_directory: "https://directory.example.invalid:8081/path?debug=1".to_string(),
            invite_key: "inv-test".to_string(),
            session_token: None,
            path_profile: "2hop".to_string(),
            policy_profile: None,
            interface: None,
            discovery_wait_sec: None,
            ready_timeout_sec: None,
            run_preflight: None,
            prod_profile: None,
            install_route: None,
        };
        let err = req.validate().expect_err("expected query rejection");
        assert!(err.contains("query/fragment"), "{err}");
    }

    #[test]
    fn connect_request_rejects_invalid_interface_name() {
        let req = ConnectRequest {
            bootstrap_directory: "https://directory.example.invalid:8081".to_string(),
            invite_key: "inv-test".to_string(),
            session_token: None,
            path_profile: "2hop".to_string(),
            policy_profile: None,
            interface: Some("wg exit 0".to_string()),
            discovery_wait_sec: None,
            ready_timeout_sec: None,
            run_preflight: None,
            prod_profile: None,
            install_route: None,
        };
        let err = req.validate().expect_err("expected invalid interface");
        assert!(err.contains("interface"), "{err}");
    }

    #[test]
    fn connect_request_rejects_non_loopback_http_bootstrap() {
        let req = ConnectRequest {
            bootstrap_directory: "http://directory.example.invalid:8081".to_string(),
            invite_key: "inv-test".to_string(),
            session_token: None,
            path_profile: "2hop".to_string(),
            policy_profile: None,
            interface: None,
            discovery_wait_sec: None,
            ready_timeout_sec: None,
            run_preflight: None,
            prod_profile: None,
            install_route: None,
        };
        let err = req.validate().expect_err("expected https requirement");
        assert!(err.contains("must use https"), "{err}");
    }

    #[test]
    fn connect_request_rejects_http_localhost_bootstrap() {
        let req = ConnectRequest {
            bootstrap_directory: "http://localhost:8081".to_string(),
            invite_key: "inv-test".to_string(),
            session_token: None,
            path_profile: "2hop".to_string(),
            policy_profile: None,
            interface: None,
            discovery_wait_sec: None,
            ready_timeout_sec: None,
            run_preflight: None,
            prod_profile: None,
            install_route: None,
        };
        let err = req.validate().expect_err("expected localhost rejection");
        assert!(err.contains("literal loopback IPs"), "{err}");
    }

    #[test]
    fn connect_request_allows_loopback_http_bootstrap() {
        let req = ConnectRequest {
            bootstrap_directory: "http://127.0.0.1:8081".to_string(),
            invite_key: "inv-test".to_string(),
            session_token: None,
            path_profile: "2hop".to_string(),
            policy_profile: None,
            interface: None,
            discovery_wait_sec: None,
            ready_timeout_sec: None,
            run_preflight: None,
            prod_profile: None,
            install_route: None,
        };
        req.validate().expect("expected loopback http bootstrap to pass");
    }

    #[test]
    fn connect_request_accepts_wireguard_style_interface_name() {
        let req = ConnectRequest {
            bootstrap_directory: "https://directory.example.invalid:8081".to_string(),
            invite_key: "inv-test".to_string(),
            session_token: None,
            path_profile: "2hop".to_string(),
            policy_profile: None,
            interface: Some("wg-client_1".to_string()),
            discovery_wait_sec: None,
            ready_timeout_sec: None,
            run_preflight: None,
            prod_profile: None,
            install_route: None,
        };
        req.validate().expect("expected valid interface");
    }

    #[test]
    fn hostname_loopback_check_requires_resolved_loopback_addresses() {
        let url = reqwest::Url::parse("http://localhost:8095").expect("url");

        let all_loopback = is_loopback_host_with_resolver(&url, |_host, _port| {
            Ok(vec![
                "127.0.0.1:8095".parse::<SocketAddr>().expect("socket addr"),
                "[::1]:8095".parse::<SocketAddr>().expect("socket addr"),
            ])
        });
        assert!(all_loopback, "expected localhost loopback resolution to pass");

        let includes_remote = is_loopback_host_with_resolver(&url, |_host, _port| {
            Ok(vec![
                "127.0.0.1:8095".parse::<SocketAddr>().expect("socket addr"),
                "203.0.113.10:8095".parse::<SocketAddr>().expect("socket addr"),
            ])
        });
        assert!(
            !includes_remote,
            "expected hostname with non-loopback resolution to fail"
        );
    }
}
