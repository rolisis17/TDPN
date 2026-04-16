use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct LocalApiConfig {
    pub base_url: String,
    pub timeout_sec: u64,
    pub allow_remote: bool,
    pub auth_bearer: Option<String>,
}

impl LocalApiConfig {
    pub fn from_env() -> Result<Self, String> {
        let base_url = std::env::var("TDPN_LOCAL_API_BASE_URL")
            .ok()
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "http://127.0.0.1:8095".to_string());

        let timeout_sec = std::env::var("TDPN_LOCAL_API_TIMEOUT_SEC")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(20);

        let allow_remote = std::env::var("TDPN_LOCAL_API_ALLOW_REMOTE")
            .ok()
            .map(|v| v.trim() == "1")
            .unwrap_or(false);

        let parsed = reqwest::Url::parse(&base_url).map_err(|e| {
            format!(
                "invalid TDPN_LOCAL_API_BASE_URL '{base_url}': {e} (expected absolute URL like http://127.0.0.1:8095)"
            )
        })?;

        match parsed.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(format!(
                    "invalid TDPN_LOCAL_API_BASE_URL '{base_url}': unsupported scheme '{scheme}' (allowed: http, https)"
                ));
            }
        }

        if parsed.host_str().is_none() {
            return Err(format!(
                "invalid TDPN_LOCAL_API_BASE_URL '{base_url}': missing host"
            ));
        }

        if !allow_remote && !is_loopback_host(&parsed) {
            let host = parsed.host_str().unwrap_or("<missing-host>");
            return Err(format!(
                "TDPN_LOCAL_API_BASE_URL host '{host}' is not loopback; set TDPN_LOCAL_API_ALLOW_REMOTE=1 to allow remote hosts"
            ));
        }

        let auth_bearer = std::env::var("TDPN_LOCAL_API_AUTH_BEARER")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        Ok(Self {
            base_url,
            timeout_sec,
            allow_remote,
            auth_bearer,
        })
    }

    fn endpoint(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("{}{}", self.base_url, path)
        } else {
            format!("{}/{}", self.base_url, path)
        }
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

    async fn parse_response(&self, path: &str, response: reqwest::Response) -> Result<Value, String> {
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| format!("reading response body for {path} failed: {e}"))?;

        if !status.is_success() {
            let reason = status.canonical_reason().unwrap_or("request failed");
            return Err(format!(
                "local API {} {} for {}: {}",
                status.as_u16(),
                reason,
                path,
                body
            ));
        }

        if body.trim().is_empty() {
            return Ok(json!({ "ok": true }));
        }

        match serde_json::from_str::<Value>(&body) {
            Ok(value) => Ok(value),
            Err(_) => Ok(json!({ "raw": body })),
        }
    }
}

fn is_loopback_host(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

fn default_path_profile() -> String {
    "2hop".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub bootstrap_directory: String,
    pub invite_key: String,
    #[serde(default = "default_path_profile")]
    pub path_profile: String,
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
        if self.bootstrap_directory.trim().is_empty() {
            return Err("bootstrap_directory is required".to_string());
        }
        if self.invite_key.trim().is_empty() {
            return Err("invite_key is required".to_string());
        }
        if !is_valid_path_profile(&self.path_profile) {
            return Err("path_profile must be one of: 1hop, 2hop, 3hop".to_string());
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

fn is_valid_path_profile(path_profile: &str) -> bool {
    matches!(path_profile, "1hop" | "2hop" | "3hop")
}
