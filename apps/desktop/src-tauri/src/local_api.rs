use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;
#[cfg(test)]
use std::net::SocketAddr;
use std::time::Duration;

const MAX_LOCAL_API_RESPONSE_BODY_BYTES: usize = 256 * 1024;
const MAX_LOCAL_API_AUTH_BEARER_BYTES: usize = 4096;
const MAX_LOCAL_API_ERROR_DETAIL_CHARS: usize = 512;
const MAX_GPM_AUTH_VERIFY_FIELD_BYTES: usize = 4096;
const MAX_GPM_AUTH_VERIFY_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_GPM_AUTH_VERIFY_ENVELOPE_BYTES: usize = 32 * 1024;
const GPM_PUBLIC_VPN_RESERVATION_AMOUNT_MICROS: u64 = 200_000;
const GPM_PUBLIC_VPN_RESERVATION_CURRENCY: &str = "TDPNC";

#[derive(Clone, Debug)]
pub struct LocalApiConfig {
    pub base_url: String,
    pub timeout_sec: u64,
    pub allow_remote: bool,
    pub auth_bearer: Option<String>,
    pub allow_update_mutations: bool,
    pub allow_service_mutations: bool,
    pub connect_require_session: bool,
    pub allow_legacy_connect_override: bool,
    pub admin_console_enabled: bool,
}

impl LocalApiConfig {
    pub fn from_env() -> Result<Self, String> {
        let base_url = first_non_empty_env(&["GPM_LOCAL_API_BASE_URL", "TDPN_LOCAL_API_BASE_URL"])
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .unwrap_or_else(|| "http://127.0.0.1:8095".to_string());
        let base_url_display = redact_url_for_display(&base_url);

        let timeout_sec =
            first_non_empty_env(&["GPM_LOCAL_API_TIMEOUT_SEC", "TDPN_LOCAL_API_TIMEOUT_SEC"])
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(20);

        let allow_remote = parse_optional_bool_env_any(
            &["GPM_LOCAL_API_ALLOW_REMOTE", "TDPN_LOCAL_API_ALLOW_REMOTE"],
            "GPM_LOCAL_API_ALLOW_REMOTE",
            Some("TDPN_LOCAL_API_ALLOW_REMOTE"),
        )?
        .unwrap_or(false);
        let allow_update_mutations = parse_optional_bool_env_any(
            &[
                "GPM_LOCAL_API_ALLOW_UPDATE_MUTATIONS",
                "TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS",
            ],
            "GPM_LOCAL_API_ALLOW_UPDATE_MUTATIONS",
            Some("TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS"),
        )?
        .unwrap_or(false);
        let allow_service_mutations = parse_optional_bool_env_any(
            &[
                "GPM_LOCAL_API_ALLOW_SERVICE_MUTATIONS",
                "TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS",
            ],
            "GPM_LOCAL_API_ALLOW_SERVICE_MUTATIONS",
            Some("TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS"),
        )?
        .unwrap_or(false);
        let connect_require_session = parse_optional_bool_env_any(
            &[
                "GPM_LOCAL_API_CONNECT_REQUIRE_SESSION",
                "TDPN_LOCAL_API_CONNECT_REQUIRE_SESSION",
            ],
            "GPM_LOCAL_API_CONNECT_REQUIRE_SESSION",
            Some("TDPN_LOCAL_API_CONNECT_REQUIRE_SESSION"),
        )?
        .unwrap_or(false);
        let allow_legacy_connect_override = parse_optional_bool_env_any(
            &[
                "GPM_LOCAL_API_ALLOW_LEGACY_CONNECT_OVERRIDE",
                "TDPN_LOCAL_API_ALLOW_LEGACY_CONNECT_OVERRIDE",
            ],
            "GPM_LOCAL_API_ALLOW_LEGACY_CONNECT_OVERRIDE",
            Some("TDPN_LOCAL_API_ALLOW_LEGACY_CONNECT_OVERRIDE"),
        )?
        .unwrap_or(false);
        let admin_console_enabled = parse_optional_bool_env_any(
            &[
                "GPM_DESKTOP_ADMIN_CONSOLE",
                "GPM_ADMIN_CONSOLE",
                "TDPN_DESKTOP_ADMIN_CONSOLE",
            ],
            "GPM_DESKTOP_ADMIN_CONSOLE",
            Some("TDPN_DESKTOP_ADMIN_CONSOLE"),
        )?
        .unwrap_or_else(|| cfg!(feature = "admin-console"));

        let auth_bearer =
            first_non_empty_env(&["GPM_LOCAL_API_AUTH_BEARER", "TDPN_LOCAL_API_AUTH_BEARER"]);
        if let Some(token) = auth_bearer.as_deref() {
            validate_auth_bearer(token)?;
        }

        let parsed = reqwest::Url::parse(&base_url).map_err(|e| {
            format!(
                "invalid GPM_LOCAL_API_BASE_URL value '{base_url_display}': {e} (expected absolute URL like http://127.0.0.1:8095; legacy alias: TDPN_LOCAL_API_BASE_URL)"
            )
        })?;

        match parsed.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(format!(
                    "invalid GPM_LOCAL_API_BASE_URL value '{base_url_display}': unsupported scheme '{scheme}' (allowed: http, https; legacy alias: TDPN_LOCAL_API_BASE_URL)"
                ));
            }
        }

        if parsed.host_str().is_none() {
            return Err(format!(
                "invalid GPM_LOCAL_API_BASE_URL value '{base_url_display}': missing host (legacy alias: TDPN_LOCAL_API_BASE_URL)"
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(format!(
                "invalid GPM_LOCAL_API_BASE_URL value '{base_url_display}': userinfo is not allowed (legacy alias: TDPN_LOCAL_API_BASE_URL)"
            ));
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(format!(
                "invalid GPM_LOCAL_API_BASE_URL value '{base_url_display}': query and fragment are not allowed (legacy alias: TDPN_LOCAL_API_BASE_URL)"
            ));
        }

        let is_literal_loopback = is_literal_loopback_host(&parsed);
        if !allow_remote && !is_literal_loopback {
            let host = parsed.host_str().unwrap_or("<missing-host>");
            return Err(format!(
                "GPM_LOCAL_API_BASE_URL host '{host}' is not a literal loopback IP (use 127.0.0.1 or ::1); set GPM_LOCAL_API_ALLOW_REMOTE=1 to allow remote hosts (legacy aliases: TDPN_LOCAL_API_BASE_URL, TDPN_LOCAL_API_ALLOW_REMOTE)"
            ));
        }

        if allow_remote && !is_literal_loopback {
            if auth_bearer.is_none() {
                return Err(
                    "GPM_LOCAL_API_ALLOW_REMOTE=1 requires GPM_LOCAL_API_AUTH_BEARER for non-loopback hosts (legacy aliases: TDPN_LOCAL_API_ALLOW_REMOTE, TDPN_LOCAL_API_AUTH_BEARER)"
                        .to_string(),
                );
            }
            if parsed.scheme() != "https" {
                return Err(format!(
                    "GPM_LOCAL_API_BASE_URL '{base_url_display}' must use https when GPM_LOCAL_API_ALLOW_REMOTE=1 targets non-loopback hosts (legacy aliases: TDPN_LOCAL_API_BASE_URL, TDPN_LOCAL_API_ALLOW_REMOTE)"
                ));
            }
        }
        if (allow_update_mutations || allow_service_mutations) && auth_bearer.is_none() {
            return Err(
                "desktop mutation controls require GPM_LOCAL_API_AUTH_BEARER (set token before enabling GPM_LOCAL_API_ALLOW_UPDATE_MUTATIONS or GPM_LOCAL_API_ALLOW_SERVICE_MUTATIONS; legacy aliases: TDPN_LOCAL_API_AUTH_BEARER, TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS, TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS)"
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
            connect_require_session,
            allow_legacy_connect_override,
            admin_console_enabled,
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuntimePolicyConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_require_session: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_legacy_connect_override: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
}

impl RuntimePolicyConfig {
    pub fn from_config_payload(payload: &Value) -> Self {
        let connect_require_session = parse_runtime_config_bool(
            payload,
            &["connect_require_session", "connectRequireSession"],
        );
        let allow_legacy_connect_override = parse_runtime_config_bool(
            payload,
            &[
                "allow_legacy_connect_override",
                "allowLegacyConnectOverride",
            ],
        );
        let config = payload.get("config").cloned().or_else(|| {
            payload
                .get("data")
                .and_then(|value| value.get("config"))
                .cloned()
        });
        Self {
            connect_require_session,
            allow_legacy_connect_override,
            config,
        }
    }
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

    #[cfg(feature = "admin-console")]
    pub async fn get_json_with_query<T: Serialize + ?Sized>(
        &self,
        path: &str,
        query: &T,
    ) -> Result<Value, String> {
        let request = self.client.get(self.config.endpoint(path)).query(query);
        let response = self
            .with_optional_auth(request)
            .send()
            .await
            .map_err(|e| format!("GET {path} failed: {e}"))?;
        self.parse_response(path, response).await
    }

    #[cfg(feature = "admin-console")]
    pub async fn get_json_with_gpm_session_query<T: Serialize + ?Sized>(
        &self,
        path: &str,
        session_token: &str,
        query: &T,
    ) -> Result<Value, String> {
        let request = self
            .client
            .get(self.config.endpoint(path))
            .header("X-GPM-Session-Token", session_token)
            .query(query);
        let response = self
            .with_optional_auth(request)
            .send()
            .await
            .map_err(|e| format!("GET {path} failed: {e}"))?;
        self.parse_response(path, response).await
    }

    pub async fn get_runtime_policy_config(&self) -> Result<RuntimePolicyConfig, String> {
        let payload = self.get_json("/v1/config").await?;
        Ok(RuntimePolicyConfig::from_config_payload(&payload))
    }

    pub async fn post_json<T: Serialize + ?Sized>(
        &self,
        path: &str,
        payload: &T,
    ) -> Result<Value, String> {
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

    async fn parse_response(
        &self,
        path: &str,
        mut response: reqwest::Response,
    ) -> Result<Value, String> {
        let status = response.status();
        let body = read_limited_response_body(path, &mut response).await?;

        if !status.is_success() {
            let reason = status.canonical_reason().unwrap_or("request failed");
            let context = format!("local API {} {} for {}", status.as_u16(), reason, path);
            if let Some(error_detail) = extract_json_error_detail(&body) {
                let detailed = format!("{context}: {error_detail}");
                eprintln!("{detailed}");
                return Err(detailed);
            }
            eprintln!("{context}");
            return Err(context);
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

fn truncate_error_detail(text: &str) -> String {
    let trimmed = text.trim();
    let total = trimmed.chars().count();
    if total <= MAX_LOCAL_API_ERROR_DETAIL_CHARS {
        return trimmed.to_string();
    }
    let kept: String = trimmed
        .chars()
        .take(MAX_LOCAL_API_ERROR_DETAIL_CHARS)
        .collect();
    let omitted = total - MAX_LOCAL_API_ERROR_DETAIL_CHARS;
    format!("{kept}...[truncated {omitted} chars]")
}

fn is_sensitive_error_field_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    let compact = normalized.replace(['_', '-'], "");
    matches!(
        normalized.as_str(),
        "token"
            | "auth_token"
            | "authtoken"
            | "access_token"
            | "accesstoken"
            | "refresh_token"
            | "refreshtoken"
            | "secret"
            | "password"
            | "private_key"
            | "privatekey"
            | "invite_key"
            | "invitekey"
            | "compat_subject_hint"
            | "bearer"
            | "api_key"
            | "apikey"
            | "signature"
            | "signature_envelope"
            | "signed_message"
    ) || normalized.ends_with("_token")
        || normalized.ends_with("_secret")
        || normalized.ends_with("_password")
        || normalized.ends_with("_private_key")
        || normalized.ends_with("_invite_key")
        || normalized.ends_with("_api_key")
        || normalized.ends_with("_signature")
        || normalized.contains("subject_hint")
        || normalized.contains("private_key")
        || normalized.contains("privatekey")
        || normalized.contains("invite_key")
        || normalized.contains("invitekey")
        || normalized.contains("bearer")
        || normalized.contains("signature")
        || normalized.contains("secret")
        || normalized.contains("password")
        || compact.ends_with("token")
        || compact.ends_with("secret")
        || compact.ends_with("apikey")
}

fn redact_sensitive_error_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => {
            Value::Array(values.iter().map(redact_sensitive_error_value).collect())
        }
        Value::Object(object) => {
            let mut redacted = serde_json::Map::new();
            for (key, entry) in object {
                if is_sensitive_error_field_key(key) {
                    redacted.insert(key.clone(), Value::String("[REDACTED]".to_string()));
                } else {
                    redacted.insert(key.clone(), redact_sensitive_error_value(entry));
                }
            }
            Value::Object(redacted)
        }
        other => other.clone(),
    }
}

fn extract_json_error_detail(body: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(body).ok()?;
    let error_value = parsed.get("error")?;
    let raw = match error_value {
        Value::Null => return None,
        Value::String(text) => text.trim().to_string(),
        other => serde_json::to_string(&redact_sensitive_error_value(other))
            .ok()?
            .trim()
            .to_string(),
    };
    if raw.is_empty() {
        return None;
    }
    Some(truncate_error_detail(&raw))
}

fn parse_bool_like_json(value: Option<&Value>) -> Option<bool> {
    match value {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::Number(value)) => value.as_i64().map(|n| n != 0),
        Some(Value::String(value)) => {
            let normalized = value.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "1" | "true" | "yes" | "on" => Some(true),
                "0" | "false" | "no" | "off" => Some(false),
                _ => None,
            }
        }
        _ => None,
    }
}

fn parse_runtime_config_bool(payload: &Value, aliases: &[&str]) -> Option<bool> {
    parse_bool_like_json(runtime_config_lookup(payload.get("config"), aliases))
        .or_else(|| parse_bool_like_json(runtime_config_lookup(Some(payload), aliases)))
        .or_else(|| {
            parse_bool_like_json(runtime_config_lookup(
                payload.get("data").and_then(|value| value.get("config")),
                aliases,
            ))
        })
}

fn runtime_config_lookup<'a>(scope: Option<&'a Value>, aliases: &[&str]) -> Option<&'a Value> {
    let scope = scope?;
    for alias in aliases {
        if let Some(value) = scope.get(alias) {
            return Some(value);
        }
    }
    None
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

async fn read_limited_response_body(
    path: &str,
    response: &mut reqwest::Response,
) -> Result<String, String> {
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

fn parse_optional_bool_env_any(
    names: &[&str],
    preferred_name: &str,
    legacy_alias: Option<&str>,
) -> Result<Option<bool>, String> {
    let display_name = format_env_with_legacy_alias(preferred_name, legacy_alias);
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
                    "invalid {display_name} value '{value}' (allowed: 1, true, yes, on, 0, false, no, off)"
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
    let display_name = format_env_with_legacy_alias(
        "GPM_LOCAL_API_AUTH_BEARER",
        Some("TDPN_LOCAL_API_AUTH_BEARER"),
    );
    if value.len() > MAX_LOCAL_API_AUTH_BEARER_BYTES {
        return Err(format!(
            "{display_name} must be <= {MAX_LOCAL_API_AUTH_BEARER_BYTES} chars"
        ));
    }
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(format!(
            "{display_name} contains invalid whitespace/control characters"
        ));
    }
    if value.chars().any(|c| !is_valid_bearer_token_char(c)) {
        return Err(format!(
            "{display_name} must use only token68 characters [A-Za-z0-9-._~+/=]"
        ));
    }
    Ok(())
}

fn format_env_with_legacy_alias(preferred_name: &str, legacy_alias: Option<&str>) -> String {
    match legacy_alias {
        Some(alias) => format!("{preferred_name} (legacy alias: {alias})"),
        None => preferred_name.to_string(),
    }
}

fn is_valid_bearer_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '+' | '/' | '=')
}

fn default_path_profile() -> String {
    "2hop".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectRequest {
    #[serde(default)]
    pub bootstrap_directory: String,
    #[serde(default)]
    pub invite_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_bootstrap_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reservation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reservation_session_id: Option<String>,
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
        let session_token = self.session_token.as_deref().map(str::trim).unwrap_or("");

        let has_bootstrap = !bootstrap.is_empty();
        let has_invite = !invite_key.is_empty();
        let has_session = !session_token.is_empty();
        if !has_session && (!has_bootstrap || !has_invite) {
            return Err(
                "connect requires either bootstrap_directory+invite_key or session_token"
                    .to_string(),
            );
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
            if session_token
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
            {
                return Err(
                    "session_token contains invalid control/whitespace characters".to_string(),
                );
            }
        }
        validate_optional_bootstrap_directory(
            "session_bootstrap_directory",
            self.session_bootstrap_directory.as_deref(),
        )?;
        validate_optional_short_text("reservation_id", self.reservation_id.as_deref(), 256)?;
        validate_optional_short_text(
            "reservation_session_id",
            self.reservation_session_id.as_deref(),
            256,
        )?;

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

fn validate_optional_short_text(
    field: &str,
    value: Option<&str>,
    max_len: usize,
) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(());
    }
    if value.len() > max_len {
        return Err(format!("{field} must be <= {max_len} chars"));
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(format!("{field} contains invalid control characters"));
    }
    Ok(())
}

#[cfg(any(feature = "admin-console", test))]
#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileRequest {
    pub path_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

#[cfg(any(feature = "admin-console", test))]
impl ProfileRequest {
    pub fn validate(&self) -> Result<(), String> {
        validate_required_session_token(self.session_token.as_deref())?;
        if !is_valid_path_profile(&self.path_profile) {
            return Err("path_profile must be one of: 1hop, 2hop, 3hop".to_string());
        }
        Ok(())
    }
}

fn validate_required_session_token(session_token: Option<&str>) -> Result<(), String> {
    let token = session_token.unwrap_or("").trim();
    if token.is_empty() {
        return Err("session_token is required".to_string());
    }
    if token.chars().any(char::is_whitespace) {
        return Err("session_token cannot contain whitespace".to_string());
    }
    if token.len() > 4096 {
        return Err("session_token is too long".to_string());
    }
    Ok(())
}

fn validate_optional_bootstrap_directory(field: &str, value: Option<&str>) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(());
    }
    if value.len() > 2048 {
        return Err(format!("{field} must be <= 2048 chars"));
    }
    let parsed = reqwest::Url::parse(value)
        .map_err(|_| format!("{field} must be an absolute URL with http or https scheme"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => return Err(format!("{field} scheme must be http or https")),
    }
    if parsed.host_str().is_none() {
        return Err(format!("{field} host is required"));
    }
    if parsed.scheme() == "http" && !is_literal_loopback_host(&parsed) {
        return Err(format!(
            "{field} must use https for non-loopback hosts (http allowed only for literal loopback IPs 127.0.0.1 or ::1)"
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!("{field} userinfo is not allowed"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!("{field} query/fragment are not allowed"));
    }
    Ok(())
}

fn validate_optional_invite_key(value: Option<&str>) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(());
    }
    if value.len() > 512 {
        return Err("invite_key must be <= 512 chars".to_string());
    }
    if value.chars().any(|c| c.is_control()) {
        return Err("invite_key contains invalid control characters".to_string());
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPMWalletChallengeRequest {
    pub wallet_address: String,
    pub wallet_provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPMWalletVerifyRequest {
    pub wallet_address: String,
    pub wallet_provider: String,
    pub challenge_id: String,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_public_key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_envelope: Option<Value>,
}

impl GPMWalletVerifyRequest {
    pub fn validate(&self) -> Result<(), String> {
        validate_required_auth_verify_field("wallet_address", &self.wallet_address)?;
        validate_required_auth_verify_field("wallet_provider", &self.wallet_provider)?;
        validate_required_auth_verify_field("challenge_id", &self.challenge_id)?;
        validate_required_auth_verify_field("signature", &self.signature)?;
        validate_optional_auth_verify_field("signature_kind", self.signature_kind.as_deref())?;
        validate_optional_auth_verify_field(
            "signature_public_key",
            self.signature_public_key.as_deref(),
        )?;
        validate_optional_auth_verify_field(
            "signature_public_key_type",
            self.signature_public_key_type.as_deref(),
        )?;
        validate_optional_auth_verify_field("public_key", self.public_key.as_deref())?;
        validate_optional_auth_verify_field("public_key_type", self.public_key_type.as_deref())?;
        validate_optional_auth_verify_field("signature_source", self.signature_source.as_deref())?;
        validate_optional_auth_verify_field("chain_id", self.chain_id.as_deref())?;
        validate_optional_auth_verify_message("signed_message", self.signed_message.as_deref())?;
        if let Some(envelope) = &self.signature_envelope {
            let serialized = serde_json::to_string(envelope)
                .map_err(|err| format!("signature_envelope must be valid JSON: {err}"))?;
            if serialized.len() > MAX_GPM_AUTH_VERIFY_ENVELOPE_BYTES {
                return Err(format!(
                    "signature_envelope must be <= {MAX_GPM_AUTH_VERIFY_ENVELOPE_BYTES} chars"
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPMSessionStatusRequest {
    pub session_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

impl GPMSessionStatusRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.session_token.trim().is_empty() {
            return Err("session_token is required".to_string());
        }
        if let Some(action) = self.action.as_deref() {
            let normalized = action.trim().to_ascii_lowercase();
            if normalized.is_empty() {
                return Ok(());
            }
            if !matches!(normalized.as_str(), "status" | "refresh" | "revoke") {
                return Err("action must be one of: status, refresh, revoke".to_string());
            }
        }
        Ok(())
    }
}

fn validate_required_auth_verify_field(name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{name} is required"));
    }
    validate_auth_verify_text_len(name, value, MAX_GPM_AUTH_VERIFY_FIELD_BYTES)
}

fn validate_optional_auth_verify_field(name: &str, value: Option<&str>) -> Result<(), String> {
    if let Some(value) = value {
        validate_auth_verify_text_len(name, value, MAX_GPM_AUTH_VERIFY_FIELD_BYTES)?;
    }
    Ok(())
}

fn validate_optional_auth_verify_message(name: &str, value: Option<&str>) -> Result<(), String> {
    if let Some(value) = value {
        validate_auth_verify_text_len(name, value, MAX_GPM_AUTH_VERIFY_MESSAGE_BYTES)?;
    }
    Ok(())
}

fn validate_auth_verify_text_len(name: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.len() > max_len {
        return Err(format!("{name} must be <= {max_len} chars"));
    }
    Ok(())
}

#[cfg(feature = "admin-console")]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GPMAuditRecentRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<String>,
}

#[cfg(feature = "admin-console")]
impl GPMAuditRecentRequest {
    pub fn sanitize(self) -> Result<Self, String> {
        let session_token = self
            .session_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
            .ok_or_else(|| "session_token is required".to_string())?;
        if session_token.len() > 4096 {
            return Err("session_token must be <= 4096 chars".to_string());
        }
        if session_token
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err("session_token contains invalid control/whitespace characters".to_string());
        }
        let limit = self.limit.unwrap_or(25).clamp(1, 200);
        let offset = self.offset.unwrap_or(0);
        let event = self
            .event
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_ascii_lowercase());
        let wallet_address = self
            .wallet_address
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string());
        let normalized_order = self.order.unwrap_or_else(|| "desc".to_string());
        let order = match normalized_order.trim().to_ascii_lowercase().as_str() {
            "" | "desc" => "desc".to_string(),
            "asc" => "asc".to_string(),
            _ => return Err("order must be one of: desc, asc".to_string()),
        };
        Ok(Self {
            session_token: Some(session_token),
            limit: Some(limit),
            offset: Some(offset),
            event,
            wallet_address,
            order: Some(order),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPMClientStatusRequest {
    pub session_token: String,
}

impl GPMClientStatusRequest {
    pub fn validate(&self) -> Result<(), String> {
        validate_required_session_token(Some(&self.session_token))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPMServerStatusRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_address: Option<String>,
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

impl GPMClientRegisterRequest {
    pub fn validate(&self) -> Result<(), String> {
        validate_required_session_token(Some(&self.session_token))?;
        validate_optional_bootstrap_directory(
            "bootstrap_directory",
            self.bootstrap_directory.as_deref(),
        )?;
        validate_optional_invite_key(self.invite_key.as_deref())?;
        if let Some(path_profile) = self.path_profile.as_deref() {
            let path_profile = path_profile.trim();
            if !path_profile.is_empty() && !is_valid_path_profile(path_profile) {
                return Err("path_profile must be one of: 1hop, 2hop, 3hop".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPMContributionStatusRequest {
    pub session_token: String,
}

impl GPMContributionStatusRequest {
    pub fn validate(&self) -> Result<(), String> {
        validate_required_session_token(Some(&self.session_token))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPMContributionToggleRequest {
    pub session_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

impl GPMContributionToggleRequest {
    pub fn validate(&self) -> Result<(), String> {
        validate_required_session_token(Some(&self.session_token))?;
        if let Some(role) = self.role.as_deref() {
            let role = role.trim();
            if !role.is_empty()
                && !matches!(
                    role,
                    "micro-relay" | "micro-exit" | "micro_relay" | "micro_exit" | "relay" | "exit"
                )
            {
                return Err("role must be one of: micro-relay, micro-exit".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GPMSettlementReserveFundsRequest {
    pub session_token: String,
    pub session_id: String,
    pub amount_micros: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reservation_id: Option<String>,
}

impl GPMSettlementReserveFundsRequest {
    pub fn validate(&self) -> Result<(), String> {
        validate_required_session_token(Some(&self.session_token))?;
        validate_optional_short_text("session_id", Some(&self.session_id), 256)?;
        if self.session_id.trim().is_empty() {
            return Err("session_id is required".to_string());
        }
        if self.amount_micros == 0 {
            return Err("amount_micros must be > 0".to_string());
        }
        if self.amount_micros != GPM_PUBLIC_VPN_RESERVATION_AMOUNT_MICROS {
            return Err(format!(
                "amount_micros must equal the public VPN reservation amount {}",
                GPM_PUBLIC_VPN_RESERVATION_AMOUNT_MICROS
            ));
        }
        validate_optional_short_text("currency", self.currency.as_deref(), 32)?;
        if let Some(currency) = self.currency.as_deref() {
            if !currency
                .trim()
                .eq_ignore_ascii_case(GPM_PUBLIC_VPN_RESERVATION_CURRENCY)
            {
                return Err(format!(
                    "currency must be {GPM_PUBLIC_VPN_RESERVATION_CURRENCY} for public VPN reservations"
                ));
            }
        }
        validate_optional_short_text("reservation_id", self.reservation_id.as_deref(), 256)?;
        Ok(())
    }
}

#[cfg(feature = "admin-console")]
#[derive(Debug, Serialize, Deserialize)]
pub struct GPMAdminContributionListRequest {
    pub session_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[cfg(feature = "admin-console")]
#[derive(Debug, Serialize, Deserialize)]
pub struct GPMAdminRewardReviewRequest {
    pub session_token: String,
    pub wallet_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub week_start_utc: Option<String>,
}

#[cfg(feature = "admin-console")]
#[derive(Debug, Serialize, Deserialize)]
pub struct GPMAdminRewardHoldRequest {
    pub session_token: String,
    pub wallet_address: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub week_start_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg(feature = "admin-console")]
#[derive(Debug, Serialize, Deserialize)]
pub struct GPMAdminRewardFinalizeRequest {
    pub session_token: String,
    pub wallet_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub week_start_utc: Option<String>,
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

#[cfg(feature = "admin-console")]
#[derive(Debug, Serialize, Deserialize)]
pub struct GPMOperatorListRequest {
    pub session_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[cfg(feature = "admin-console")]
#[derive(Debug, Serialize, Deserialize)]
pub struct GPMOperatorApproveRequest {
    pub wallet_address: String,
    pub approved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub if_updated_at_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
    fn runtime_policy_config_reads_connect_flags_and_carries_config_payload() {
        let payload = json!({
            "ok": true,
            "config": {
                "connect_require_session": true,
                "allow_legacy_connect_override": false,
                "gpm_manifest_require_https": true,
                "profile_default_gate_allow_remote_http_probe": false
            }
        });
        let policy = RuntimePolicyConfig::from_config_payload(&payload);
        assert_eq!(policy.connect_require_session, Some(true));
        assert_eq!(policy.allow_legacy_connect_override, Some(false));
        let config = policy.config.expect("runtime config payload");
        assert_eq!(
            config
                .get("gpm_manifest_require_https")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            config
                .get("profile_default_gate_allow_remote_http_probe")
                .and_then(Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn runtime_policy_config_uses_data_config_fallback_when_top_level_missing() {
        let payload = json!({
            "ok": true,
            "data": {
                "config": {
                    "connectRequireSession": "1",
                    "allowLegacyConnectOverride": "0",
                    "profile_default_gate_allow_insecure_probe": true
                }
            }
        });
        let policy = RuntimePolicyConfig::from_config_payload(&payload);
        assert_eq!(policy.connect_require_session, Some(true));
        assert_eq!(policy.allow_legacy_connect_override, Some(false));
        let config = policy.config.expect("runtime data.config payload");
        assert_eq!(
            config
                .get("profile_default_gate_allow_insecure_probe")
                .and_then(Value::as_bool),
            Some(true)
        );
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
                ("TDPN_LOCAL_API_CONNECT_REQUIRE_SESSION", None),
                ("GPM_LOCAL_API_CONNECT_REQUIRE_SESSION", None),
                ("TDPN_LOCAL_API_ALLOW_LEGACY_CONNECT_OVERRIDE", None),
                ("GPM_LOCAL_API_ALLOW_LEGACY_CONNECT_OVERRIDE", None),
                ("GPM_DESKTOP_ADMIN_CONSOLE", None),
                ("GPM_ADMIN_CONSOLE", None),
                ("TDPN_DESKTOP_ADMIN_CONSOLE", None),
            ],
            || {
                let cfg = LocalApiConfig::from_env().expect("from_env");
                assert_eq!(cfg.base_url, "http://127.0.0.1:8095");
                assert_eq!(cfg.timeout_sec, 20);
                assert!(!cfg.allow_remote);
                assert_eq!(cfg.auth_bearer, None);
                assert!(!cfg.allow_update_mutations);
                assert!(!cfg.allow_service_mutations);
                assert!(!cfg.connect_require_session);
                assert!(!cfg.allow_legacy_connect_override);
                assert_eq!(cfg.admin_console_enabled, cfg!(feature = "admin-console"));
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
                (
                    "TDPN_LOCAL_API_BASE_URL",
                    Some("http://user:pass@127.0.0.1:8095"),
                ),
                ("TDPN_LOCAL_API_TIMEOUT_SEC", None),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", None),
                ("TDPN_LOCAL_API_AUTH_BEARER", None),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected userinfo rejection");
                assert!(
                    err.contains("userinfo is not allowed"),
                    "unexpected error: {err}"
                );
            },
        );
    }

    #[test]
    fn from_env_rejects_query_and_fragment_in_base_url() {
        with_env_vars(
            &[
                (
                    "TDPN_LOCAL_API_BASE_URL",
                    Some("http://127.0.0.1:8095?token=secret#frag"),
                ),
                ("TDPN_LOCAL_API_TIMEOUT_SEC", None),
                ("TDPN_LOCAL_API_ALLOW_REMOTE", None),
                ("TDPN_LOCAL_API_AUTH_BEARER", None),
            ],
            || {
                let err =
                    LocalApiConfig::from_env().expect_err("expected query/fragment rejection");
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
            connect_require_session: false,
            allow_legacy_connect_override: false,
            admin_console_enabled: false,
        };
        assert_eq!(cfg.redacted_base_url(), "https://example.com:8443");
    }

    #[test]
    fn from_env_enables_admin_console_explicitly() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("GPM_DESKTOP_ADMIN_CONSOLE", Some("1")),
                ("GPM_ADMIN_CONSOLE", None),
                ("TDPN_DESKTOP_ADMIN_CONSOLE", None),
            ],
            || {
                let cfg = LocalApiConfig::from_env().expect("from_env");
                assert!(cfg.admin_console_enabled);
            },
        );
    }

    #[test]
    fn from_env_admin_console_env_zero_is_kill_switch() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("GPM_DESKTOP_ADMIN_CONSOLE", Some("0")),
                ("GPM_ADMIN_CONSOLE", None),
                ("TDPN_DESKTOP_ADMIN_CONSOLE", None),
            ],
            || {
                let cfg = LocalApiConfig::from_env().expect("from_env");
                assert!(!cfg.admin_console_enabled);
            },
        );
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
                assert!(err.contains("invalid GPM_LOCAL_API_ALLOW_REMOTE"), "{err}");
                assert!(
                    err.contains("legacy alias: TDPN_LOCAL_API_ALLOW_REMOTE"),
                    "{err}"
                );
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
                assert!(err.contains("requires GPM_LOCAL_API_AUTH_BEARER"), "{err}");
                assert!(
                    err.contains(
                        "legacy aliases: TDPN_LOCAL_API_ALLOW_REMOTE, TDPN_LOCAL_API_AUTH_BEARER"
                    ),
                    "{err}"
                );
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
                assert!(err.contains("requires GPM_LOCAL_API_AUTH_BEARER"), "{err}");
                assert!(
                    err.contains(
                        "legacy aliases: TDPN_LOCAL_API_ALLOW_REMOTE, TDPN_LOCAL_API_AUTH_BEARER"
                    ),
                    "{err}"
                );
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
                let err =
                    LocalApiConfig::from_env().expect_err("expected auth bearer length validation");
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
                let err = LocalApiConfig::from_env()
                    .expect_err("expected auth bearer charset validation");
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
                    err.contains("desktop mutation controls require GPM_LOCAL_API_AUTH_BEARER"),
                    "{err}"
                );
                assert!(
                    err.contains(
                        "legacy aliases: TDPN_LOCAL_API_AUTH_BEARER, TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS, TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS"
                    ),
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
                    err.contains("invalid GPM_LOCAL_API_ALLOW_UPDATE_MUTATIONS"),
                    "{err}"
                );
                assert!(
                    err.contains("legacy alias: TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS"),
                    "{err}"
                );
            },
        );
    }

    #[test]
    fn from_env_parses_connect_require_session_flags() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("http://127.0.0.1:8095")),
                ("TDPN_LOCAL_API_CONNECT_REQUIRE_SESSION", Some("0")),
                ("GPM_LOCAL_API_CONNECT_REQUIRE_SESSION", Some("1")),
            ],
            || {
                let cfg = LocalApiConfig::from_env().expect("from_env");
                assert!(cfg.connect_require_session);
            },
        );
    }

    #[test]
    fn from_env_rejects_invalid_connect_require_session_flag_value() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("http://127.0.0.1:8095")),
                ("TDPN_LOCAL_API_CONNECT_REQUIRE_SESSION", Some("maybe")),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected bool parse error");
                assert!(
                    err.contains("invalid GPM_LOCAL_API_CONNECT_REQUIRE_SESSION"),
                    "{err}"
                );
                assert!(
                    err.contains("legacy alias: TDPN_LOCAL_API_CONNECT_REQUIRE_SESSION"),
                    "{err}"
                );
            },
        );
    }

    #[test]
    fn from_env_parses_allow_legacy_connect_override_flags() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("http://127.0.0.1:8095")),
                ("TDPN_LOCAL_API_ALLOW_LEGACY_CONNECT_OVERRIDE", Some("0")),
                ("GPM_LOCAL_API_ALLOW_LEGACY_CONNECT_OVERRIDE", Some("1")),
            ],
            || {
                let cfg = LocalApiConfig::from_env().expect("from_env");
                assert!(cfg.allow_legacy_connect_override);
            },
        );
    }

    #[test]
    fn from_env_rejects_invalid_allow_legacy_connect_override_flag_value() {
        let _guard = env_lock().lock().expect("env lock");
        with_env(
            &[
                ("TDPN_LOCAL_API_BASE_URL", Some("http://127.0.0.1:8095")),
                (
                    "TDPN_LOCAL_API_ALLOW_LEGACY_CONNECT_OVERRIDE",
                    Some("maybe"),
                ),
            ],
            || {
                let err = LocalApiConfig::from_env().expect_err("expected bool parse error");
                assert!(
                    err.contains("invalid GPM_LOCAL_API_ALLOW_LEGACY_CONNECT_OVERRIDE"),
                    "{err}"
                );
                assert!(
                    err.contains("legacy alias: TDPN_LOCAL_API_ALLOW_LEGACY_CONNECT_OVERRIDE"),
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
            session_bootstrap_directory: None,
            reservation_id: None,
            reservation_session_id: None,
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
        req.validate()
            .expect("session token connect should be accepted");
    }

    #[test]
    fn connect_request_serializes_production_reservation_fields() {
        let req = ConnectRequest {
            bootstrap_directory: "".to_string(),
            invite_key: "".to_string(),
            session_token: Some("gpm-session-token".to_string()),
            session_bootstrap_directory: None,
            reservation_id: Some("res-desktop-1".to_string()),
            reservation_session_id: Some("gpm-vpn-session-1".to_string()),
            path_profile: "2hop".to_string(),
            policy_profile: None,
            interface: None,
            discovery_wait_sec: None,
            ready_timeout_sec: None,
            run_preflight: None,
            prod_profile: Some(true),
            install_route: None,
        };
        req.validate()
            .expect("reservation-bound session connect should validate");
        let value = serde_json::to_value(&req).expect("serialize request");
        assert_eq!(value["reservation_id"], "res-desktop-1");
        assert_eq!(value["reservation_session_id"], "gpm-vpn-session-1");
    }

    #[test]
    fn connect_request_deserializes_production_session_payload_without_legacy_fields() {
        let req: ConnectRequest = serde_json::from_value(serde_json::json!({
            "session_token": "gpm-session-token",
            "session_bootstrap_directory": "https://bootstrap-a.globalprivatemesh.net:8081",
            "reservation_id": "res-desktop-1",
            "reservation_session_id": "gpm-vpn-session-1",
            "prod_profile": true
        }))
        .expect("deserialize production connect request");

        req.validate()
            .expect("session-token production connect should not require legacy bootstrap fields");
        assert!(req.bootstrap_directory.is_empty());
        assert!(req.invite_key.is_empty());
        assert_eq!(req.path_profile, "2hop");
        assert_eq!(
            req.session_bootstrap_directory.as_deref(),
            Some("https://bootstrap-a.globalprivatemesh.net:8081")
        );
        assert_eq!(req.reservation_id.as_deref(), Some("res-desktop-1"));
        assert_eq!(
            req.reservation_session_id.as_deref(),
            Some("gpm-vpn-session-1")
        );
    }

    #[test]
    fn gpm_settlement_reserve_funds_request_validates_public_app_shape() {
        let request = GPMSettlementReserveFundsRequest {
            session_token: "gpm-session-token".to_string(),
            session_id: "gpm-vpn-session-1".to_string(),
            amount_micros: 200000,
            currency: Some("TDPNC".to_string()),
            reservation_id: Some("res-desktop-1".to_string()),
        };
        request
            .validate()
            .expect("expected desktop reserve-funds request to validate");
        let missing_amount = GPMSettlementReserveFundsRequest {
            amount_micros: 0,
            ..request.clone()
        };
        let err = missing_amount
            .validate()
            .expect_err("expected missing amount rejection");
        assert!(err.contains("amount_micros"), "{err}");

        let wrong_amount = GPMSettlementReserveFundsRequest {
            amount_micros: 300000,
            ..request.clone()
        };
        let err = wrong_amount
            .validate()
            .expect_err("expected fixed amount rejection");
        assert!(err.contains("public VPN reservation amount"), "{err}");

        let wrong_currency = GPMSettlementReserveFundsRequest {
            currency: Some("BAD".to_string()),
            ..request.clone()
        };
        let err = wrong_currency
            .validate()
            .expect_err("expected fixed currency rejection");
        assert!(err.contains("currency must be TDPNC"), "{err}");
    }

    #[test]
    fn gpm_public_requests_validate_before_daemon_forward() {
        let register = GPMClientRegisterRequest {
            session_token: "gpm-session-token".to_string(),
            bootstrap_directory: Some("https://bootstrap.globalprivatemesh.net".to_string()),
            invite_key: Some("inv-test".to_string()),
            path_profile: Some("2hop".to_string()),
        };
        register.validate().expect("valid client register");

        let bad_register = GPMClientRegisterRequest {
            path_profile: Some("private".to_string()),
            ..register
        };
        let err = bad_register
            .validate()
            .expect_err("expected invalid path_profile rejection");
        assert!(err.contains("path_profile"), "{err}");

        let status = GPMContributionStatusRequest {
            session_token: "gpm-session-token".to_string(),
        };
        status.validate().expect("valid contribution status");

        let bad_status = GPMContributionStatusRequest {
            session_token: " ".to_string(),
        };
        let err = bad_status
            .validate()
            .expect_err("expected session_token rejection");
        assert!(err.contains("session_token"), "{err}");

        let toggle = GPMContributionToggleRequest {
            session_token: "gpm-session-token".to_string(),
            role: Some("micro-relay".to_string()),
        };
        toggle.validate().expect("valid contribution role");

        let bad_toggle = GPMContributionToggleRequest {
            role: Some("validator".to_string()),
            ..toggle
        };
        let err = bad_toggle
            .validate()
            .expect_err("expected role enum rejection");
        assert!(err.contains("micro-relay"), "{err}");
    }

    #[test]
    fn path_profile_validation_is_strict() {
        let bad_connect = ConnectRequest {
            bootstrap_directory: "http://127.0.0.1:8081".to_string(),
            invite_key: "inv-test".to_string(),
            session_token: None,
            session_bootstrap_directory: None,
            reservation_id: None,
            reservation_session_id: None,
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
            session_token: Some("session-123".to_string()),
        };
        let profile_err = bad_profile.validate().expect_err("invalid set_profile");
        assert!(profile_err.contains("1hop, 2hop, 3hop"), "{profile_err}");

        let missing_session_profile = ProfileRequest {
            path_profile: "2hop".to_string(),
            session_token: None,
        };
        let session_err = missing_session_profile
            .validate()
            .expect_err("missing session token");
        assert!(
            session_err.contains("session_token is required"),
            "{session_err}"
        );
    }

    #[test]
    fn gpm_session_request_requires_token_and_valid_action() {
        let missing_token = GPMSessionStatusRequest {
            session_token: "   ".to_string(),
            action: Some("status".to_string()),
        };
        let token_err = missing_token
            .validate()
            .expect_err("expected missing token validation error");
        assert!(
            token_err.contains("session_token is required"),
            "{token_err}"
        );

        let invalid_action = GPMSessionStatusRequest {
            session_token: "gpm-token".to_string(),
            action: Some("rotate".to_string()),
        };
        let action_err = invalid_action
            .validate()
            .expect_err("expected invalid action validation error");
        assert!(
            action_err.contains("status, refresh, revoke"),
            "{action_err}"
        );

        let valid_status = GPMSessionStatusRequest {
            session_token: "gpm-token".to_string(),
            action: Some("status".to_string()),
        };
        valid_status
            .validate()
            .expect("expected status action to validate");

        let valid_refresh = GPMSessionStatusRequest {
            session_token: "gpm-token".to_string(),
            action: Some("refresh".to_string()),
        };
        valid_refresh
            .validate()
            .expect("expected refresh action to validate");

        let valid_revoke = GPMSessionStatusRequest {
            session_token: "gpm-token".to_string(),
            action: Some("revoke".to_string()),
        };
        valid_revoke
            .validate()
            .expect("expected revoke action to validate");
    }

    #[test]
    fn gpm_wallet_verify_request_preserves_strict_proof_metadata() {
        let request = GPMWalletVerifyRequest {
            wallet_address: "cosmos1wallet".to_string(),
            wallet_provider: "keplr".to_string(),
            challenge_id: "challenge-1".to_string(),
            signature: "MEUCIQDexample".to_string(),
            signature_kind: Some("sign_arbitrary".to_string()),
            signature_public_key: Some("Aq1publickey".to_string()),
            signature_public_key_type: Some("secp256k1".to_string()),
            public_key: None,
            public_key_type: None,
            signature_source: Some("wallet_extension".to_string()),
            chain_id: Some("gpm-mainnet-1".to_string()),
            signed_message: Some("Sign in to Global Private Mesh".to_string()),
            signature_envelope: Some(serde_json::json!({
                "pub_key": {
                    "type": "tendermint/PubKeySecp256k1",
                    "value": "Aq1publickey"
                }
            })),
        };

        request
            .validate()
            .expect("expected strict proof metadata to validate");
        let value = serde_json::to_value(&request).expect("serialize request");
        assert_eq!(value["signature_kind"], "sign_arbitrary");
        assert_eq!(value["signature_public_key"], "Aq1publickey");
        assert_eq!(value["signature_public_key_type"], "secp256k1");
        assert_eq!(value["signature_source"], "wallet_extension");
        assert_eq!(value["chain_id"], "gpm-mainnet-1");
        assert_eq!(value["signed_message"], "Sign in to Global Private Mesh");
        assert_eq!(
            value["signature_envelope"]["pub_key"]["type"],
            "tendermint/PubKeySecp256k1"
        );
    }

    #[test]
    fn gpm_wallet_verify_request_rejects_oversized_signature_envelope() {
        let request = GPMWalletVerifyRequest {
            wallet_address: "cosmos1wallet".to_string(),
            wallet_provider: "keplr".to_string(),
            challenge_id: "challenge-1".to_string(),
            signature: "MEUCIQDexample".to_string(),
            signature_kind: None,
            signature_public_key: None,
            signature_public_key_type: None,
            public_key: None,
            public_key_type: None,
            signature_source: None,
            chain_id: None,
            signed_message: None,
            signature_envelope: Some(serde_json::json!({
                "blob": "x".repeat(MAX_GPM_AUTH_VERIFY_ENVELOPE_BYTES + 1)
            })),
        };

        let err = request
            .validate()
            .expect_err("expected oversized signature envelope rejection");
        assert!(err.contains("signature_envelope"), "{err}");
    }

    #[cfg(feature = "admin-console")]
    #[test]
    fn gpm_audit_recent_request_requires_admin_session_token() {
        let missing = GPMAuditRecentRequest {
            session_token: None,
            limit: Some(10),
            offset: None,
            event: None,
            wallet_address: None,
            order: None,
        };
        let err = missing
            .sanitize()
            .expect_err("expected missing token error");
        assert!(err.contains("session_token is required"), "{err}");

        let invalid = GPMAuditRecentRequest {
            session_token: Some("token with spaces".to_string()),
            limit: Some(10),
            offset: None,
            event: None,
            wallet_address: None,
            order: None,
        };
        let err = invalid
            .sanitize()
            .expect_err("expected invalid token error");
        assert!(err.contains("session_token contains invalid"), "{err}");

        let request = GPMAuditRecentRequest {
            session_token: Some("  gpm-admin-token  ".to_string()),
            limit: Some(999),
            offset: Some(3),
            event: Some(" AUTH_VERIFIED ".to_string()),
            wallet_address: Some(" cosmos1admin ".to_string()),
            order: Some("ASC".to_string()),
        }
        .sanitize()
        .expect("expected audit request to sanitize");

        assert_eq!(request.session_token.as_deref(), Some("gpm-admin-token"));
        assert_eq!(request.limit, Some(200));
        assert_eq!(request.offset, Some(3));
        assert_eq!(request.event.as_deref(), Some("auth_verified"));
        assert_eq!(request.wallet_address.as_deref(), Some("cosmos1admin"));
        assert_eq!(request.order.as_deref(), Some("asc"));
    }

    #[test]
    fn connect_request_rejects_bootstrap_with_query() {
        let req = ConnectRequest {
            bootstrap_directory: "https://directory.example.invalid:8081/path?debug=1".to_string(),
            invite_key: "inv-test".to_string(),
            session_token: None,
            session_bootstrap_directory: None,
            reservation_id: None,
            reservation_session_id: None,
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
            session_bootstrap_directory: None,
            reservation_id: None,
            reservation_session_id: None,
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
            session_bootstrap_directory: None,
            reservation_id: None,
            reservation_session_id: None,
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
            session_bootstrap_directory: None,
            reservation_id: None,
            reservation_session_id: None,
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
            session_bootstrap_directory: None,
            reservation_id: None,
            reservation_session_id: None,
            path_profile: "2hop".to_string(),
            policy_profile: None,
            interface: None,
            discovery_wait_sec: None,
            ready_timeout_sec: None,
            run_preflight: None,
            prod_profile: None,
            install_route: None,
        };
        req.validate()
            .expect("expected loopback http bootstrap to pass");
    }

    #[test]
    fn connect_request_accepts_wireguard_style_interface_name() {
        let req = ConnectRequest {
            bootstrap_directory: "https://directory.example.invalid:8081".to_string(),
            invite_key: "inv-test".to_string(),
            session_token: None,
            session_bootstrap_directory: None,
            reservation_id: None,
            reservation_session_id: None,
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
    fn extract_json_error_detail_reads_error_field_when_present() {
        let detail = extract_json_error_detail(r#"{"error":"stale operator application"}"#)
            .expect("expected detail");
        assert_eq!(detail, "stale operator application");

        let object_detail = extract_json_error_detail(r#"{"error":{"code":"stale","retry":true}}"#)
            .expect("expected object detail");
        assert!(
            object_detail.contains("\"code\":\"stale\""),
            "expected object detail to preserve JSON structure: {object_detail}"
        );
    }

    #[test]
    fn extract_json_error_detail_redacts_sensitive_fields_in_error_objects() {
        let detail = extract_json_error_detail(
            r#"{"error":{"code":"stale","session_token":"abc123","nested":{"invite_key":"inv-1","token_type":"bearer"}}}"#,
        )
        .expect("expected detail");
        assert!(
            detail.contains("\"code\":\"stale\""),
            "expected non-sensitive field to remain visible: {detail}"
        );
        assert!(
            detail.contains("\"session_token\":\"[REDACTED]\""),
            "expected session token to be redacted: {detail}"
        );
        assert!(
            detail.contains("\"invite_key\":\"[REDACTED]\""),
            "expected nested invite key to be redacted: {detail}"
        );
        assert!(
            detail.contains("\"token_type\":\"bearer\""),
            "expected non-sensitive token_type field to remain visible: {detail}"
        );
        assert!(!detail.contains("abc123"), "raw secret leaked: {detail}");
        assert!(!detail.contains("inv-1"), "raw invite key leaked: {detail}");
    }

    #[test]
    fn extract_json_error_detail_uses_safe_truncation_and_ignores_missing_error() {
        let long_error = "x".repeat(MAX_LOCAL_API_ERROR_DETAIL_CHARS + 7);
        let payload = format!(r#"{{"error":"{}"}}"#, long_error);
        let detail = extract_json_error_detail(&payload).expect("expected truncated detail");
        assert!(
            detail.contains("[truncated 7 chars]"),
            "expected truncation marker: {detail}"
        );
        assert_eq!(
            detail.chars().take(5).collect::<String>(),
            "xxxxx",
            "expected retained content prefix"
        );

        assert!(
            extract_json_error_detail(r#"{"message":"no error key"}"#).is_none(),
            "expected missing error field to return None"
        );
        assert!(
            extract_json_error_detail(r#"{"error":"   "}"#).is_none(),
            "expected blank error string to return None"
        );
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
        assert!(
            all_loopback,
            "expected localhost loopback resolution to pass"
        );

        let includes_remote = is_loopback_host_with_resolver(&url, |_host, _port| {
            Ok(vec![
                "127.0.0.1:8095".parse::<SocketAddr>().expect("socket addr"),
                "203.0.113.10:8095"
                    .parse::<SocketAddr>()
                    .expect("socket addr"),
            ])
        });
        assert!(
            !includes_remote,
            "expected hostname with non-loopback resolution to fail"
        );
    }
}
