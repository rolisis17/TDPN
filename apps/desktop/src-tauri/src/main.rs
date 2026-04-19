mod local_api;

use local_api::{
    ConnectRequest, GPMClientRegisterRequest, GPMOperatorApplyRequest, GPMOperatorApproveRequest,
    GPMOperatorStatusRequest, GPMSessionStatusRequest, GPMWalletChallengeRequest,
    GPMWalletVerifyRequest, LocalApiClient, LocalApiConfig, ProfileRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

struct AppState {
    local_api: LocalApiClient,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct ServiceLifecycleRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_token: Option<String>,
}

#[derive(Serialize)]
struct ControlConfig {
    base_url: String,
    timeout_sec: u64,
    allow_remote: bool,
    auth_bearer_configured: bool,
    allow_update_mutations: bool,
    allow_service_mutations: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    update_channel: Option<String>,
    update_feed_configured: bool,
    product_name: String,
    product_short_name: String,
    api_contract: String,
}

#[tauri::command]
fn control_config(state: State<'_, AppState>) -> ControlConfig {
    let cfg = state.local_api.config();
    ControlConfig {
        base_url: cfg.redacted_base_url(),
        timeout_sec: cfg.timeout_sec,
        allow_remote: cfg.allow_remote,
        auth_bearer_configured: cfg.auth_bearer.is_some(),
        allow_update_mutations: cfg.allow_update_mutations,
        allow_service_mutations: cfg.allow_service_mutations,
        update_channel: optional_env_any(&["GPM_DESKTOP_UPDATE_CHANNEL", "TDPN_DESKTOP_UPDATE_CHANNEL"]),
        update_feed_configured: optional_env_any(&[
            "GPM_DESKTOP_UPDATE_FEED_CONFIGURED",
            "TDPN_DESKTOP_UPDATE_FEED_CONFIGURED",
        ])
            .map(|v| v == "1")
            .unwrap_or_else(|| {
                optional_env_any(&["GPM_DESKTOP_UPDATE_FEED_URL", "TDPN_DESKTOP_UPDATE_FEED_URL"])
                    .is_some()
            }),
        product_name: "Global Private Mesh".to_string(),
        product_short_name: "GPM".to_string(),
        api_contract: "gpm-v1-with-tdpn-compat".to_string(),
    }
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn optional_env_any(names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(value) = optional_env(name) {
            return Some(value);
        }
    }
    None
}

fn remove_unbounded_output_fields(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(remove_unbounded_output_fields)
                .collect(),
        ),
        Value::Object(mut object) => {
            object.remove("output");
            object.remove("raw");
            for entry in object.values_mut() {
                let next = std::mem::take(entry);
                *entry = remove_unbounded_output_fields(next);
            }
            Value::Object(object)
        }
        other => other,
    }
}

fn is_sensitive_field_key(key: &str) -> bool {
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
            | "bearer"
            | "api_key"
            | "apikey"
    ) || normalized.ends_with("_token")
        || normalized.ends_with("_secret")
        || normalized.ends_with("_password")
        || normalized.ends_with("_private_key")
        || normalized.ends_with("_invite_key")
        || normalized.ends_with("_api_key")
        || normalized.contains("private_key")
        || normalized.contains("privatekey")
        || normalized.contains("invite_key")
        || normalized.contains("invitekey")
        || normalized.contains("bearer")
        || normalized.contains("secret")
        || normalized.contains("password")
        || compact.ends_with("token")
        || compact.ends_with("secret")
        || compact.ends_with("apikey")
}

fn redact_sensitive_fields(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(redact_sensitive_fields).collect()),
        Value::Object(mut object) => {
            for (key, entry) in object.iter_mut() {
                if is_sensitive_field_key(key) {
                    *entry = Value::String("[REDACTED]".to_string());
                    continue;
                }
                let next = std::mem::take(entry);
                *entry = redact_sensitive_fields(next);
            }
            Value::Object(object)
        }
        other => other,
    }
}

fn sanitize_desktop_payload(value: Value) -> Value {
    redact_sensitive_fields(remove_unbounded_output_fields(value))
}

fn fallback_to_legacy_service_endpoint(error: &str) -> bool {
    let normalized = error.to_ascii_lowercase();
    normalized.contains("404 not found") || normalized.contains("501 not implemented")
}

fn diagnostics_allowlisted_view(payload: Value) -> Value {
    let mut response = Map::new();
    response.insert(
        "ok".to_string(),
        Value::Bool(payload.get("ok").and_then(Value::as_bool).unwrap_or(false)),
    );
    if let Some(error) = payload.get("error") {
        response.insert("error".to_string(), error.clone());
    }

    let Some(diagnostics) = payload.get("diagnostics").and_then(Value::as_object) else {
        return Value::Object(response);
    };

    let mut diagnostics_view = Map::new();
    if let Some(status) = diagnostics.get("status").and_then(Value::as_str) {
        diagnostics_view.insert("status".to_string(), Value::String(status.to_string()));
    }
    if let Some(generated_at_utc) = diagnostics.get("generated_at_utc").and_then(Value::as_str) {
        diagnostics_view.insert(
            "generated_at_utc".to_string(),
            Value::String(generated_at_utc.to_string()),
        );
    }

    if let Some(summary) = diagnostics.get("summary").and_then(Value::as_object) {
        let mut summary_view = Map::new();
        for key in ["findings_total", "warnings_total", "failures_total"] {
            if let Some(value) = summary.get(key).and_then(Value::as_i64) {
                summary_view.insert(key.to_string(), Value::Number(value.into()));
            }
        }
        if !summary_view.is_empty() {
            diagnostics_view.insert("summary".to_string(), Value::Object(summary_view));
        }
    }

    if let Some(inputs) = diagnostics.get("inputs").and_then(Value::as_object) {
        let mut inputs_view = Map::new();
        for key in ["base_port", "client_iface", "exit_iface", "vpn_iface"] {
            if let Some(value) = inputs.get(key) {
                inputs_view.insert(key.to_string(), value.clone());
            }
        }
        if !inputs_view.is_empty() {
            diagnostics_view.insert("inputs".to_string(), Value::Object(inputs_view));
        }
    }

    if let Some(findings) = diagnostics.get("findings").and_then(Value::as_array) {
        let mut findings_view = Vec::new();
        for finding in findings.iter().take(100) {
            let Some(finding_obj) = finding.as_object() else {
                continue;
            };
            let mut finding_view = Map::new();
            for key in ["severity", "code", "message", "remediation"] {
                if let Some(value) = finding_obj.get(key).and_then(Value::as_str) {
                    finding_view.insert(key.to_string(), Value::String(value.to_string()));
                }
            }
            if !finding_view.is_empty() {
                findings_view.push(Value::Object(finding_view));
            }
        }
        diagnostics_view.insert("findings".to_string(), Value::Array(findings_view));
        if findings.len() > 100 {
            diagnostics_view.insert("findings_truncated".to_string(), Value::Bool(true));
        }
    }

    response.insert("diagnostics".to_string(), Value::Object(diagnostics_view));
    Value::Object(response)
}

#[tauri::command]
async fn control_health(state: State<'_, AppState>) -> Result<Value, String> {
    state
        .local_api
        .get_json("/v1/health")
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_status(state: State<'_, AppState>) -> Result<Value, String> {
    state
        .local_api
        .get_json("/v1/status")
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_get_diagnostics(state: State<'_, AppState>) -> Result<Value, String> {
    state
        .local_api
        .get_json("/v1/get_diagnostics")
        .await
        .map(diagnostics_allowlisted_view)
}

#[tauri::command]
async fn control_connect(state: State<'_, AppState>, request: ConnectRequest) -> Result<Value, String> {
    request.validate()?;
    state
        .local_api
        .post_json("/v1/connect", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_disconnect(state: State<'_, AppState>) -> Result<Value, String> {
    state
        .local_api
        .post_empty("/v1/disconnect")
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_set_profile(state: State<'_, AppState>, request: ProfileRequest) -> Result<Value, String> {
    request.validate()?;
    state
        .local_api
        .post_json("/v1/set_profile", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_update(state: State<'_, AppState>) -> Result<Value, String> {
    if !state.local_api.config().allow_update_mutations {
        return Err(
            "desktop update action disabled (set GPM_LOCAL_API_ALLOW_UPDATE_MUTATIONS=1; legacy alias: TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS=1)"
                .to_string(),
        );
    }
    state
        .local_api
        .post_empty("/v1/update")
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_service_status(state: State<'_, AppState>) -> Result<Value, String> {
    state
        .local_api
        .get_json("/v1/service/status")
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_service_start(
    state: State<'_, AppState>,
    request: Option<ServiceLifecycleRequest>,
) -> Result<Value, String> {
    control_service_lifecycle(state, "start", request.unwrap_or_default()).await
}

async fn control_service_lifecycle(
    state: State<'_, AppState>,
    action: &str,
    request: ServiceLifecycleRequest,
) -> Result<Value, String> {
    if !state.local_api.config().allow_service_mutations {
        return Err(
            "service lifecycle actions disabled (set GPM_LOCAL_API_ALLOW_SERVICE_MUTATIONS=1; legacy alias: TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS=1)"
                .to_string(),
        );
    }
    let gpm_path = format!("/v1/gpm/service/{action}");
    match state.local_api.post_json(&gpm_path, &request).await {
        Ok(value) => Ok(sanitize_desktop_payload(value)),
        Err(error) if fallback_to_legacy_service_endpoint(&error) => {
            let legacy_path = format!("/v1/service/{action}");
            state
                .local_api
                .post_empty(&legacy_path)
                .await
                .map(sanitize_desktop_payload)
        }
        Err(error) => Err(error),
    }
}

#[tauri::command]
async fn control_service_stop(
    state: State<'_, AppState>,
    request: Option<ServiceLifecycleRequest>,
) -> Result<Value, String> {
    control_service_lifecycle(state, "stop", request.unwrap_or_default()).await
}

#[tauri::command]
async fn control_service_restart(
    state: State<'_, AppState>,
    request: Option<ServiceLifecycleRequest>,
) -> Result<Value, String> {
    control_service_lifecycle(state, "restart", request.unwrap_or_default()).await
}

#[tauri::command]
async fn control_gpm_bootstrap_manifest(state: State<'_, AppState>) -> Result<Value, String> {
    state
        .local_api
        .get_json("/v1/gpm/bootstrap/manifest")
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_auth_challenge(
    state: State<'_, AppState>,
    request: GPMWalletChallengeRequest,
) -> Result<Value, String> {
    state
        .local_api
        .post_json("/v1/gpm/auth/challenge", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_auth_verify(
    state: State<'_, AppState>,
    request: GPMWalletVerifyRequest,
) -> Result<Value, String> {
    state
        .local_api
        .post_json("/v1/gpm/auth/verify", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_session(
    state: State<'_, AppState>,
    request: GPMSessionStatusRequest,
) -> Result<Value, String> {
    state
        .local_api
        .post_json("/v1/gpm/session", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_audit_recent(
    state: State<'_, AppState>,
    limit: Option<u32>,
) -> Result<Value, String> {
    let limit = limit.unwrap_or(25).clamp(1, 200);
    state
        .local_api
        .get_json(&format!("/v1/gpm/audit/recent?limit={limit}"))
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_client_register(
    state: State<'_, AppState>,
    request: GPMClientRegisterRequest,
) -> Result<Value, String> {
    state
        .local_api
        .post_json("/v1/gpm/onboarding/client/register", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_operator_apply(
    state: State<'_, AppState>,
    request: GPMOperatorApplyRequest,
) -> Result<Value, String> {
    state
        .local_api
        .post_json("/v1/gpm/onboarding/operator/apply", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_operator_status(
    state: State<'_, AppState>,
    request: GPMOperatorStatusRequest,
) -> Result<Value, String> {
    state
        .local_api
        .post_json("/v1/gpm/onboarding/operator/status", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_operator_approve(
    state: State<'_, AppState>,
    request: GPMOperatorApproveRequest,
) -> Result<Value, String> {
    state
        .local_api
        .post_json("/v1/gpm/onboarding/operator/approve", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(test)]
mod tests {
    use super::{sanitize_desktop_payload, Value};
    use serde_json::json;

    #[test]
    fn sanitize_desktop_payload_removes_unbounded_and_redacts_secret_fields() {
        let payload = json!({
            "ok": true,
            "output": "very large diagnostic output",
            "nested": {
                "raw": "raw-command-output",
                "invite_key": "inv-sensitive",
                "token": "abc123",
                "accessToken": "access-sensitive",
                "clientSecret": "secret-sensitive",
                "token_type": "client_access",
                "password_hint": "unsafe",
                "array": [
                    {"api_key": "k-1"},
                    {"refreshToken": "k-2"},
                    {"public": "safe"}
                ]
            }
        });

        let sanitized = sanitize_desktop_payload(payload);
        assert!(sanitized.get("output").is_none());
        let nested = sanitized
            .get("nested")
            .and_then(Value::as_object)
            .expect("nested object");
        assert!(nested.get("raw").is_none());
        assert_eq!(nested.get("invite_key"), Some(&json!("[REDACTED]")));
        assert_eq!(nested.get("token"), Some(&json!("[REDACTED]")));
        assert_eq!(nested.get("accessToken"), Some(&json!("[REDACTED]")));
        assert_eq!(nested.get("clientSecret"), Some(&json!("[REDACTED]")));
        assert_eq!(nested.get("token_type"), Some(&json!("client_access")));
        assert_eq!(nested.get("password_hint"), Some(&json!("[REDACTED]")));
        let array = nested
            .get("array")
            .and_then(Value::as_array)
            .expect("array");
        assert_eq!(
            array[0].get("api_key"),
            Some(&json!("[REDACTED]")),
            "api_key should be redacted"
        );
        assert_eq!(array[1].get("refreshToken"), Some(&json!("[REDACTED]")));
        assert_eq!(array[2].get("public"), Some(&json!("safe")));
    }
}

fn main() {
    let local_api_config = LocalApiConfig::from_env()
        .expect("failed to load local daemon API configuration from environment");
    let local_api = LocalApiClient::new(local_api_config)
        .expect("failed to initialize local daemon API client");

    tauri::Builder::default()
        .manage(AppState { local_api })
        .invoke_handler(tauri::generate_handler![
            control_config,
            control_health,
            control_status,
            control_get_diagnostics,
            control_connect,
            control_disconnect,
            control_set_profile,
            control_update,
            control_service_status,
            control_service_start,
            control_service_stop,
            control_service_restart,
            control_gpm_bootstrap_manifest,
            control_gpm_auth_challenge,
            control_gpm_auth_verify,
            control_gpm_session,
            control_gpm_audit_recent,
            control_gpm_client_register,
            control_gpm_operator_apply,
            control_gpm_operator_status,
            control_gpm_operator_approve
        ])
        .run(tauri::generate_context!())
        .expect("error while running Global Private Mesh (GPM) desktop scaffold");
}
