mod local_api;

use local_api::{
    ConnectRequest, GPMClientRegisterRequest, GPMClientStatusRequest, GPMContributionStatusRequest,
    GPMContributionToggleRequest, GPMSessionStatusRequest, GPMSettlementReserveFundsRequest,
    GPMWalletChallengeRequest, GPMWalletVerifyRequest, LocalApiClient, LocalApiConfig,
    RuntimePolicyConfig,
};
#[cfg(feature = "admin-console")]
use local_api::{
    GPMAdminContributionListRequest, GPMAdminRewardFinalizeRequest, GPMAdminRewardHoldRequest,
    GPMAdminRewardReviewRequest, GPMAuditRecentRequest, GPMOperatorApplyRequest,
    GPMOperatorApproveRequest, GPMOperatorListRequest, GPMOperatorStatusRequest,
    GPMServerStatusRequest, ProfileRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tauri::State;

struct AppState {
    local_api: LocalApiClient,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct ServiceLifecycleRequest {
    #[serde(default)]
    session_token: String,
}

#[cfg(any(feature = "admin-console", test))]
impl ServiceLifecycleRequest {
    fn validate(&self) -> Result<(), String> {
        validate_admin_session_token(&self.session_token)
    }
}

#[cfg(any(feature = "admin-console", test))]
fn validate_admin_session_token(session_token: &str) -> Result<(), String> {
    let token = session_token.trim();
    if token.is_empty() {
        return Err("session_token is required for Admin Console mutations".to_string());
    }
    if token.chars().any(char::is_whitespace) {
        return Err("session_token cannot contain whitespace".to_string());
    }
    if token.len() > 4096 {
        return Err("session_token is too long".to_string());
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
struct GPMOnboardingOverviewRequest {
    session_token: String,
}

impl GPMOnboardingOverviewRequest {
    fn validate(&self) -> Result<(), String> {
        if self.session_token.trim().is_empty() {
            return Err("session_token is required".to_string());
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ControlConfig {
    base_url: String,
    timeout_sec: u64,
    allow_remote: bool,
    auth_bearer_configured: bool,
    allow_update_mutations: bool,
    allow_service_mutations: bool,
    connect_require_session: bool,
    allow_legacy_connect_override: bool,
    admin_console_enabled: bool,
    app_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    update_channel: Option<String>,
    update_feed_configured: bool,
    product_name: String,
    product_short_name: String,
    api_contract: String,
}

#[derive(Serialize)]
struct RuntimePolicyView {
    available: bool,
    policy_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    connect_require_session: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_legacy_connect_override: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[tauri::command]
fn control_config(state: State<'_, AppState>) -> ControlConfig {
    let cfg = state.local_api.config();
    let admin_console_enabled = cfg!(feature = "admin-console") && cfg.admin_console_enabled;
    ControlConfig {
        base_url: cfg.redacted_base_url(),
        timeout_sec: cfg.timeout_sec,
        allow_remote: cfg.allow_remote,
        auth_bearer_configured: cfg.auth_bearer.is_some(),
        allow_update_mutations: cfg.allow_update_mutations,
        allow_service_mutations: cfg.allow_service_mutations,
        connect_require_session: cfg.connect_require_session,
        allow_legacy_connect_override: cfg.allow_legacy_connect_override,
        admin_console_enabled,
        app_mode: if admin_console_enabled {
            "admin_console".to_string()
        } else {
            "public_app".to_string()
        },
        update_channel: optional_env_any(&[
            "GPM_DESKTOP_UPDATE_CHANNEL",
            "TDPN_DESKTOP_UPDATE_CHANNEL",
        ]),
        update_feed_configured: optional_env_any(&[
            "GPM_DESKTOP_UPDATE_FEED_CONFIGURED",
            "TDPN_DESKTOP_UPDATE_FEED_CONFIGURED",
        ])
        .map(|v| v == "1")
        .unwrap_or_else(|| {
            optional_env_any(&[
                "GPM_DESKTOP_UPDATE_FEED_URL",
                "TDPN_DESKTOP_UPDATE_FEED_URL",
            ])
            .is_some()
        }),
        product_name: "Global Private Mesh".to_string(),
        product_short_name: "GPM".to_string(),
        api_contract: "gpm-v1-with-tdpn-compat".to_string(),
    }
}

#[cfg(any(feature = "admin-console", test))]
fn ensure_admin_console_config(config: &LocalApiConfig, action: &str) -> Result<(), String> {
    if !cfg!(feature = "admin-console") {
        return Err(format!(
            "{action} is available only in the separate GPM Admin Console build (compile with cargo feature `admin-console`; the public GPM App does not expose admin commands)"
        ));
    }
    if config.admin_console_enabled {
        return Ok(());
    }
    Err(format!(
        "{action} is available only in the separate GPM Admin Console (Admin Console feature builds are enabled by default; unset GPM_DESKTOP_ADMIN_CONSOLE or set it to 1, legacy alias: TDPN_DESKTOP_ADMIN_CONSOLE=1; set it to 0 only as a kill switch)"
    ))
}

#[cfg(feature = "admin-console")]
fn ensure_admin_console_state(state: &State<'_, AppState>, action: &str) -> Result<(), String> {
    ensure_admin_console_config(state.local_api.config(), action)
}

#[tauri::command]
async fn control_runtime_config(state: State<'_, AppState>) -> Result<RuntimePolicyView, String> {
    let view = match state.local_api.get_runtime_policy_config().await {
        Ok(RuntimePolicyConfig {
            connect_require_session,
            allow_legacy_connect_override,
            config,
        }) => {
            let config = config.and_then(sanitize_runtime_policy_config_for_renderer);
            let has_runtime_policy = connect_require_session.is_some()
                || allow_legacy_connect_override.is_some()
                || config.is_some();
            RuntimePolicyView {
                available: true,
                policy_source: if has_runtime_policy {
                    "runtime_config".to_string()
                } else {
                    "env_default".to_string()
                },
                connect_require_session,
                allow_legacy_connect_override,
                config,
                note: if has_runtime_policy {
                    None
                } else {
                    Some(
                        "runtime config missing policy flags (connect_require_session/allow_legacy_connect_override); using env default"
                            .to_string(),
                    )
                },
            }
        }
        Err(_) => RuntimePolicyView {
            available: false,
            policy_source: "config_unavailable".to_string(),
            connect_require_session: Some(true),
            allow_legacy_connect_override: Some(false),
            config: None,
            note: Some(
                "runtime config unavailable; failing closed until /v1/config is reachable"
                    .to_string(),
            ),
        },
    };
    Ok(view)
}

fn normalize_runtime_policy_key(key: &str) -> String {
    key.trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

fn runtime_policy_leaf_key_allowed(normalized: &str) -> bool {
    matches!(
        normalized,
        "connectrequiresession"
            | "allowlegacyconnectoverride"
            | "gpmmanifestrequirehttps"
            | "manifestrequirehttps"
            | "requirehttps"
            | "httpsrequiredbypolicy"
            | "gpmmanifestrequiresignature"
            | "manifestrequiresignature"
            | "requiresignature"
            | "signaturerequiredbypolicy"
            | "gpmmanifesttrustpolicysource"
            | "manifesttrustpolicysource"
            | "manifestpolicysource"
            | "policysource"
            | "gpmauthverifyrequiremetadata"
            | "authverifyrequiremetadata"
            | "requiremetadata"
            | "gpmauthverifymetadatamode"
            | "authverifymetadatamode"
            | "metadatamode"
            | "gpmauthverifypolicysource"
            | "authverifypolicysource"
            | "gpmauthverifyrequirewalletextensionsource"
            | "authverifyrequirewalletextensionsource"
            | "requirewalletextensionsource"
            | "gpmauthverifyrequirewalletextensionsourcepolicysource"
            | "authverifyrequirewalletextensionsourcepolicysource"
            | "gpmoperatorapprovalrequiresession"
            | "operatorapprovalrequiresession"
            | "approvalrequiresession"
            | "gpmoperatorapprovalpolicysource"
            | "operatorapprovalpolicysource"
            | "gpmoperatorapprovalrequiresessionpolicysource"
            | "operatorapprovalrequiresessionpolicysource"
            | "gpmproductionmode"
            | "productionmode"
            | "gpmproductionmodepolicysource"
            | "productionmodepolicysource"
            | "profiledefaultgateallowremotehttpprobe"
            | "gpmprofiledefaultgateallowremotehttpprobe"
            | "allowremotehttpprobe"
            | "profiledefaultgateallowinsecureprobe"
            | "gpmprofiledefaultgateallowinsecureprobe"
            | "allowinsecureprobe"
            | "profiledefaultgateprobepolicysource"
            | "profilegateprobepolicysource"
            | "probepolicysource"
    )
}

fn runtime_policy_container_key_allowed(normalized: &str) -> bool {
    matches!(
        normalized,
        "config"
            | "data"
            | "policy"
            | "policies"
            | "authverifypolicy"
            | "authverify"
            | "auth"
            | "operatorapprovalpolicy"
            | "operatorapproval"
            | "operator"
            | "manifesttrustpolicy"
            | "bootstrapmanifestpolicy"
            | "bootstrapmanifest"
            | "manifest"
            | "profiledefaultgatepolicy"
            | "profiledefaultgate"
            | "profilegate"
            | "profile"
            | "productionmode"
            | "production"
    )
}

fn sanitize_runtime_policy_value_for_renderer(value: &Value) -> Option<Value> {
    let Value::Object(object) = value else {
        return None;
    };
    let mut sanitized = Map::new();
    for (key, entry) in object {
        let normalized = normalize_runtime_policy_key(key);
        if runtime_policy_leaf_key_allowed(&normalized) {
            match entry {
                Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                    sanitized.insert(key.clone(), entry.clone());
                }
                Value::Object(_) => {
                    if runtime_policy_container_key_allowed(&normalized) {
                        if let Some(nested) = sanitize_runtime_policy_value_for_renderer(entry) {
                            sanitized.insert(key.clone(), nested);
                        }
                    }
                }
                _ => {}
            }
            continue;
        }
        if runtime_policy_container_key_allowed(&normalized) {
            if let Some(nested) = sanitize_runtime_policy_value_for_renderer(entry) {
                sanitized.insert(key.clone(), nested);
            }
        }
    }
    if sanitized.is_empty() {
        None
    } else {
        Some(Value::Object(sanitized))
    }
}

fn sanitize_runtime_policy_config_for_renderer(value: Value) -> Option<Value> {
    sanitize_runtime_policy_value_for_renderer(&value)
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
            | "compat_subject_hint"
            | "bearer"
            | "api_key"
            | "apikey"
    ) || normalized.ends_with("_token")
        || normalized.ends_with("_secret")
        || normalized.ends_with("_password")
        || normalized.ends_with("_private_key")
        || normalized.ends_with("_invite_key")
        || normalized.ends_with("_api_key")
        || normalized.contains("subject_hint")
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
        Value::Array(values) => {
            Value::Array(values.into_iter().map(redact_sensitive_fields).collect())
        }
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

fn sanitize_token_issuing_payload(value: Value) -> Value {
    let session_token = value
        .get("session_token")
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut sanitized = sanitize_desktop_payload(value);
    if let (Some(token), Some(object)) = (session_token, sanitized.as_object_mut()) {
        object.insert("session_token".to_string(), Value::String(token));
    }
    sanitized
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

fn public_diagnostics_view(payload: Value) -> Value {
    diagnostics_allowlisted_view(sanitize_desktop_payload(payload))
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
    #[cfg(feature = "admin-console")]
    let admin_diagnostics_enabled = ensure_admin_console_state(&state, "Diagnostics").is_ok();
    #[cfg(not(feature = "admin-console"))]
    let admin_diagnostics_enabled = false;

    let diagnostics_path = if admin_diagnostics_enabled {
        "/v1/get_diagnostics"
    } else {
        "/v1/gpm/diagnostics/public"
    };
    state
        .local_api
        .get_json(diagnostics_path)
        .await
        .map(|payload| {
            if admin_diagnostics_enabled {
                sanitize_desktop_payload(payload)
            } else {
                public_diagnostics_view(payload)
            }
        })
}

#[tauri::command]
async fn control_connect(
    state: State<'_, AppState>,
    request: ConnectRequest,
) -> Result<Value, String> {
    request.validate()?;
    enforce_connect_policy(&state, &request).await?;
    state
        .local_api
        .post_json("/v1/connect", &request)
        .await
        .map(sanitize_desktop_payload)
}

async fn enforce_connect_policy(
    state: &State<'_, AppState>,
    request: &ConnectRequest,
) -> Result<(), String> {
    let policy = state
        .local_api
        .get_runtime_policy_config()
        .await
        .map_err(|_| {
            "Connect is unavailable: runtime policy is unavailable; retry after /v1/config is reachable"
                .to_string()
        })?;
    enforce_connect_policy_request(request, &policy)
}

fn enforce_connect_policy_request(
    request: &ConnectRequest,
    policy: &RuntimePolicyConfig,
) -> Result<(), String> {
    let session_token = request
        .session_token
        .as_deref()
        .map(str::trim)
        .unwrap_or("");
    let production_mode = runtime_config_bool(
        policy.config.as_ref(),
        &[
            "gpm_production_mode",
            "gpmProductionMode",
            "production_mode",
            "productionMode",
        ],
    )
    .unwrap_or(false);
    let require_session = policy
        .connect_require_session
        .unwrap_or(production_mode || request.prod_profile == Some(true));
    let allow_legacy = policy.allow_legacy_connect_override.unwrap_or(false);

    if session_token.is_empty() && (require_session || !allow_legacy) {
        return Err("connect requires session_token by runtime policy".to_string());
    }
    if request.prod_profile == Some(true) && request.install_route == Some(false) {
        return Err("production profile connect requires install_route=true so host traffic is routed through GPM".to_string());
    }
    if request.prod_profile == Some(true)
        && request.path_profile.trim().eq_ignore_ascii_case("1hop")
    {
        return Err(
            "production profile connect requires a strict 2hop or 3hop profile".to_string(),
        );
    }
    if production_mode || request.prod_profile == Some(true) {
        if session_token.is_empty() {
            return Err("production connect requires session_token".to_string());
        }
        let reservation_id = request
            .reservation_id
            .as_deref()
            .map(str::trim)
            .unwrap_or("");
        let reservation_session_id = request
            .reservation_session_id
            .as_deref()
            .map(str::trim)
            .unwrap_or("");
        if reservation_id.is_empty() || reservation_session_id.is_empty() {
            return Err("production profile connect requires chain-confirmed reservation_id and reservation_session_id".to_string());
        }
    }
    Ok(())
}

fn runtime_config_bool(config: Option<&Value>, keys: &[&str]) -> Option<bool> {
    let object = config?.as_object()?;
    for key in keys {
        if let Some(value) = object.get(*key).and_then(Value::as_bool) {
            return Some(value);
        }
    }
    None
}

#[tauri::command]
async fn control_disconnect(
    state: State<'_, AppState>,
    request: Option<ServiceLifecycleRequest>,
) -> Result<Value, String> {
    let request = request.unwrap_or_default();
    state
        .local_api
        .post_json("/v1/disconnect", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(feature = "admin-console")]
#[tauri::command]
async fn control_set_profile(
    state: State<'_, AppState>,
    request: ProfileRequest,
) -> Result<Value, String> {
    ensure_admin_console_state(&state, "Set Profile")?;
    request.validate()?;
    state
        .local_api
        .post_json("/v1/set_profile", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(feature = "admin-console")]
#[tauri::command]
async fn control_update(
    state: State<'_, AppState>,
    request: ServiceLifecycleRequest,
) -> Result<Value, String> {
    ensure_admin_console_state(&state, "Update")?;
    request.validate()?;
    if !state.local_api.config().allow_update_mutations {
        return Err(
            "desktop update action disabled (set GPM_LOCAL_API_ALLOW_UPDATE_MUTATIONS=1; legacy alias: TDPN_LOCAL_API_ALLOW_UPDATE_MUTATIONS=1)"
                .to_string(),
        );
    }
    state
        .local_api
        .post_json("/v1/update", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(feature = "admin-console")]
#[tauri::command]
async fn control_service_status(
    state: State<'_, AppState>,
    request: ServiceLifecycleRequest,
) -> Result<Value, String> {
    ensure_admin_console_state(&state, "Service Status")?;
    request.validate()?;
    state
        .local_api
        .post_json("/v1/gpm/service/status", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(feature = "admin-console")]
#[tauri::command]
async fn control_service_start(
    state: State<'_, AppState>,
    request: Option<ServiceLifecycleRequest>,
) -> Result<Value, String> {
    control_service_lifecycle(state, "start", request.unwrap_or_default()).await
}

#[cfg(feature = "admin-console")]
async fn control_service_lifecycle(
    state: State<'_, AppState>,
    action: &str,
    request: ServiceLifecycleRequest,
) -> Result<Value, String> {
    ensure_admin_console_state(&state, "Service Lifecycle")?;
    request.validate()?;
    if !state.local_api.config().allow_service_mutations {
        return Err(
            "service lifecycle actions disabled (set GPM_LOCAL_API_ALLOW_SERVICE_MUTATIONS=1; legacy alias: TDPN_LOCAL_API_ALLOW_SERVICE_MUTATIONS=1)"
                .to_string(),
        );
    }
    let gpm_path = format!("/v1/gpm/service/{action}");
    state
        .local_api
        .post_json(&gpm_path, &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(feature = "admin-console")]
#[tauri::command]
async fn control_service_stop(
    state: State<'_, AppState>,
    request: Option<ServiceLifecycleRequest>,
) -> Result<Value, String> {
    control_service_lifecycle(state, "stop", request.unwrap_or_default()).await
}

#[cfg(feature = "admin-console")]
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
    request.validate()?;
    state
        .local_api
        .post_json("/v1/gpm/auth/verify", &request)
        .await
        .map(sanitize_token_issuing_payload)
}

#[tauri::command]
async fn control_gpm_session(
    state: State<'_, AppState>,
    request: GPMSessionStatusRequest,
) -> Result<Value, String> {
    request.validate()?;
    state
        .local_api
        .post_json("/v1/gpm/session", &request)
        .await
        .map(sanitize_token_issuing_payload)
}

#[cfg(feature = "admin-console")]
#[tauri::command]
async fn control_gpm_audit_recent(
    state: State<'_, AppState>,
    session_token: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
    event: Option<String>,
    wallet_address: Option<String>,
    order: Option<String>,
) -> Result<Value, String> {
    ensure_admin_console_state(&state, "Recent Audit")?;
    let mut query = GPMAuditRecentRequest {
        session_token,
        limit,
        offset,
        event,
        wallet_address,
        order,
    }
    .sanitize()?;
    let session_token = query
        .session_token
        .as_deref()
        .ok_or_else(|| "session_token is required".to_string())?
        .to_string();
    query.session_token = None;
    state
        .local_api
        .get_json_with_gpm_session_query("/v1/gpm/audit/recent", &session_token, &query)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_client_register(
    state: State<'_, AppState>,
    request: GPMClientRegisterRequest,
) -> Result<Value, String> {
    request.validate()?;
    state
        .local_api
        .post_json("/v1/gpm/onboarding/client/register", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_client_status(
    state: State<'_, AppState>,
    request: GPMClientStatusRequest,
) -> Result<Value, String> {
    request.validate()?;
    state
        .local_api
        .post_json("/v1/gpm/onboarding/client/status", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_contribution_status(
    state: State<'_, AppState>,
    request: GPMContributionStatusRequest,
) -> Result<Value, String> {
    request.validate()?;
    state
        .local_api
        .post_json("/v1/gpm/contribution/status", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_contribution_enable(
    state: State<'_, AppState>,
    request: GPMContributionToggleRequest,
) -> Result<Value, String> {
    request.validate()?;
    state
        .local_api
        .post_json("/v1/gpm/contribution/enable", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_contribution_disable(
    state: State<'_, AppState>,
    request: GPMContributionToggleRequest,
) -> Result<Value, String> {
    request.validate()?;
    state
        .local_api
        .post_json("/v1/gpm/contribution/disable", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_rewards_current_week(
    state: State<'_, AppState>,
    request: GPMContributionStatusRequest,
) -> Result<Value, String> {
    request.validate()?;
    state
        .local_api
        .post_json("/v1/gpm/rewards/current-week", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_rewards_history(
    state: State<'_, AppState>,
    request: GPMContributionStatusRequest,
) -> Result<Value, String> {
    request.validate()?;
    state
        .local_api
        .post_json("/v1/gpm/rewards/history", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_settlement_reserve_funds(
    state: State<'_, AppState>,
    request: GPMSettlementReserveFundsRequest,
) -> Result<Value, String> {
    request.validate()?;
    state
        .local_api
        .post_json("/v1/gpm/settlement/reserve-funds", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(feature = "admin-console")]
#[tauri::command]
async fn control_gpm_admin_contribution_list(
    state: State<'_, AppState>,
    request: GPMAdminContributionListRequest,
) -> Result<Value, String> {
    ensure_admin_console_state(&state, "Contribution Review")?;
    state
        .local_api
        .post_json("/v1/gpm/admin/contributions/list", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(feature = "admin-console")]
#[tauri::command]
async fn control_gpm_admin_reward_review(
    state: State<'_, AppState>,
    request: GPMAdminRewardReviewRequest,
) -> Result<Value, String> {
    ensure_admin_console_state(&state, "Reward Review")?;
    state
        .local_api
        .post_json("/v1/gpm/admin/rewards/review", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(feature = "admin-console")]
#[tauri::command]
async fn control_gpm_admin_reward_hold(
    state: State<'_, AppState>,
    request: GPMAdminRewardHoldRequest,
) -> Result<Value, String> {
    ensure_admin_console_state(&state, "Reward Hold")?;
    state
        .local_api
        .post_json("/v1/gpm/admin/rewards/hold", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(feature = "admin-console")]
#[tauri::command]
async fn control_gpm_admin_reward_finalize(
    state: State<'_, AppState>,
    request: GPMAdminRewardFinalizeRequest,
) -> Result<Value, String> {
    ensure_admin_console_state(&state, "Reward Finalize")?;
    state
        .local_api
        .post_json("/v1/gpm/admin/rewards/finalize", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(feature = "admin-console")]
#[tauri::command]
async fn control_gpm_server_status(
    state: State<'_, AppState>,
    request: GPMServerStatusRequest,
) -> Result<Value, String> {
    ensure_admin_console_state(&state, "Server Status")?;
    state
        .local_api
        .post_json("/v1/gpm/onboarding/server/status", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[tauri::command]
async fn control_gpm_onboarding_overview(
    state: State<'_, AppState>,
    request: GPMOnboardingOverviewRequest,
) -> Result<Value, String> {
    request.validate()?;
    state
        .local_api
        .post_json("/v1/gpm/onboarding/overview", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(feature = "admin-console")]
#[tauri::command]
async fn control_gpm_operator_apply(
    state: State<'_, AppState>,
    request: GPMOperatorApplyRequest,
) -> Result<Value, String> {
    ensure_admin_console_state(&state, "Apply Operator Role")?;
    state
        .local_api
        .post_json("/v1/gpm/onboarding/operator/apply", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(feature = "admin-console")]
#[tauri::command]
async fn control_gpm_operator_status(
    state: State<'_, AppState>,
    request: GPMOperatorStatusRequest,
) -> Result<Value, String> {
    ensure_admin_console_state(&state, "Operator Status")?;
    state
        .local_api
        .post_json("/v1/gpm/onboarding/operator/status", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(feature = "admin-console")]
#[tauri::command]
async fn control_gpm_operator_list(
    state: State<'_, AppState>,
    request: GPMOperatorListRequest,
) -> Result<Value, String> {
    ensure_admin_console_state(&state, "Operator Queue")?;
    state
        .local_api
        .post_json("/v1/gpm/onboarding/operator/list", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(feature = "admin-console")]
#[tauri::command]
async fn control_gpm_operator_approve(
    state: State<'_, AppState>,
    request: GPMOperatorApproveRequest,
) -> Result<Value, String> {
    ensure_admin_console_state(&state, "Operator Approval")?;
    state
        .local_api
        .post_json("/v1/gpm/onboarding/operator/approve", &request)
        .await
        .map(sanitize_desktop_payload)
}

#[cfg(test)]
mod tests {
    use super::{
        enforce_connect_policy_request, ensure_admin_console_config, public_diagnostics_view,
        sanitize_desktop_payload, ConnectRequest, LocalApiConfig, RuntimePolicyConfig,
        ServiceLifecycleRequest, Value,
    };
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

    #[test]
    fn public_diagnostics_view_keeps_only_redacted_summary_fields() {
        let findings: Vec<Value> = (0..101)
            .map(|idx| {
                json!({
                    "severity": "warning",
                    "code": format!("check-{idx}"),
                    "message": format!("public finding {idx}"),
                    "remediation": "retry after reviewing public status",
                    "output": "raw command output",
                    "admin_token": "admin-secret"
                })
            })
            .collect();
        let payload = json!({
            "ok": true,
            "output": "root command output",
            "raw": "root raw output",
            "diagnostics": {
                "status": "warn",
                "generated_at_utc": "2026-04-29T00:00:00Z",
                "raw": "doctor raw output",
                "output": "doctor command output",
                "environment": {
                    "admin_token": "admin-secret"
                },
                "summary": {
                    "findings_total": 101,
                    "warnings_total": 101,
                    "failures_total": 0,
                    "admin_notes": "private"
                },
                "inputs": {
                    "base_port": 8095,
                    "client_iface": "wgclient0",
                    "exit_iface": "wgexit0",
                    "vpn_iface": "wgvpn0",
                    "invite_key": "invite-secret"
                },
                "findings": findings
            }
        });

        let public_view = public_diagnostics_view(payload);
        assert!(public_view.get("output").is_none());
        assert!(public_view.get("raw").is_none());

        let diagnostics = public_view
            .get("diagnostics")
            .and_then(Value::as_object)
            .expect("public diagnostics object");
        assert_eq!(diagnostics.get("status"), Some(&json!("warn")));
        assert!(diagnostics.get("raw").is_none());
        assert!(diagnostics.get("output").is_none());
        assert!(diagnostics.get("environment").is_none());

        let summary = diagnostics
            .get("summary")
            .and_then(Value::as_object)
            .expect("public summary object");
        assert_eq!(summary.get("findings_total"), Some(&json!(101)));
        assert_eq!(summary.get("warnings_total"), Some(&json!(101)));
        assert_eq!(summary.get("failures_total"), Some(&json!(0)));
        assert!(summary.get("admin_notes").is_none());

        let inputs = diagnostics
            .get("inputs")
            .and_then(Value::as_object)
            .expect("public inputs object");
        assert_eq!(inputs.get("base_port"), Some(&json!(8095)));
        assert_eq!(inputs.get("vpn_iface"), Some(&json!("wgvpn0")));
        assert!(inputs.get("invite_key").is_none());

        let findings = diagnostics
            .get("findings")
            .and_then(Value::as_array)
            .expect("public findings array");
        assert_eq!(findings.len(), 100);
        assert_eq!(diagnostics.get("findings_truncated"), Some(&json!(true)));
        assert_eq!(findings[0].get("severity"), Some(&json!("warning")));
        assert_eq!(findings[0].get("code"), Some(&json!("check-0")));
        assert!(findings[0].get("output").is_none());
        assert!(findings[0].get("admin_token").is_none());
    }

    #[test]
    fn service_lifecycle_request_serialization_preserves_session_token_semantics() {
        let with_session_token = ServiceLifecycleRequest {
            session_token: "session-123".to_string(),
        };
        let without_session_token = ServiceLifecycleRequest::default();

        assert_eq!(
            serde_json::to_value(with_session_token).expect("serialize with token"),
            json!({ "session_token": "session-123" })
        );
        assert_eq!(
            serde_json::to_value(without_session_token).expect("serialize without token"),
            json!({ "session_token": "" })
        );
    }

    #[test]
    fn service_lifecycle_request_requires_session_token() {
        let missing = ServiceLifecycleRequest::default();
        let err = missing.validate().expect_err("missing token should fail");
        assert!(err.contains("session_token is required"), "{err}");

        let whitespace = ServiceLifecycleRequest {
            session_token: "session token".to_string(),
        };
        let err = whitespace
            .validate()
            .expect_err("whitespace token should fail");
        assert!(err.contains("cannot contain whitespace"), "{err}");

        let valid = ServiceLifecycleRequest {
            session_token: "session-token".to_string(),
        };
        valid.validate().expect("valid token should pass");
    }

    fn connect_request_for_policy(
        session_token: Option<&str>,
        prod_profile: bool,
    ) -> ConnectRequest {
        ConnectRequest {
            bootstrap_directory: if session_token.is_some() {
                "".to_string()
            } else {
                "https://directory.example.invalid:8081".to_string()
            },
            invite_key: if session_token.is_some() {
                "".to_string()
            } else {
                "inv-test".to_string()
            },
            session_token: session_token.map(str::to_string),
            session_bootstrap_directory: None,
            reservation_id: None,
            reservation_session_id: None,
            path_profile: "2hop".to_string(),
            policy_profile: None,
            interface: None,
            discovery_wait_sec: None,
            ready_timeout_sec: None,
            run_preflight: None,
            prod_profile: Some(prod_profile),
            install_route: None,
        }
    }

    #[test]
    fn connect_policy_rejects_legacy_when_runtime_requires_session() {
        let request = connect_request_for_policy(None, false);
        let policy = RuntimePolicyConfig {
            connect_require_session: Some(true),
            allow_legacy_connect_override: Some(true),
            config: Some(json!({})),
        };
        let err = enforce_connect_policy_request(&request, &policy)
            .expect_err("session-required policy should reject legacy connect");
        assert!(err.contains("session_token"), "{err}");
    }

    #[test]
    fn connect_policy_requires_reservation_for_production_connect() {
        let mut request = connect_request_for_policy(Some("session-token"), true);
        let policy = RuntimePolicyConfig {
            connect_require_session: Some(true),
            allow_legacy_connect_override: Some(false),
            config: Some(json!({ "gpm_production_mode": true })),
        };
        let err = enforce_connect_policy_request(&request, &policy)
            .expect_err("production policy should require reservation binding");
        assert!(err.contains("reservation_id"), "{err}");

        request.reservation_id = Some("reservation-1".to_string());
        request.reservation_session_id = Some("reservation-session-1".to_string());
        enforce_connect_policy_request(&request, &policy)
            .expect("session and reservation-bound production connect should pass");
    }

    #[test]
    fn connect_policy_prod_profile_requires_settlement_reservation() {
        let mut request = connect_request_for_policy(Some("session-token"), true);
        let policy = RuntimePolicyConfig {
            connect_require_session: None,
            allow_legacy_connect_override: Some(false),
            config: Some(json!({ "gpm_production_mode": false })),
        };

        let err = enforce_connect_policy_request(&request, &policy)
            .expect_err("prod profile should require reservation binding");
        assert!(err.contains("reservation_id"), "{err}");

        request.reservation_id = Some("reservation-1".to_string());
        request.reservation_session_id = Some("reservation-session-1".to_string());
        enforce_connect_policy_request(&request, &policy)
            .expect("prod profile with session and reservation binding should pass");
    }

    #[test]
    fn connect_policy_prod_profile_rejects_explicit_no_route() {
        let mut request = connect_request_for_policy(Some("session-token"), true);
        request.install_route = Some(false);
        let policy = RuntimePolicyConfig {
            connect_require_session: None,
            allow_legacy_connect_override: Some(false),
            config: Some(json!({ "gpm_production_mode": false })),
        };

        let err = enforce_connect_policy_request(&request, &policy)
            .expect_err("prod profile should reject explicit no-route connects");
        assert!(err.contains("install_route=true"), "{err}");
    }

    #[test]
    fn connect_policy_prod_profile_rejects_one_hop() {
        let mut request = connect_request_for_policy(Some("session-token"), true);
        request.path_profile = "1hop".to_string();
        request.install_route = Some(true);
        let policy = RuntimePolicyConfig {
            connect_require_session: None,
            allow_legacy_connect_override: Some(false),
            config: Some(json!({ "gpm_production_mode": false })),
        };

        let err = enforce_connect_policy_request(&request, &policy)
            .expect_err("prod profile should reject one-hop routing");
        assert!(err.contains("strict 2hop or 3hop"), "{err}");
    }

    #[test]
    fn admin_console_guard_blocks_public_mode_commands() {
        let public_cfg = LocalApiConfig {
            base_url: "http://127.0.0.1:8095".to_string(),
            timeout_sec: 20,
            allow_remote: false,
            auth_bearer: None,
            allow_update_mutations: false,
            allow_service_mutations: false,
            connect_require_session: false,
            allow_legacy_connect_override: false,
            admin_console_enabled: false,
        };
        let err = ensure_admin_console_config(&public_cfg, "Operator Queue")
            .expect_err("public mode should reject admin command");
        assert!(err.contains("GPM Admin Console"), "{err}");

        let admin_cfg = LocalApiConfig {
            admin_console_enabled: true,
            ..public_cfg
        };
        if cfg!(feature = "admin-console") {
            ensure_admin_console_config(&admin_cfg, "Operator Queue")
                .expect("admin console feature build should allow admin command when enabled");
        } else {
            let err = ensure_admin_console_config(&admin_cfg, "Operator Queue").expect_err(
                "public feature build should reject admin commands even when env is set",
            );
            assert!(err.contains("Admin Console build"), "{err}");
        }
    }
}

fn main() {
    let local_api_config = LocalApiConfig::from_env()
        .expect("failed to load local daemon API configuration from environment");
    let local_api = LocalApiClient::new(local_api_config)
        .expect("failed to initialize local daemon API client");

    let builder = tauri::Builder::default().manage(AppState { local_api });

    #[cfg(feature = "admin-console")]
    let builder = builder.invoke_handler(tauri::generate_handler![
        control_config,
        control_runtime_config,
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
        control_gpm_client_status,
        control_gpm_contribution_status,
        control_gpm_contribution_enable,
        control_gpm_contribution_disable,
        control_gpm_rewards_current_week,
        control_gpm_rewards_history,
        control_gpm_settlement_reserve_funds,
        control_gpm_admin_contribution_list,
        control_gpm_admin_reward_review,
        control_gpm_admin_reward_hold,
        control_gpm_admin_reward_finalize,
        control_gpm_server_status,
        control_gpm_onboarding_overview,
        control_gpm_operator_apply,
        control_gpm_operator_status,
        control_gpm_operator_list,
        control_gpm_operator_approve
    ]);

    #[cfg(not(feature = "admin-console"))]
    let builder = builder.invoke_handler(tauri::generate_handler![
        control_config,
        control_runtime_config,
        control_health,
        control_status,
        control_get_diagnostics,
        control_connect,
        control_disconnect,
        control_gpm_bootstrap_manifest,
        control_gpm_auth_challenge,
        control_gpm_auth_verify,
        control_gpm_session,
        control_gpm_client_register,
        control_gpm_client_status,
        control_gpm_contribution_status,
        control_gpm_contribution_enable,
        control_gpm_contribution_disable,
        control_gpm_rewards_current_week,
        control_gpm_rewards_history,
        control_gpm_settlement_reserve_funds,
        control_gpm_onboarding_overview
    ]);

    builder
        .run(tauri::generate_context!())
        .expect("error while running Global Private Mesh (GPM) desktop scaffold");
}
