mod local_api;

use local_api::{ConnectRequest, LocalApiClient, LocalApiConfig, ProfileRequest};
use serde::Serialize;
use serde_json::Value;
use tauri::State;

struct AppState {
    local_api: LocalApiClient,
}

#[derive(Serialize)]
struct ControlConfig {
    base_url: String,
    timeout_sec: u64,
}

#[tauri::command]
fn control_config(state: State<'_, AppState>) -> ControlConfig {
    let cfg = state.local_api.config();
    ControlConfig {
        base_url: cfg.base_url.clone(),
        timeout_sec: cfg.timeout_sec,
    }
}

#[tauri::command]
async fn control_health(state: State<'_, AppState>) -> Result<Value, String> {
    state.local_api.get_json("/v1/health").await
}

#[tauri::command]
async fn control_status(state: State<'_, AppState>) -> Result<Value, String> {
    state.local_api.get_json("/v1/status").await
}

#[tauri::command]
async fn control_get_diagnostics(state: State<'_, AppState>) -> Result<Value, String> {
    state.local_api.get_json("/v1/get_diagnostics").await
}

#[tauri::command]
async fn control_connect(state: State<'_, AppState>, request: ConnectRequest) -> Result<Value, String> {
    request.validate()?;
    state.local_api.post_json("/v1/connect", &request).await
}

#[tauri::command]
async fn control_disconnect(state: State<'_, AppState>) -> Result<Value, String> {
    state.local_api.post_empty("/v1/disconnect").await
}

#[tauri::command]
async fn control_set_profile(state: State<'_, AppState>, request: ProfileRequest) -> Result<Value, String> {
    request.validate()?;
    state.local_api.post_json("/v1/set_profile", &request).await
}

#[tauri::command]
async fn control_update(state: State<'_, AppState>) -> Result<Value, String> {
    state.local_api.post_empty("/v1/update").await
}

fn main() {
    let local_api_config = LocalApiConfig::from_env();
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
            control_update
        ])
        .run(tauri::generate_context!())
        .expect("error while running TDPN desktop scaffold");
}
