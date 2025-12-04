use axum::{routing::post, Router, Json};
use log::{info, error};
use plucky_poro_anti_cheat_common::SecurityEvent;
use serde_json::Value;
use std::net::SocketAddr;

async fn handle_alert(Json(payload): Json<Value>) {
    match serde_json::from_value::<SecurityEvent>(payload.clone()) {
        Ok(event) => {
            let comm = std::str::from_utf8(&event.comm)
                .unwrap_or("<unknown>")
                .trim_end_matches('\0');
            info!(
                "Received security alert: PID={}, Type={}, Comm={}",
                event.pid, event.event_type, comm
            );
        }
        Err(e) => {
            error!("Failed to deserialize security event: {}", e);
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let app = Router::new().route("/", post(handle_alert));

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    info!("Mock server listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}