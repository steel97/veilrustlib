use crate::callback::Callback;
use once_cell::sync::OnceCell;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

static RUNTIME: OnceCell<RuntimeHandle> = OnceCell::new();

pub struct RuntimeHandle {
    runtime: tokio::runtime::Runtime,
    request_tx: tokio::sync::mpsc::UnboundedSender<String>,
    #[allow(dead_code)]
    callback: Callback,
}

impl RuntimeHandle {
    pub fn init(callback: Callback) -> Result<(), String> {
        if RUNTIME.get().is_some() {
            return Err("Runtime already initialized".to_string());
        }

        let runtime = Runtime::new().map_err(|e| format!("Failed to create runtime: {}", e))?;
        let (request_tx, request_rx) = mpsc::unbounded_channel();

        let handle = RuntimeHandle {
            runtime,
            request_tx,
            callback: callback.clone(),
        };

        // Spawn the event loop
        handle.runtime.spawn(event_loop(request_rx, callback));

        RUNTIME
            .set(handle)
            .map_err(|_| "Failed to set runtime".to_string())?;

        Ok(())
    }

    pub fn send_request(json: String) -> Result<(), String> {
        let handle = RUNTIME.get().ok_or("Runtime not initialized")?;
        handle
            .request_tx
            .send(json)
            .map_err(|_| "Failed to send request".to_string())
    }

    pub fn shutdown() {
        if let Some(handle) = RUNTIME.get() {
            // Close the request channel to signal shutdown
            // The event loop will exit when the channel is closed
            let _ = &handle.request_tx;
        }
    }

    pub fn is_initialized() -> bool {
        RUNTIME.get().is_some()
    }
}

async fn event_loop(mut request_rx: mpsc::UnboundedReceiver<String>, callback: Callback) {
    while let Some(json_request) = request_rx.recv().await {
        let callback_clone = callback.clone();
        
        // Spawn a task to handle the request
        tokio::spawn(async move {
            let response = crate::handlers::handle_request(&json_request).await;
            callback_clone.invoke(&response);
        });
    }
}
