mod callback;
mod client;
mod error;
mod handlers;
mod protocol;
mod runtime;

use callback::{CCallback, Callback};
use error::{
    clear_last_error, get_last_error, set_last_error, VEIL_ERROR_ALREADY_INITIALIZED,
    VEIL_ERROR_CALLBACK_NULL, VEIL_ERROR_INVALID_JSON, VEIL_ERROR_NOT_INITIALIZED, VEIL_OK,
};
use runtime::RuntimeHandle;
use std::ffi::{c_char, c_void, CStr};
use std::ptr;

/// Initialize the Veil FFI runtime with a callback function
///
/// # Arguments
/// * `callback` - Function pointer to receive JSON responses
/// * `user_data` - Opaque pointer passed back to callback
///
/// # Returns
/// * `VEIL_OK` (0) on success
/// * `VEIL_ERROR_CALLBACK_NULL` if callback is null
/// * `VEIL_ERROR_ALREADY_INITIALIZED` if already initialized
///
/// # Safety
/// The callback must be thread-safe and must not panic
#[no_mangle]
pub unsafe extern "C" fn veil_init(callback: Option<CCallback>, user_data: *mut c_void) -> i32 {
    clear_last_error();

    let callback_fn = match callback {
        Some(cb) => cb,
        None => {
            set_last_error("Callback function is null".to_string());
            return VEIL_ERROR_CALLBACK_NULL;
        }
    };

    if RuntimeHandle::is_initialized() {
        set_last_error("Runtime already initialized".to_string());
        return VEIL_ERROR_ALREADY_INITIALIZED;
    }

    let cb = Callback::new();
    cb.set(callback_fn, user_data);

    match RuntimeHandle::init(cb) {
        Ok(_) => VEIL_OK,
        Err(e) => {
            set_last_error(e);
            VEIL_ERROR_NOT_INITIALIZED
        }
    }
}

/// Send a JSON request to the Veil FFI runtime
///
/// # Arguments
/// * `json_request` - Null-terminated JSON string
///
/// # Returns
/// * `VEIL_OK` (0) on success (response will arrive via callback)
/// * `VEIL_ERROR_NOT_INITIALIZED` if runtime not initialized
/// * `VEIL_ERROR_INVALID_JSON` if JSON parsing fails
///
/// # Safety
/// The json_request pointer must be valid and null-terminated
#[no_mangle]
pub unsafe extern "C" fn veil_send(json_request: *const c_char) -> i32 {
    clear_last_error();

    if json_request.is_null() {
        set_last_error("JSON request pointer is null".to_string());
        return VEIL_ERROR_INVALID_JSON;
    }

    if !RuntimeHandle::is_initialized() {
        set_last_error("Runtime not initialized".to_string());
        return VEIL_ERROR_NOT_INITIALIZED;
    }

    // Convert C string to Rust String
    let c_str = match CStr::from_ptr(json_request).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("Invalid UTF-8 in JSON request".to_string());
            return VEIL_ERROR_INVALID_JSON;
        }
    };

    // Parse JSON to validate it
    if serde_json::from_str::<serde_json::Value>(c_str).is_err() {
        set_last_error("Invalid JSON".to_string());
        return VEIL_ERROR_INVALID_JSON;
    }

    // Send to runtime
    match RuntimeHandle::send_request(c_str.to_string()) {
        Ok(_) => VEIL_OK,
        Err(e) => {
            set_last_error(e);
            VEIL_ERROR_NOT_INITIALIZED
        }
    }
}

/// Shutdown the Veil FFI runtime and close all clients
///
/// This function blocks until all pending requests are completed
///
/// # Safety
/// Must be called from the same thread that called veil_init
#[no_mangle]
pub extern "C" fn veil_shutdown() {
    client::ClientRegistry::close_all();
    RuntimeHandle::shutdown();
}

/// Get the last error message from a failed synchronous call
///
/// # Returns
/// Pointer to null-terminated error string, valid until next FFI call
///
/// # Safety
/// The returned pointer is thread-local and must not be freed by the caller
#[no_mangle]
pub extern "C" fn veil_last_error() -> *const c_char {
    let error = get_last_error();
    if error.is_empty() {
        ptr::null()
    } else {
        // Store in thread-local static to keep it alive
        thread_local! {
            static ERROR_BUFFER: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(Vec::new());
        }
        
        ERROR_BUFFER.with(|buf| {
            let mut buffer = buf.borrow_mut();
            buffer.clear();
            buffer.extend_from_slice(error.as_bytes());
            buffer.push(0); // null terminator
            buffer.as_ptr() as *const c_char
        })
    }
}

/// Get the version of the FFI library
///
/// # Returns
/// Pointer to static null-terminated version string
#[no_mangle]
pub extern "C" fn veil_version() -> *const c_char {
    const VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        unsafe {
            let version = veil_version();
            let c_str = CStr::from_ptr(version);
            let version_str = c_str.to_str().unwrap();
            assert_eq!(version_str, "0.1.0");
        }
    }
}
