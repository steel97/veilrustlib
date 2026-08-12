use std::cell::RefCell;

// FFI error codes (synchronous errors returned from veil_send)
pub const VEIL_OK: i32 = 0;
pub const VEIL_ERROR_INVALID_JSON: i32 = -1;
#[allow(dead_code)]
pub const VEIL_ERROR_INVALID_CLIENT_ID: i32 = -2;
pub const VEIL_ERROR_NOT_INITIALIZED: i32 = -3;
pub const VEIL_ERROR_ALREADY_INITIALIZED: i32 = -4;
pub const VEIL_ERROR_CALLBACK_NULL: i32 = -5;

// JSON error codes (asynchronous errors in callback responses)
pub const ERROR_CODE_INVALID_INPUT: i32 = 400;
pub const ERROR_CODE_NOT_FOUND: i32 = 404;
pub const ERROR_CODE_INTERNAL: i32 = 500;
pub const ERROR_CODE_RPC: i32 = 503;
pub const ERROR_CODE_INSUFFICIENT_BALANCE: i32 = 507;

thread_local! {
    static LAST_ERROR: RefCell<String> = RefCell::new(String::new());
}

pub fn set_last_error(error: String) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = error;
    });
}

pub fn get_last_error() -> String {
    LAST_ERROR.with(|e| e.borrow().clone())
}

pub fn clear_last_error() {
    LAST_ERROR.with(|e| {
        e.borrow_mut().clear();
    });
}

/// Map veilrustlib errors to JSON error codes
pub fn map_veil_error_code(error: &veilrustlib::VeilError) -> i32 {
    match error {
        veilrustlib::VeilError::InvalidInput(_) => ERROR_CODE_INVALID_INPUT,
        veilrustlib::VeilError::InvalidAddress(_) => ERROR_CODE_INVALID_INPUT,
        veilrustlib::VeilError::Rpc(_) => ERROR_CODE_RPC,
        veilrustlib::VeilError::InsufficientFunds { .. } => ERROR_CODE_INSUFFICIENT_BALANCE,
        veilrustlib::VeilError::Cache(_) => ERROR_CODE_INTERNAL,
        _ => ERROR_CODE_INTERNAL,
    }
}
