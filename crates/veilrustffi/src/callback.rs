use parking_lot::Mutex;
use std::ffi::c_void;
use std::sync::Arc;

/// C callback function type
pub type CCallback = unsafe extern "C" fn(*const i8, usize, *mut c_void);

/// Thread-safe callback storage
#[derive(Clone)]
pub struct Callback {
    func: Arc<Mutex<Option<(CCallback, *mut c_void)>>>,
}

impl Callback {
    pub fn new() -> Self {
        Self {
            func: Arc::new(Mutex::new(None)),
        }
    }

    pub fn set(&self, callback: CCallback, user_data: *mut c_void) {
        let mut guard = self.func.lock();
        *guard = Some((callback, user_data));
    }

    #[allow(dead_code)]
    pub fn clear(&self) {
        let mut guard = self.func.lock();
        *guard = None;
    }

    pub fn invoke(&self, json: &str) {
        let guard = self.func.lock();
        if let Some((callback, user_data)) = *guard {
            let json_bytes = json.as_bytes();
            let json_ptr = json_bytes.as_ptr() as *const i8;
            let json_len = json_bytes.len();
            
            // Call the C callback
            // Safety: The callback is responsible for not panicking or causing UB
            unsafe {
                callback(json_ptr, json_len, user_data);
            }
        }
    }

    #[allow(dead_code)]
    pub fn is_set(&self) -> bool {
        self.func.lock().is_some()
    }
}

unsafe impl Send for Callback {}
unsafe impl Sync for Callback {}
