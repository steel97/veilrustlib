use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use veilrustlib::{RpcClient, StealthKeys};
use veilrustlib::cache::RedbStore;

static CLIENT_REGISTRY: once_cell::sync::Lazy<Arc<RwLock<ClientRegistry>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(ClientRegistry::new())));

pub struct ClientSession {
    pub rpc_client: Arc<RpcClient>,
    pub cache_store: Option<RedbStore>,
    pub stealth_keys: Option<StealthKeys>,
}

pub struct ClientRegistry {
    clients: HashMap<u64, ClientSession>,
    next_id: u64,
}

impl ClientRegistry {
    fn new() -> Self {
        Self {
            clients: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn create_client(
        rpc_client: RpcClient,
        cache_store: Option<RedbStore>,
    ) -> u64 {
        let mut registry = CLIENT_REGISTRY.write();
        let client_id = registry.next_id;
        registry.next_id += 1;

        let session = ClientSession {
            rpc_client: Arc::new(rpc_client),
            cache_store,
            stealth_keys: None,
        };

        registry.clients.insert(client_id, session);
        client_id
    }



    pub fn close_client(client_id: u64) -> bool {
        let mut registry = CLIENT_REGISTRY.write();
        registry.clients.remove(&client_id).is_some()
    }

    pub fn with_client<F, R>(client_id: u64, f: F) -> Option<R>
    where
        F: FnOnce(&ClientSession) -> R,
    {
        let registry = CLIENT_REGISTRY.read();
        registry.clients.get(&client_id).map(f)
    }

    pub fn with_client_mut<F, R>(client_id: u64, f: F) -> Option<R>
    where
        F: FnOnce(&mut ClientSession) -> R,
    {
        let mut registry = CLIENT_REGISTRY.write();
        registry.clients.get_mut(&client_id).map(f)
    }

    pub fn close_all() {
        let mut registry = CLIENT_REGISTRY.write();
        registry.clients.clear();
    }
}
