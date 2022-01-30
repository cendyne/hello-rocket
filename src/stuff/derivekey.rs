use dashmap::DashMap;

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub enum DeriveKeyPurpose {
    ExactIndex,
    PartialIndex(String),
    Secret,
}
unsafe impl Sync for DeriveKeyPurpose {}
unsafe impl Send for DeriveKeyPurpose {}

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub struct DeriveKeyContext {
    table: String,
    column: String,
    purpose: DeriveKeyPurpose,
}
unsafe impl Sync for DeriveKeyContext {}
unsafe impl Send for DeriveKeyContext {}

impl DeriveKeyContext {
    pub fn new(table: String, column: String, purpose: DeriveKeyPurpose) -> DeriveKeyContext {
        Self {
            table,
            column,
            purpose,
        }
    }
}

pub type DerivedKey = [u8; 32];
#[derive(Clone, Hash, Debug)]
pub struct DeriveKeyResult {
    key: DerivedKey,
    // TODO consider Sealing State
}
unsafe impl Sync for DeriveKeyResult {}
unsafe impl Send for DeriveKeyResult {}
impl DeriveKeyResult {
    pub fn new(key: DerivedKey) -> DeriveKeyResult {
        Self { key }
    }
}

fn derive_key(key: &[u8; 32], context: &DeriveKeyContext) -> Result<DeriveKeyResult, String> {
    let additional_data = match &context.purpose {
        DeriveKeyPurpose::ExactIndex => {
            format!("index:table{}:column{}", context.table, context.column)
        }
        DeriveKeyPurpose::PartialIndex(variant) => {
            format!(
                "partial:table{}:column{}:variant{}",
                context.table, context.column, variant
            )
        }
        DeriveKeyPurpose::Secret => {
            format!("secret:table{}:column{}", context.table, context.column)
        }
    };
    let hash = blake3::keyed_hash(key, additional_data.as_bytes());
    Ok(DeriveKeyResult::new(*hash.as_bytes()))
}

pub struct DerivingKey {
    key: [u8; 32],
    keys: DashMap<DeriveKeyContext, DeriveKeyResult>,
}
impl DerivingKey {
    pub fn new(key: [u8; 32]) -> DerivingKey {
        Self {
            key,
            keys: DashMap::new(),
        }
    }
    pub fn key(&self, context: &DeriveKeyContext) -> Result<DerivedKey, String> {
        let cloned = context.clone();
        let fun = || derive_key(&self.key, context);
        self.keys
            .entry(cloned)
            .or_try_insert_with(fun)
            .map(|r| r.value().key)
    }
}
