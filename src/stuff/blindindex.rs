use argon2::{self, Config};

#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub enum IndexType {
    Fast,
    Sensitive,
}

pub fn blind_index(
    key: &[u8; 32],
    value: &[u8],
    index_type: IndexType,
) -> Result<[u8; 32], String> {
    match index_type {
        IndexType::Fast => {
            let hash = blake3::keyed_hash(key, value);
            Ok(*hash.as_bytes())
        }
        IndexType::Sensitive => {
            let config = Config::<'_> {
                hash_length: 32,
                ..Default::default()
            };

            let encoded =
                argon2::hash_raw(value, key, &config).map_err(|_| "Could not encode password")?;
            let mut result = [0; 32];
            result.copy_from_slice(&encoded[..32]);
            Ok(result)
        }
    }
}
