pub struct KeyedHash([u8; 32]);
impl KeyedHash {
    pub fn new(key: [u8; 32]) -> KeyedHash {
        Self(key)
    }
    pub fn sign(&self, data: &[u8]) -> blake3::Hash {
        blake3::keyed_hash(&self.0, data)
    }
    pub fn length(&self) -> usize {
        blake3::OUT_LEN
    }
    pub fn verify(&self, data: &[u8], tag: [u8; 32]) -> Result<(), String> {
        let hash = blake3::keyed_hash(&self.0, data);
        let other = blake3::Hash::from(tag);
        // This uses constant time comparison internally
        if hash != other {
            return Err("Invalid Signature".to_string());
        }
        Ok(())
    }
}
