pub struct KeyedHash([u8; 32]);
impl KeyedHash {
    pub fn new(key: [u8; 32]) -> KeyedHash {
        Self(key)
    }
    pub fn sign(&self, data: &[u8]) -> blake3::Hash {
        blake3::keyed_hash(&self.0, data)
    }
    pub fn sign_truncated_u64(&self, data: &[u8]) -> u64 {
        let hash = self.sign(data);
        let hash_bytes = hash.as_bytes();
        let mut be_bytes : [u8; 8] = [0; 8];
        be_bytes.copy_from_slice(&hash_bytes[0..8]);
        u64::from_be_bytes(be_bytes)
    }
    pub fn sign_truncated_u32(&self, data: &[u8]) -> u32 {
        let hash = self.sign(data);
        let hash_bytes = hash.as_bytes();
        let mut be_bytes : [u8; 4] = [0; 4];
        be_bytes.copy_from_slice(&hash_bytes[0..4]);
        u32::from_be_bytes(be_bytes)
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

pub fn verify_message<'a>(message: &'a [u8], hmac_key: &KeyedHash) -> Result<&'a [u8], String> {
    let hash_length = hmac_key.length();
    let message_length = message.len();
    if message_length <= hash_length {
        return Err("Insufficient Length".to_string());
    }
    let length = message_length - hash_length;
    let mut tag: [u8; 32] = [0; 32];
    tag.copy_from_slice(&message[length..length + 32]);
    hmac_key.verify(&message[0..length], tag)?;
    Ok(&message[0..length])
}

pub fn sign_message(message: &[u8], hmac_key: &KeyedHash) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(message.len() + hmac_key.length());
    let tag = hmac_key.sign(message);
    let tag_bytes = tag.as_bytes();
    output.extend_from_slice(message);
    output.extend_from_slice(tag_bytes);
    Ok(output)
}
