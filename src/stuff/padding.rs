use ring::rand;

pub struct PaddingState {
    rng: rand::SystemRandom,
}

const U32_MAX: usize = u32::MAX as usize;

impl PaddingState {
    pub fn new() -> PaddingState {
        let rng = rand::SystemRandom::new();
        Self { rng }
    }
    pub fn pad(&self, message: &[u8], length: usize) -> Result<Vec<u8>, String> {
        let real_length = message.len();
        if real_length > U32_MAX {
            Err(format!(
                "Real length {} exceeds supported padding size {}",
                real_length,
                u32::MAX
            ))
        } else if real_length > length {
            Err(format!(
                "Real length {} exceeds input padded size {}",
                real_length, length
            ))
        } else {
            let mut result = Vec::with_capacity(4 + length as usize);
            let len = (real_length as u32).to_be_bytes();
            let mut remainder = length - real_length;
            result.extend_from_slice(&len);
            result.extend_from_slice(message);
            // Now to pad it with random material
            while remainder > 32 {
                remainder -= 32;
                let bytes: [u8; 32] = rand::generate(&self.rng)
                    .map_err(|_| "gen random failed")?
                    .expose();
                result.extend_from_slice(&bytes);
            }
            while remainder > 8 {
                remainder -= 8;
                let bytes: [u8; 8] = rand::generate(&self.rng)
                    .map_err(|_| "gen random failed")?
                    .expose();
                result.extend_from_slice(&bytes);
            }
            if remainder > 0 {
                // Generate one final block, copy a subset of that block
                let bytes: [u8; 8] = rand::generate(&self.rng)
                    .map_err(|_| "gen random failed")?
                    .expose();
                result.extend_from_slice(&bytes[..remainder])
            }

            Ok(result)
        }
    }
    pub fn unpad(message: &[u8]) -> Result<&[u8], String> {
        let len = message.len();
        if len < 4 {
            return Err("Message length is insufficient".to_string());
        }
        let mut real_length_be: [u8; 4] = [0; 4];
        real_length_be.copy_from_slice(&message[0..4]);
        let real_length = u32::from_be_bytes(real_length_be) as usize;
        let remainder = len - 4;
        if real_length > remainder {
            return Err("Corrupted Input".to_string());
        }

        Ok(&message[4..4 + real_length])
    }
}
