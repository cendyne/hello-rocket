use base64ct::{Base64UrlUnpadded, Encoding};
use ring::rand;
use std::env;

fn load_key(var: &str) -> Result<[u8; 32], String> {
    let res = env::var(var).map_err(|e| format!("Failed to load {}: {}", var, e))?;
    let message = Base64UrlUnpadded::decode_vec(&res)
        .map_err(|_| format!("Failed to load {}, expected base64 string", var))?;
    if message.len() == 32 {
        let mut result: [u8; 32] = [0; 32];
        result.copy_from_slice(&message);
        Ok(result)
    } else {
        Err(format!(
            "Failed to load {}, it has length {} but 32 bytes are expected",
            var,
            message.len()
        ))
    }
}

fn random_32(rng: &dyn rand::SecureRandom) -> Result<[u8; 32], String> {
    let mut result: [u8; 32] = [0; 32];
    rng.fill(&mut result).map_err(|_| "Could not init nonce")?;
    Ok(result)
}

pub fn load_or_random(var: &str, rng: &dyn rand::SecureRandom) -> Result<[u8; 32], String> {
    load_key(var).or_else(|msg| {
        println!("{}", msg);
        println!("Attempting to load a random key for {}", var);
        let key = random_32(rng)?;
        println!(
            "Consider setting {}={} in the environment or .env file",
            var,
            Base64UrlUnpadded::encode_string(&key)
        );
        Ok(key)
    })
}
