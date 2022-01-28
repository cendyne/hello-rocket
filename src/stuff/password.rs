use argon2::{self, Config};
use ring::rand;

pub fn encode_password(password: &[u8], rng: &dyn rand::SecureRandom) -> Result<String, String> {
    let salt: [u8; 16] = rand::generate(rng)
        .map_err(|_| "gen random failed")?
        .expose();
    let config = Config::default();
    let encoded =
        argon2::hash_encoded(password, &salt, &config).map_err(|_| "Could not encode password")?;
    Ok(encoded)
}
pub fn verify_password(password: &[u8], encoded_password: &str) -> Result<(), String> {
    let verified = argon2::verify_encoded(encoded_password, password)
    .map_err(|_| "Password format failure")?;
    if verified {
        Ok(())
    } else {
        Err("Password check failed".to_string())
    }
}
