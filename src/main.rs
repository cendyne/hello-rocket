#[macro_use]
extern crate rocket;
use argon2::{self, Config};
use base64ct::{Base64UrlUnpadded, Encoding};
use ring::{aead, rand};
use rocket::tokio::time::{sleep, Duration};
use rocket::State;
use std::env;
use std::sync::{Arc, Mutex};
use std::vec;
mod stuff;
use stuff::blindindex::{blind_index, IndexType};
use stuff::derivekey::{DeriveKeyContext, DeriveKeyPurpose, DerivingKey};
use stuff::keyedhash::KeyedHash;
use stuff::secret::{open_secret, seal_secret, SealingState};

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[get("/sleep")]
async fn sleeping() -> &'static str {
    sleep(Duration::from_secs(3)).await;
    "Slept"
}

#[get("/rando")]
fn rando(rng: &State<rand::SystemRandom>) -> Result<String, String> {
    let key_value: [u8; 32] = rand::generate(rng.inner())
        .map_err(|_| "gen random failed")?
        .expose();
    let encoded = Base64UrlUnpadded::encode_string(&key_value);
    Ok(encoded)
}

#[get("/sign/<param>")]
fn sign_thing(param: &str, hmac_key: &State<KeyedHash>) -> String {
    let tag = hmac_key.sign(param.as_bytes());
    let mut message = vec![];
    message.extend_from_slice(param.as_bytes());
    message.extend_from_slice(tag.as_bytes());
    let encoded = Base64UrlUnpadded::encode_string(&message);
    format!("{} -> {}", param, encoded)
}

#[get("/verify/<param>")]
fn verify_thing(param: &str, hmac_key: &State<KeyedHash>) -> Result<String, String> {
    let message = Base64UrlUnpadded::decode_vec(param).map_err(|_| "Invalid Base64 input")?;
    let hash_length = hmac_key.length();
    let message_length = message.len();
    if message_length <= hash_length {
        return Err("Insufficient Length".to_string());
    }
    let length = message_length - hash_length;
    let mut tag: [u8; 32] = [0; 32];
    tag.copy_from_slice(&message[length..length + 32]);
    hmac_key.verify(&message[0..length], tag)?;
    let text = std::str::from_utf8(&message[0..length]).map_err(|e| format!("{}", e))?;
    Ok(format!("{} -> {}", param, text))
}

#[get("/secret/<param>/<aad>")]
fn secretbox(
    param: &str,
    aad: &str,
    encrypt: &State<Arc<Mutex<SealingState>>>,
) -> Result<String, String> {
    let mut encrypt_key = encrypt
        .lock()
        .map_err(|_| "Could not obtain encryption key")?;

    let final_message = seal_secret(param.as_bytes(), aad.as_bytes(), &mut encrypt_key)?;

    // let encoded = Base64::encode_string(message);
    let encoded = Base64UrlUnpadded::encode_string(&final_message);
    Ok(format!("Secret is {} and result: {}", param, encoded))
}

#[get("/open/<secret>/<aad>")]
fn openbox(
    secret: &str,
    aad: &str,
    encrypt: &State<Arc<Mutex<SealingState>>>,
) -> Result<String, String> {
    let message = Base64UrlUnpadded::decode_vec(secret).map_err(|_| "Could not decode")?;
    // println!("Got message {:x?}", message);
    let encrypt_key = encrypt
        .lock()
        .map_err(|_| "Could not obtain encryption key")?;
    let decrypted = open_secret(&message[..], aad.as_bytes(), &*encrypt_key)?;
    let text = std::str::from_utf8(&decrypted[..]).map_err(|e| format!("{}", e))?;
    Ok(format!(
        "Secret is {} and length is {}",
        text,
        decrypted.len()
    ))
}

#[get("/password/<secret>")]
fn password(secret: &str, rng: &State<rand::SystemRandom>) -> Result<String, String> {
    use rocket::http::RawStr;
    let pwd = secret.as_bytes();
    let salt: [u8; 16] = rand::generate(rng.inner())
        .map_err(|_| "gen random failed")?
        .expose();
    let config = Config::default();
    let encoded =
        argon2::hash_encoded(pwd, &salt, &config).map_err(|_| "Could not encode password")?;
    let encoded: &RawStr = RawStr::new(&encoded);
    Ok(format!("{}", RawStr::percent_encode(encoded)))
}

#[get("/verify-password/<secret>/<encoded>")]
fn verify_password(secret: &str, encoded: &str) -> Result<String, String> {
    let pwd = secret.as_bytes();
    argon2::verify_encoded(encoded, pwd).map_err(|_| "Could not encode password")?;
    Ok(format!("{} is the password for {}", secret, encoded))
}

#[get("/table/<table>/<column>/<value>?<sensitive>&<partial>&<secret>")]
fn table_value(
    table: &str,
    column: &str,
    value: &str,
    sensitive: Option<bool>,
    partial: Option<&str>,
    secret: Option<bool>,
    deriving_key: &State<Arc<DerivingKey>>,
) -> Result<String, String> {
    let context = DeriveKeyContext::new(
        table.to_string(),
        column.to_string(),
        match partial {
            Some(variant) => DeriveKeyPurpose::PartialIndex(variant.to_string()),
            None => match secret {
                Some(true) => DeriveKeyPurpose::Secret,
                Some(false) => DeriveKeyPurpose::ExactIndex,
                None => DeriveKeyPurpose::ExactIndex,
            },
        },
    );
    let key = deriving_key.key(&context)?;
    if secret == Some(true) {
        Ok(format!(
            "{}:{} column secret key is {}",
            table,
            column,
            Base64UrlUnpadded::encode_string(&key)
        ))
    } else {
        let index = blind_index(
            &key,
            value.as_bytes(),
            match sensitive {
                Some(true) => IndexType::Sensitive,
                Some(false) => IndexType::Fast,
                None => IndexType::Fast,
            },
        )?;
        Ok(format!(
            "{}:{} column value \"{}\" is {}",
            table,
            column,
            value,
            Base64UrlUnpadded::encode_string(&index)
        ))
    }
}

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

fn load_or_random(var: &str, rng: &dyn rand::SecureRandom) -> Result<[u8; 32], String> {
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

#[launch]
fn rocket() -> _ {
    dotenv::dotenv().ok();

    let rng = rand::SystemRandom::new();
    let encryption_key = load_or_random("ENCRYPTION_KEY", &rng).unwrap();
    let signing_key = load_or_random("SIGNING_KEY", &rng).unwrap();
    let derivation_key = load_or_random("DERIVATION_KEY", &rng).unwrap();
    // let rng2 : &dyn rand::SecureRandom = &rng;
    // const KEY_LEN : usize = 32;
    // let mut key_bytes : [u8; KEY_LEN] = [0; KEY_LEN];
    // rng2.fill(&mut key_bytes).expect("Filled random");
    // println!("Key {:?}", key_bytes);
    // let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, &SIGN_KEY);
    let sealing_state = SealingState::new(&aead::CHACHA20_POLY1305, &encryption_key)
        .expect("Encryption key failed to set up");
    // let unbound = aead::UnboundKey::new().expect("Made a key");
    // let nonce_bytes : [u8; 8] = [0; 8];
    // let nonce_seq = CounterNonceSequence::new(nonce_bytes);
    // let opening : aead::OpeningKey<CounterNonceSequence> = aead::BoundKey::new(unbound, nonce_seq);
    // // Need a whole new key and nonce object
    // let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &ENC_KEY).expect("Made a key");
    // let nonce_bytes : [u8; 8] = [0; 8];
    // let nonce_seq = CounterNonceSequence::new(nonce_bytes);
    // let sealing : aead::SealingKey<CounterNonceSequence> = aead::BoundKey::new(unbound, nonce_seq);
    // // let sk = aead::SealingKey::new(unbound, nonce_seq);
    // // sealing.algorithm().tag_len();

    rocket::build()
        .manage(rng)
        // .manage(hmac_key)
        .manage(KeyedHash::new(signing_key))
        // .manage(Arc::new(Mutex::new(sealing)))
        // .manage(Arc::new(Mutex::new(opening)))
        .manage(Arc::new(Mutex::new(sealing_state)))
        .manage(Arc::new(DerivingKey::new(derivation_key)))
        .mount(
            "/",
            routes![
                index,
                sleeping,
                rando,
                sign_thing,
                verify_thing,
                secretbox,
                openbox,
                password,
                verify_password,
                table_value
            ],
        )
        .mount("/hello", routes![index])
        .attach(rocket::shield::Shield::new())
}
