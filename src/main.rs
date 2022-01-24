#[macro_use] extern crate rocket;
use rocket::tokio::time::{sleep, Duration};
use ring::{rand,aead};
use std::sync::{Arc, Mutex};
use rocket::State;
use std::vec;
use base64ct::{Base64UrlUnpadded, Encoding};
use argon2::{self, Config};
use std::env;

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
        .map_err(|_| "gen random failed")?.expose();
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
    let message = Base64UrlUnpadded::decode_vec(param)
        .map_err(|_| "Invalid Base64 input")?;
    let hash_length = hmac_key.length();
    let message_length = message.len();
    if message_length <= hash_length {
        return Err("Insufficient Length".to_string());
    }
    let length = message_length - hash_length;
    let mut tag : [u8; 32] = [0; 32];
    tag.copy_from_slice(&message[length..length+32]);
    hmac_key.verify(&message[0..length], tag)?;
    let text = std::str::from_utf8(&message[0..length])
        .map_err(|e| format!("{}", e))?;
    Ok(format!("{} -> {}", param, text))
}

#[get("/secret/<param>/<aad>")]
fn secretbox(param: &str, aad: &str, encrypt: &State<Arc<Mutex<SealingState>>>) -> Result<String, String> {
    let aadbytes = aad.as_bytes();
    let additional_data = aead::Aad::from(&aadbytes);
    let mut encrypt_key = encrypt.lock()
        .map_err(|_| "Could not obtain encryption key")?;

    let mut message = vec![0; param.len()];
    message.copy_from_slice(param.as_bytes());
    let sealing_key_with_nonce = encrypt_key.sealing_key()?;
    let mut sealing_key = sealing_key_with_nonce.0;
    let sealing_nonce = sealing_key_with_nonce.1;
    let tag = sealing_key.seal_in_place_separate_tag(additional_data, &mut message)
        .map_err(|_| "Could not seal in place")?;
    
    println!("Nonce: {:?}, Message {:?}, Tag {:?}", sealing_nonce, message, tag.as_ref());
    let mut final_message = vec![];
    final_message.extend_from_slice(&sealing_nonce);
    final_message.append(&mut message);
    final_message.extend_from_slice(tag.as_ref());
    
    // let encoded = Base64::encode_string(message);
    let encoded = Base64UrlUnpadded::encode_string(&final_message);
    Ok(format!("Secret is {} and result: {}", param, encoded))
}

#[get("/open/<secret>/<aad>")]
fn openbox(secret: &str, aad: &str, encrypt: &State<Arc<Mutex<SealingState>>>) -> Result<String, String> {
    let aadbytes = aad.as_bytes();
    let message = Base64UrlUnpadded::decode_vec(secret)
        .map_err(|_| "Could not decode")?;
    println!("Got message {:x?}", message);
    let additional_data = aead::Aad::from(&aadbytes);
    let mut encrypt_key = encrypt.lock()
        .map_err(|_| "Could not obtain encryption key")?;
    let message_length = message.len();
    let tag_length = encrypt_key.algorithm.tag_len();
    if message_length <= tag_length + aead::NONCE_LEN {
        return Err("Insufficient Length".to_string());
    }
    let length = message_length - tag_length - aead::NONCE_LEN;
    let mut nonce : [u8; aead::NONCE_LEN] = [0;aead::NONCE_LEN];
    nonce.copy_from_slice(&message[0..aead::NONCE_LEN]);
    println!("Nonce found {:?}", nonce);
    let mut offset_message = vec![];
    offset_message.extend_from_slice(&message[aead::NONCE_LEN..]);
    println!("Message found {:?}", &offset_message[0..length]);
    println!("Tag found {:?}", &offset_message[length..]);
    let mut opening_key = encrypt_key.opening_key(nonce)?;
    let result = opening_key.open_in_place(additional_data, &mut offset_message)
        .map_err(|_| "could not open message")?;
    let text = std::str::from_utf8(&result[0..length]).map_err(|e| format!("{}", e))?;
    Ok(format!("Secret is {} and length is {}", text, length))
}

#[get("/password/<secret>")]
fn password(secret: &str, rng: &State<rand::SystemRandom>) -> Result<String, String> {
    use rocket::http::RawStr;
    let pwd = secret.as_bytes();
    let salt: [u8; 16] = rand::generate(rng.inner())
        .map_err(|_| "gen random failed")?.expose();
    let config = Config::default();
    let encoded = argon2::hash_encoded(pwd, &salt, &config)
        .map_err(|_| "Could not encode password")?;
    let encoded: &RawStr = RawStr::new(&encoded);
    Ok(format!("{}", RawStr::percent_encode(encoded)))
}

#[get("/verify-password/<secret>/<encoded>"q)]
fn verify_password(secret: &str, encoded: &str) -> Result<String, String> {
    let pwd = secret.as_bytes();
    argon2::verify_encoded(encoded, pwd)
        .map_err(|_| "Could not encode password")?;
    Ok(format!("{} is the password for {}", secret, encoded))
}

struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    fn new(nonce: [u8; aead::NONCE_LEN]) -> Self {
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        Self(Some(nonce))
    }
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified)
    }
}

struct SealingState {
    algorithm: &'static aead::Algorithm,
    key_material: Vec<u8>,
    rng: rand::SystemRandom,
    nonce: [u8; aead::NONCE_LEN]
}

struct SealingKeyWithNonce(aead::SealingKey<OneNonceSequence>, [u8; aead::NONCE_LEN]);

impl SealingState {
    fn new(algorithm: &'static aead::Algorithm, key: &[u8]) -> Result<Self, String> {
        let rng = rand::SystemRandom::new();
        let mut bytes: [u8; 12] = [0; 12];
        let rng2 : &dyn rand::SecureRandom = &rng;
        rng2.fill(&mut bytes[0..8]).map_err(|_| "Could not init nonce")?;
        let mut key_material = vec![0; key.len()];
        key_material.copy_from_slice(key);
        
        Ok(Self {
            algorithm,
            key_material,
            rng,
            nonce: bytes
        })
    }

    fn next_nonce(&mut self) -> Result<[u8; aead::NONCE_LEN], String> {
        let mut nonce = [0; aead::NONCE_LEN];
        nonce.clone_from_slice(&self.nonce);
        let mut refresh = false;
        for i in [11, 10, 9, 8] {
            if self.nonce[i] == 255 {
                self.nonce[i] = 0;
                if i == 8 {
                    refresh = true;
                    break;
                }
            } else {
                self.nonce[i] += 1;
                break;
            }
        }
        // Refresh nonce after 2^32 times
        if refresh {
            let rng2 : &dyn rand::SecureRandom = &self.rng;
            rng2.fill(&mut self.nonce[0..8]).map_err(|_| "Could not init nonce")?;
            self.nonce[8] = 0;
            self.nonce[9] = 0;
            self.nonce[10] = 0;
            self.nonce[11] = 0;
        }
        println!("Next nonce: {:x?}", self.nonce);
        Ok(nonce)
    }

    fn sealing_key(&mut self) -> Result<SealingKeyWithNonce, String> {
        let unbound = aead::UnboundKey::new(self.algorithm, &self.key_material)
            .map_err(|_| "Could not create key")?;
        let next_nonce = self.next_nonce()?;

        let nonce = OneNonceSequence::new(next_nonce);
        Ok(SealingKeyWithNonce(aead::BoundKey::new(unbound, nonce), next_nonce))
    }

    fn opening_key(&mut self, nonce: [u8; aead::NONCE_LEN]) -> Result<aead::OpeningKey<OneNonceSequence>, String> {
        let unbound = aead::UnboundKey::new(self.algorithm, &self.key_material)
            .map_err(|_| "Could not create key")?;
        let nonce = OneNonceSequence::new(nonce);
        Ok(aead::BoundKey::new(unbound, nonce))
    }
}

struct KeyedHash([u8; 32]);
impl KeyedHash {
    fn new(key : [u8; 32]) -> KeyedHash {
        Self(key)
    }
    fn sign(&self, data: &[u8]) -> blake3::Hash {
        blake3::keyed_hash(&self.0, data)
    }
    fn length(&self) -> usize {
        blake3::OUT_LEN
    }
    fn verify(&self, data: &[u8], tag: [u8; 32]) -> Result<(), String> {
        let hash = blake3::keyed_hash(&self.0, data);
        let other = blake3::Hash::from(tag);
        // This uses constant time comparison internally
        if hash != other {
            return Err("Invalid Signature".to_string());
        }
        Ok(())
    }
}

fn load_key(var: &str) -> Result<[u8; 32], String> {
    let res = env::var(var)
        .map_err(|e| format!("Failed to load {}: {}", var, e))?;
    let message = Base64UrlUnpadded::decode_vec(&res)
        .map_err(|_| format!("Failed to load {}, expected base64 string", var))?;
    if message.len() == 32 {
        let mut result : [u8;32] = [0; 32];
        result.copy_from_slice(&message);
        Ok(result)
    } else {
        Err(format!("Failed to load {}, it has length {} but 32 bytes are expected", var, message.len()))
    }
}

fn random_32(rng: &dyn rand::SecureRandom) -> Result<[u8; 32], String> {
    let mut result : [u8;32] = [0; 32];
    rng.fill(&mut result).map_err(|_| "Could not init nonce")?;
    Ok(result)
}

fn load_or_random(var: &str, rng : &dyn rand::SecureRandom) -> [u8; 32] {
    match load_key(var) {
        Ok(val) => {
            val
        }
        Err(msg) => {
            println!("{}", msg);
            println!("Attempting to load a random key for {}", var);
            let key = random_32(rng).unwrap();
            println!("Consider setting {}={} in the environment or .env file", var, Base64UrlUnpadded::encode_string(&key));
            key
        }
    }
}

#[launch]
fn rocket() -> _ {
    dotenv::dotenv().ok();

    let rng = rand::SystemRandom::new();
    let encryption_key = load_or_random("ENCRYPTION_KEY", &rng);
    let signing_key = load_or_random("SIGNING_KEY", &rng);
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
    .mount("/", routes![index, sleeping, rando, sign_thing, verify_thing, secretbox, openbox, password, verify_password])
    .mount("/hello", routes![index])
    .attach(rocket::shield::Shield::new())
}
