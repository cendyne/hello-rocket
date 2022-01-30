#[macro_use]
extern crate rocket;
use ring::rand;
use rocket::tokio::time::{sleep, Duration};
use rocket::State;
use std::sync::Arc;
use std::vec;
mod stuff;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use stuff::blindindex::{blind_index, IndexType};
use stuff::bloom::secret_match;
use stuff::derivekey::{DeriveKeyContext, DeriveKeyPurpose, DerivingKey};
use stuff::environment::load_or_random;
use stuff::keyedhash::{sign_message, verify_message, KeyedHash};
use stuff::padding::PaddingState;
use stuff::password::{encode_password, verify_password};
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
    let encoded =
        Base64UrlSafeNoPadding::encode_to_string(&key_value).map_err(|e| format!("{}", e))?;
    Ok(encoded)
}

#[get("/sign/<param>")]
fn sign_thing(param: &str, hmac_key: &State<KeyedHash>) -> Result<String, String> {
    let message = sign_message(param.as_bytes(), &*hmac_key)?;
    let encoded =
        Base64UrlSafeNoPadding::encode_to_string(&message).map_err(|e| format!("{}", e))?;
    let small_bloom = hmac_key.sign_truncated_u32(&message);
    let bigger_bloom = hmac_key.sign_truncated_u64(&message);
    Ok(format!(
        "{} -> {}\nu32 -> {}\nu64 -> {}",
        param, encoded, small_bloom, bigger_bloom
    ))
}

#[get("/verify/<param>")]
fn verify_thing(param: &str, hmac_key: &State<KeyedHash>) -> Result<String, String> {
    let message = Base64UrlSafeNoPadding::decode_to_vec(param, None)
        .map_err(|_| "Invalid Base64 input".to_string())?;
    let content = verify_message(&message, &*hmac_key)?;
    let text = std::str::from_utf8(content).map_err(|e| format!("{}", e))?;
    Ok(format!("{} -> {}", param, text))
}

#[get("/secret/<param>/<aad>")]
fn secretbox(param: &str, aad: &str, encrypt: &State<Arc<SealingState>>) -> Result<String, String> {
    let final_message = seal_secret(param.as_bytes(), aad.as_bytes(), &*encrypt)?;

    // let encoded = Base64::encode_string(message);
    let encoded =
        Base64UrlSafeNoPadding::encode_to_string(&final_message).map_err(|e| format!("{}", e))?;
    Ok(format!("Secret is {} and result: {}", param, encoded))
}

#[get("/open/<secret>/<aad>")]
fn openbox(secret: &str, aad: &str, encrypt: &State<Arc<SealingState>>) -> Result<String, String> {
    let message = Base64UrlSafeNoPadding::decode_to_vec(secret, None)
        .map_err(|_| "Invalid Base64 input".to_string())?;
    // println!("Got message {:x?}", message);
    let decrypted = open_secret(&message[..], aad.as_bytes(), &*encrypt)?;
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
    let encoded = encode_password(secret.as_bytes(), rng.inner())?;
    let encoded: &RawStr = RawStr::new(&encoded);
    Ok(format!("{}", RawStr::percent_encode(encoded)))
}

#[get("/verify-password/<secret>/<encoded>")]
fn password_verify(secret: &str, encoded: &str) -> Result<String, String> {
    verify_password(secret.as_bytes(), encoded)?;
    Ok(format!("{} is the password for {}", secret, encoded))
}

#[get("/pad-message/<message>/<len>")]
fn pad_message_handler(
    message: &str,
    len: usize,
    padding: &State<Arc<PaddingState>>,
) -> Result<String, String> {
    let result = padding.pad(message.as_bytes(), len)?;
    Ok(format!(
        "message {} padded to {}",
        message,
        Base64UrlSafeNoPadding::encode_to_string(result).map_err(|e| format!("{}", e))?
    ))
}

#[get("/unpad-message/<message>")]
fn unpad_message_handler(message: &str) -> Result<String, String> {
    let decoded = Base64UrlSafeNoPadding::decode_to_vec(message, None)
        .map_err(|_| "Invalid Base64 input".to_string())?;
    let result = PaddingState::unpad(&decoded[..])?;
    let text = std::str::from_utf8(result).map_err(|e| format!("{}", e))?;
    Ok(format!("message {} unpadded to {}", message, text))
}

#[get("/match-message/<message>/<secret>/<aad>")]
fn match_message_handler(
    message: &str,
    secret: &str,
    aad: &str,
    encrypt: &State<Arc<SealingState>>,
) -> Result<String, String> {
    let decoded = Base64UrlSafeNoPadding::decode_to_vec(secret, None)
        .map_err(|_| "Invalid Base64 input".to_string())?;
    if secret_match(message.as_bytes(), aad.as_bytes(), &decoded, encrypt)? {
        Ok(format!("message {} matches secret {}", message, secret))
    } else {
        Ok(format!(
            "message {} does not match secret {}",
            message, secret
        ))
    }
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
            Base64UrlSafeNoPadding::encode_to_string(key).map_err(|e| format!("{}", e))?
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
            Base64UrlSafeNoPadding::encode_to_string(index).map_err(|e| format!("{}", e))?
        ))
    }
}

#[launch]
fn rocket() -> _ {
    dotenv::dotenv().ok();

    let rng = rand::SystemRandom::new();
    let encryption_key = load_or_random("ENCRYPTION_KEY", &rng).unwrap();
    let signing_key = load_or_random("SIGNING_KEY", &rng).unwrap();
    let derivation_key = load_or_random("DERIVATION_KEY", &rng).unwrap();
    let sealing_state =
        SealingState::new(&encryption_key).expect("Encryption key failed to set up");

    rocket::build()
        .manage(rng)
        .manage(KeyedHash::new(signing_key))
        .manage(Arc::new(sealing_state))
        .manage(Arc::new(DerivingKey::new(derivation_key)))
        .manage(Arc::new(PaddingState::new()))
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
                password_verify,
                pad_message_handler,
                unpad_message_handler,
                match_message_handler,
                table_value
            ],
        )
        .mount("/hello", routes![index])
        .attach(rocket::shield::Shield::new())
}
