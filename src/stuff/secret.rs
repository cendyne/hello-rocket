use crate::stuff::oncenonce::OneNonceSequence;
use ring::{aead, rand};

pub struct SealingState {
    pub algorithm: &'static aead::Algorithm,
    key_material: Vec<u8>,
    rng: rand::SystemRandom,
    nonce: [u8; aead::NONCE_LEN],
}

pub struct SealingKeyWithNonce(
    pub aead::SealingKey<OneNonceSequence>,
    pub [u8; aead::NONCE_LEN],
);

impl SealingState {
    pub fn new(algorithm: &'static aead::Algorithm, key: &[u8]) -> Result<Self, String> {
        let rng = rand::SystemRandom::new();
        let mut bytes: [u8; 12] = [0; 12];
        let rng2: &dyn rand::SecureRandom = &rng;
        rng2.fill(&mut bytes[0..8])
            .map_err(|_| "Could not init nonce")?;
        let mut key_material = vec![0; key.len()];
        key_material.copy_from_slice(key);

        Ok(Self {
            algorithm,
            key_material,
            rng,
            nonce: bytes,
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
            let rng2: &dyn rand::SecureRandom = &self.rng;
            rng2.fill(&mut self.nonce[0..8])
                .map_err(|_| "Could not init nonce")?;
            self.nonce[8] = 0;
            self.nonce[9] = 0;
            self.nonce[10] = 0;
            self.nonce[11] = 0;
        }
        println!("Next nonce: {:x?}", self.nonce);
        Ok(nonce)
    }

    pub fn sealing_key(&mut self) -> Result<SealingKeyWithNonce, String> {
        let unbound = aead::UnboundKey::new(self.algorithm, &self.key_material)
            .map_err(|_| "Could not create key")?;
        let next_nonce = self.next_nonce()?;

        let nonce = OneNonceSequence::new(next_nonce);
        Ok(SealingKeyWithNonce(
            aead::BoundKey::new(unbound, nonce),
            next_nonce,
        ))
    }

    pub fn opening_key(
        &self,
        nonce: [u8; aead::NONCE_LEN],
    ) -> Result<aead::OpeningKey<OneNonceSequence>, String> {
        let unbound = aead::UnboundKey::new(self.algorithm, &self.key_material)
            .map_err(|_| "Could not create key")?;
        let nonce = OneNonceSequence::new(nonce);
        Ok(aead::BoundKey::new(unbound, nonce))
    }
}

pub fn open_secret(
    message: &[u8],
    aad: &[u8],
    encrypt_key: &SealingState,
) -> Result<Vec<u8>, String> {
    let additional_data = aead::Aad::from(aad);
    let message_length = message.len();
    let tag_length = encrypt_key.algorithm.tag_len();
    if message_length <= tag_length + aead::NONCE_LEN {
        return Err("Insufficient Length".to_string());
    }
    let length = message_length - tag_length - aead::NONCE_LEN;
    let mut nonce: [u8; aead::NONCE_LEN] = [0; aead::NONCE_LEN];
    nonce.copy_from_slice(&message[0..aead::NONCE_LEN]);
    // println!("Nonce found {:?}", nonce);
    let mut offset_message = vec![];
    offset_message.extend_from_slice(&message[aead::NONCE_LEN..]);
    // println!("Message found {:?}", &offset_message[0..length]);
    // println!("Tag found {:?}", &offset_message[length..]);
    let mut opening_key = encrypt_key.opening_key(nonce)?;
    let result = opening_key
        .open_in_place(additional_data, &mut offset_message)
        .map_err(|_| "could not open message")?;
    let mut decrypted = vec![];
    decrypted.extend_from_slice(&result[0..length]);
    Ok(decrypted)
}

pub fn seal_secret(
    message: &[u8],
    aad: &[u8],
    encrypt_key: &mut SealingState,
) -> Result<Vec<u8>, String> {
    let additional_data = aead::Aad::from(aad);
    let mut cloned = vec![0; message.len()];
    cloned.copy_from_slice(message);
    let sealing_key_with_nonce = encrypt_key.sealing_key()?;
    let mut sealing_key = sealing_key_with_nonce.0;
    let sealing_nonce = sealing_key_with_nonce.1;
    let mut final_message = vec![];
    final_message.reserve(sealing_nonce.len() + message.len() + encrypt_key.algorithm.tag_len());
    final_message.extend_from_slice(&sealing_nonce);
    final_message.extend_from_slice(message);

    let tag = sealing_key
        .seal_in_place_separate_tag(additional_data, &mut final_message[sealing_nonce.len()..])
        .map_err(|_| "Could not seal in place")?;
    final_message.extend_from_slice(tag.as_ref());

    // println!(
    //     "Nonce: {:?}, Message {:?}, Tag {:?}",
    //     sealing_nonce,
    //     message,
    //     tag.as_ref()
    // );
    // println!("Finally: {:?}", final_message);

    Ok(final_message)
}
