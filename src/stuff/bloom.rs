use crate::stuff::secret::{SealingState,open_secret};
use ring::constant_time::{verify_slices_are_equal};

pub fn secret_match(expected: &[u8], aad: &[u8], secret: &[u8], key: &SealingState) -> Result<bool, String> {
    let value = open_secret(secret, aad, key)?;
    verify_slices_are_equal(expected, &value)
        .map(|_| true)
        .or(Ok(false))
}