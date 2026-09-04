use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use uuid::Uuid;

use crate::StoreError;

const NONCE_BYTES: usize = 12;

#[derive(Clone)]
pub(crate) struct ReceiptCipher(Aes256Gcm);

impl ReceiptCipher {
    pub(crate) fn new(key: &[u8]) -> Result<Self, StoreError> {
        if key.len() != 32 {
            return Err(StoreError::Configuration(
                "receipt encryption key must be exactly 32 bytes",
            ));
        }
        Ok(Self(Aes256Gcm::new_from_slice(key).map_err(|_| {
            StoreError::Configuration("receipt encryption key is invalid")
        })?))
    }

    pub(crate) fn encrypt(
        &self,
        idempotency_key: Uuid,
        operation_id: Uuid,
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_BYTES], Vec<u8>), StoreError> {
        let mut nonce = [0_u8; NONCE_BYTES];
        getrandom::fill(&mut nonce)
            .map_err(|_| StoreError::Encryption("cannot generate receipt nonce"))?;
        let ciphertext = self
            .0
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad(idempotency_key, operation_id),
                },
            )
            .map_err(|_| StoreError::Encryption("cannot encrypt operation receipt"))?;
        Ok((nonce, ciphertext))
    }

    pub(crate) fn decrypt(
        &self,
        idempotency_key: Uuid,
        operation_id: Uuid,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        if nonce.len() != NONCE_BYTES {
            return Err(StoreError::CorruptData("operation receipt nonce"));
        }
        self.0
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad(idempotency_key, operation_id),
                },
            )
            .map_err(|_| StoreError::Encryption("cannot decrypt operation receipt"))
    }
}

fn aad(idempotency_key: Uuid, operation_id: Uuid) -> [u8; 48] {
    let mut value = [0_u8; 48];
    value[..16].copy_from_slice(idempotency_key.as_bytes());
    value[16..32].copy_from_slice(operation_id.as_bytes());
    value[32..].copy_from_slice(b"syouyu-receipt-1");
    value
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::ReceiptCipher;

    #[test]
    fn receipt_encryption_is_bound_to_operation() {
        let cipher = ReceiptCipher::new(&[7; 32]).unwrap();
        let key = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let (nonce, ciphertext) = cipher.encrypt(key, operation, b"secret").unwrap();
        assert_eq!(
            cipher.decrypt(key, operation, &nonce, &ciphertext).unwrap(),
            b"secret"
        );
        assert!(
            cipher
                .decrypt(key, Uuid::new_v4(), &nonce, &ciphertext)
                .is_err()
        );
        assert!(!ciphertext.windows(6).any(|value| value == b"secret"));
    }
}
