//! Deterministic key generation.
#![no_std]
#![feature(error_in_core)]

use bitflags::bitflags;
use hkdf::Hkdf;
use sgx_types::metadata::*;
use sgx_types::*;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

bitflags! {
    /// Key policy used by SGX to derive a new secret key.
    #[derive(Default)]
    pub struct SgxKeyPolicy: u16 {
        const MRENCLAVE = SGX_KEYPOLICY_MRENCLAVE;
        const MRSIGNER = SGX_KEYPOLICY_MRSIGNER;
        const NOISVPRODID = SGX_KEYPOLICY_NOISVPRODID;
        const CONFIGID = SGX_KEYPOLICY_CONFIGID;
        const ISVFAMILYID = SGX_KEYPOLICY_ISVFAMILYID;
        const ISVEXTPRODID = SGX_KEYPOLICY_ISVEXTPRODID;
    }
}

impl From<SgxKeyPolicy> for u16 {
    fn from(policy: SgxKeyPolicy) -> Self {
        policy.bits()
    }
}

impl From<u16> for SgxKeyPolicy {
    fn from(bits: u16) -> Self {
        SgxKeyPolicy { bits }
    }
}

/// Builder type used to configure SGX's key derivation.
#[must_use]
#[derive(Debug, Default, Eq, PartialEq, Clone, Copy)]
pub struct SgxSecretBuilder {
    key_id: [u8; 32],
    policy: SgxKeyPolicy,
}

fn hash_id_when_too_long(key_id: &[u8]) -> [u8; 32] {
    if key_id.len() > SGX_KEYID_SIZE {
        let mut hasher = Sha256::new();
        hasher.update(key_id);
        return hasher.finalize().into();
    }
    let mut buffer = <[u8; SGX_KEYID_SIZE]>::default();
    buffer.copy_from_slice(key_id);
    buffer
}

type HkdfSha256 = Hkdf<Sha256>;

/// Representation of a secret derived using the `sgx_get_key` API from the
/// Intel SDK.
#[must_use]
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SgxSecret<const KEY_SIZE: usize = 16>([u8; KEY_SIZE]);

impl SgxSecretBuilder {
    /// Instanstiate a new builder in its default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Overwrite the existing `key_id` that is to be requested from SGX.
    pub fn key_id(self, id: &[u8]) -> Self {
        Self {
            key_id: hash_id_when_too_long(id),
            policy: self.policy,
        }
    }

    /// Overwrite the current key derivation policy.
    pub fn policy(self, policy: SgxKeyPolicy) -> Self {
        Self {
            key_id: self.key_id,
            policy,
        }
    }

    /// Generate a new [SgxSecret] deterministically via SGX using metadata
    /// supplied to the current builder.
    ///
    /// **NB:** The current implementation panics when the requested secret is
    /// more than 255 times the length of a SHA256 digest.
    pub fn build<const KEY_SIZE: usize>(&self) -> SgxSecret<KEY_SIZE> {
        // At present the static_assertions crate does not support `const`
        // generics:
        //
        // https://github.com/nvzqz/static-assertions-rs/issues/40.
        //
        // TODO: find away to check this length constraint at compile time.
        assert!(KEY_SIZE <= 255 * Sha256::output_size());
        let report_body = unsafe { *sgx_self_report() }.body;
        let key_request = sgx_key_request_t {
            key_name: SGX_KEYSELECT_SEAL,
            key_policy: u16::from(self.policy),
            isv_svn: report_body.isv_svn,
            reserved1: 0u16,
            cpu_svn: report_body.cpu_svn,
            attribute_mask: report_body.attributes,
            key_id: sgx_key_id_t::default(),
            misc_mask: DEFAULT_MISC_MASK,
            config_svn: report_body.config_svn,
            reserved2: [0u8; SGX_KEY_REQUEST_RESERVED2_BYTES],
        };

        let mut ikm = <[u8; 16]>::default();
        let mut okm = [0u8; KEY_SIZE];
        unsafe { sgx_get_key(&key_request, &mut ikm) };
        let kdf = HkdfSha256::new(Some(&self.key_id), &ikm);
        kdf.expand(&[], &mut okm)
            .expect("Invalid length: requested key is too long");
        SgxSecret(okm)
    }
}
