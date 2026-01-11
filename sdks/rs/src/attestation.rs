use std::collections::BTreeMap;

use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED, UnparsedPublicKey};
use aws_nitro_enclaves_cose::{
    CoseSign1,
    crypto::{Hash, MessageDigest, SignatureAlgorithm, SigningPublicKey},
    error::CoseError,
};
use serde_cbor::{self, value::Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_parser::{
    oid_registry::{OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA384},
    prelude::{FromDer, TbsCertificate, X509Certificate},
    time::ASN1Time,
};

pub const AWS_ROOT_KEY: [u8; 96] = hex_literal::hex!(
    "fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4"
);
pub const MOCK_ROOT_KEY: [u8; 96] = hex_literal::hex!(
    "6c79411ebaae7489a4e8355545c0346784b31df5d08cb1f7c0097836a82f67240f2a7201862880a1d09a0bb326637188fbbafab47a10abe3630fcf8c18d35d96532184985e582c0dce3dace8441f37b9cc9211dff935baae69e4872cc3494410"
);

#[derive(Debug)]
pub struct AttestationDecoded {
    pub root_public_key: Box<[u8]>,
    pub image_id: [u8; 32],
    pub pcrs: [[u8; 48]; 12],
    pub timestamp_ms: u64,
    pub public_key: Box<[u8]>,
    pub user_data: Box<[u8]>,
}

#[derive(Error, Debug)]
pub enum AttestationError {
    // parse errors
    #[error("failed to parse cose")]
    InvalidCose(#[source] CoseError),
    #[error("failed to parse cbor")]
    InvalidCbor(#[source] serde_cbor::Error),
    #[error("x509 error in {context}: {error}")]
    X509 {
        context: String,
        #[source]
        error: x509_parser::nom::Err<x509_parser::error::X509Error>,
    },
    #[error("missing field: {0}")]
    MissingField(String),
    #[error("field {0} has invalid type")]
    InvalidType(String),
    #[error("field {0} has invalid length: {1}")]
    InvalidLength(String, String),
    #[error("timestamp conversion error: {0}")]
    TimestampConversion(#[from] std::num::TryFromIntError),
    // verification errors
    #[error("cose signature verification failed")]
    CoseSignatureVerifyFailed(#[source] CoseError),
    #[error("leaf signature verification failed")]
    LeafSignatureVerifyFailed,
    #[error("certificate chain signature verification failed at index {index}")]
    CertChainSignatureFailed { index: usize },
    #[error("certificate chain issuer or subject mismatch at index {index}")]
    CertChainIssuerOrSubjectMismatch { index: usize },
    #[error("certificate chain expired at index {index}")]
    CertChainExpired { index: usize },
    // expectation mismatch errors
    #[error("timestamp mismatch: expected {expected}, got {got}")]
    TimestampMismatch { expected: u64, got: u64 },
    #[error("too old: expected age {age}, got {got}, now {now}")]
    TooOld { age: u64, got: u64, now: u64 },
    #[error("pcr{idx} mismatch: expected {expected:?}, got {got:?}")]
    PcrsMismatch {
        idx: usize,
        expected: [u8; 48],
        got: [u8; 48],
    },
    #[error("image id mismatch: expected {expected}, got {got}")]
    ImageIdMismatch { expected: String, got: String },
    #[error("root public key mismatch: expected {expected}, got {got}")]
    RootPublicKeyMismatch { expected: String, got: String },
    #[error("public key mismatch: expected {expected}, got {got}")]
    PublicKeyMismatch { expected: String, got: String },
    #[error("user data mismatch: expected {expected}, got {got}")]
    UserDataMismatch { expected: String, got: String },
}

#[derive(Debug, Default, Clone)]
pub struct AttestationExpectations<'a> {
    pub root_public_key: Option<&'a [u8]>,
    pub pcrs: [Option<[u8; 48]>; 12],
    pub image_id: Option<&'a [u8; 32]>,
    pub timestamp_ms: Option<u64>,
    // (max age, current timestamp), in ms
    pub age_ms: Option<(u64, u64)>,
    pub public_key: Option<&'a [u8]>,
    pub user_data: Option<&'a [u8]>,
}

pub fn verify(
    attestation_doc: &[u8],
    expectations: AttestationExpectations,
) -> Result<AttestationDecoded, AttestationError> {
    let mut result = AttestationDecoded {
        root_public_key: Default::default(),
        image_id: Default::default(),
        pcrs: [[0; 48]; 12],
        timestamp_ms: 0,
        public_key: Default::default(),
        user_data: Default::default(),
    };

    // parse attestation doc
    let (cosesign1, mut attestation_doc) = parse_attestation_doc(attestation_doc)?;

    // parse timestamp
    result.timestamp_ms = parse_timestamp(&mut attestation_doc)?;

    // check expected timestamp if exists
    if let Some(expected_ts) = expectations.timestamp_ms
        && result.timestamp_ms != expected_ts
    {
        return Err(AttestationError::TimestampMismatch {
            expected: expected_ts,
            got: result.timestamp_ms,
        });
    }

    // check age if exists
    if let Some((max_age, current_ts)) = expectations.age_ms
        && result.timestamp_ms <= current_ts
        && current_ts - result.timestamp_ms > max_age
    {
        return Err(AttestationError::TooOld {
            age: max_age,
            got: result.timestamp_ms,
            now: current_ts,
        });
    }

    // parse pcrs
    result.pcrs = parse_pcrs(&mut attestation_doc)?;

    // check pcrs if exists
    if let Some((idx, _)) = expectations
        .pcrs
        .iter()
        // add index
        .enumerate()
        // return None if expectation is None so it gets filtered
        // return result of comparison if expectation exists
        .filter_map(|(idx, &expected_pcr)| Some((idx, expected_pcr? == result.pcrs[idx])))
        // short circuit on first comparison failure
        .find(|&(_, res)| !res)
    {
        return Err(AttestationError::PcrsMismatch {
            idx,
            expected: expectations.pcrs[idx].unwrap_or([0; 48]),
            got: result.pcrs[idx],
        });
    };

    // compute image id
    let mut hasher = Sha256::new();
    // bitflags denoting what pcrs are part of the computation
    // this one has 4-15
    hasher.update((4..=15).fold(0u32, |acc, x| acc | (1 << x)).to_be_bytes());
    hasher.update(result.pcrs.as_flattened());
    result.image_id = hasher.finalize().into();

    // check image id if exists
    if let Some(image_id) = expectations.image_id
        && &result.image_id != image_id
    {
        return Err(AttestationError::ImageIdMismatch {
            expected: hex::encode(image_id),
            got: hex::encode(result.image_id),
        });
    }

    // verify signature and cert chain
    result.root_public_key =
        verify_root_of_trust(&mut attestation_doc, &cosesign1, result.timestamp_ms)?;

    // check root public key if exists
    if let Some(root_public_key) = expectations.root_public_key
        && result.root_public_key.as_ref() != root_public_key
    {
        return Err(AttestationError::RootPublicKeyMismatch {
            expected: hex::encode(root_public_key),
            got: hex::encode(&result.root_public_key),
        });
    }

    // return the enclave key
    result.public_key = parse_enclave_key(&mut attestation_doc)?;

    // check enclave public key if exists
    if let Some(public_key) = expectations.public_key
        && result.public_key.as_ref() != public_key
    {
        return Err(AttestationError::PublicKeyMismatch {
            expected: hex::encode(public_key),
            got: hex::encode(&result.public_key),
        });
    }

    // return the user data
    result.user_data = parse_user_data(&mut attestation_doc)?;

    // check user data if exists
    if let Some(user_data) = expectations.user_data
        && result.user_data.as_ref() != user_data
    {
        return Err(AttestationError::UserDataMismatch {
            expected: hex::encode(user_data),
            got: hex::encode(&result.user_data),
        });
    }

    Ok(result)
}

fn parse_attestation_doc(
    attestation_doc: &[u8],
) -> Result<(CoseSign1, BTreeMap<Value, Value>), AttestationError> {
    let cosesign1 =
        CoseSign1::from_bytes(attestation_doc).map_err(AttestationError::InvalidCose)?;
    // SAFETY: method cannot fail if no key is proided
    let payload = cosesign1
        .get_payload::<CertHasher>(None)
        .expect("cannot fail");
    let cbor = serde_cbor::from_slice::<BTreeMap<Value, Value>>(&payload)
        .map_err(AttestationError::InvalidCbor)?;

    Ok((cosesign1, cbor))
}

fn parse_timestamp(attestation_doc: &mut BTreeMap<Value, Value>) -> Result<u64, AttestationError> {
    let timestamp = attestation_doc
        .remove(&"timestamp".to_owned().into())
        .ok_or(AttestationError::MissingField("timestamp".into()))?;
    let timestamp = (match timestamp {
        Value::Integer(b) => Ok(b),
        _ => Err(AttestationError::InvalidType("timestamp".into())),
    })?;
    let timestamp = timestamp.try_into()?;

    Ok(timestamp)
}

fn parse_pcrs(
    attestation_doc: &mut BTreeMap<Value, Value>,
) -> Result<[[u8; 48]; 12], AttestationError> {
    let pcrs_arr = attestation_doc
        .remove(&"nitrotpm_pcrs".to_owned().into())
        .ok_or(AttestationError::MissingField("nitrotpm_pcrs".into()))?;
    let mut pcrs_arr = (match pcrs_arr {
        Value::Map(b) => Ok(b),
        _ => Err(AttestationError::InvalidType("nitrotpm_pcrs".to_string())),
    })?;

    let mut result = [[0; 48]; 12];
    for (i, result_pcr) in result.iter_mut().take(12).enumerate() {
        let i = i + 4;
        let pcr = pcrs_arr
            .remove(&(i as u32).into())
            .ok_or(AttestationError::MissingField(format!("pcr{i}")))?;
        let pcr = (match pcr {
            Value::Bytes(b) => Ok(b),
            _ => Err(AttestationError::InvalidType(format!("pcr{i}"))),
        })?;
        *result_pcr = pcr
            .as_slice()
            .try_into()
            .map_err(|e| AttestationError::InvalidLength(format!("pcr{i}"), format!("{e}")))?;
    }

    Ok(result)
}

fn verify_root_of_trust(
    attestation_doc: &mut BTreeMap<Value, Value>,
    cosesign1: &CoseSign1,
    timestamp: u64,
) -> Result<Box<[u8]>, AttestationError> {
    // verify attestation doc signature
    let enclave_certificate_bytes = attestation_doc
        .remove(&"certificate".to_owned().into())
        .ok_or(AttestationError::MissingField("certificate".into()))?;
    let enclave_certificate_bytes = (match enclave_certificate_bytes {
        Value::Bytes(b) => Ok(b),
        _ => Err(AttestationError::InvalidType("enclave certificate".into())),
    })?;
    let (_, cert) = X509Certificate::from_der(&enclave_certificate_bytes).map_err(|e| {
        AttestationError::X509 {
            context: "leaf".into(),
            error: e,
        }
    })?;

    // Extract public key for COSE verification
    let verifier_cert = CertWrapper(&cert.tbs_certificate);

    let verify_result = cosesign1
        .verify_signature::<CertHasher>(&verifier_cert)
        .map_err(AttestationError::CoseSignatureVerifyFailed)?;

    if !verify_result {
        return Err(AttestationError::LeafSignatureVerifyFailed);
    }

    // verify certificate chain
    let cabundle = attestation_doc
        .remove(&"cabundle".to_owned().into())
        .ok_or(AttestationError::MissingField("cabundle".into()))?;
    let mut cabundle = (match cabundle {
        Value::Array(b) => Ok(b),
        _ => Err(AttestationError::InvalidType("cabundle".into())),
    })?;
    cabundle.reverse();

    let root_public_key = verify_cert_chain(cert, &cabundle, timestamp)?;

    Ok(root_public_key)
}

fn verify_cert_chain(
    cert: X509Certificate,
    cabundle: &[Value],
    timestamp: u64,
) -> Result<Box<[u8]>, AttestationError> {
    let mut certs = Vec::with_capacity(cabundle.len() + 1);
    certs.push(cert);

    for (i, cert_val) in cabundle.iter().enumerate() {
        let cert_der = (match cert_val {
            Value::Bytes(b) => Ok(b),
            _ => Err(AttestationError::InvalidType("cert decode".into())),
        })?;
        let (_, cert) =
            X509Certificate::from_der(cert_der).map_err(|e| AttestationError::X509 {
                context: format!("bundle {}", i),
                error: e,
            })?;
        certs.push(cert);
    }

    for i in 0..(certs.len() - 1) {
        let issuer_spki = &certs[i + 1].tbs_certificate.subject_pki;

        // Use Some(issuer_spki) as expected by x509-parser
        certs[i]
            .verify_signature(Some(issuer_spki))
            .map_err(|_| AttestationError::CertChainSignatureFailed { index: i })?;

        if certs[i + 1].tbs_certificate.subject != certs[i].tbs_certificate.issuer {
            return Err(AttestationError::CertChainIssuerOrSubjectMismatch { index: i });
        }

        let current_time = ASN1Time::from_timestamp((timestamp / 1000) as i64).map_err(|e| {
            AttestationError::X509 {
                context: format!("timestamp {}", i),
                error: e.into(),
            }
        })?;

        if certs[i].tbs_certificate.validity.not_after < current_time
            || certs[i].tbs_certificate.validity.not_before > current_time
        {
            return Err(AttestationError::CertChainExpired { index: i });
        }
    }

    let root_public_key = certs
        .last()
        .ok_or(AttestationError::MissingField("root".into()))?
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data[1..]
        .to_vec()
        .into_boxed_slice();

    Ok(root_public_key)
}

fn parse_enclave_key(
    attestation_doc: &mut BTreeMap<Value, Value>,
) -> Result<Box<[u8]>, AttestationError> {
    let public_key = attestation_doc
        .remove(&"public_key".to_owned().into())
        .ok_or(AttestationError::MissingField("public_key".into()))?;
    let public_key = (match public_key {
        Value::Bytes(b) => Ok(b),
        _ => Err(AttestationError::InvalidType("public_key".into())),
    })?;

    Ok(public_key.into_boxed_slice())
}

fn parse_user_data(
    attestation_doc: &mut BTreeMap<Value, Value>,
) -> Result<Box<[u8]>, AttestationError> {
    let user_data = attestation_doc
        .remove(&"user_data".to_owned().into())
        .ok_or(AttestationError::MissingField("user_data".into()))?;
    let user_data = (match user_data {
        Value::Bytes(b) => Ok(b),
        Value::Null => Ok(vec![]),
        _ => Err(AttestationError::InvalidType("user_data".into())),
    })?;

    Ok(user_data.into_boxed_slice())
}

pub struct CertHasher;

impl Hash for CertHasher {
    fn hash(_algorithm: MessageDigest, data: &[u8]) -> Result<Vec<u8>, CoseError> {
        // NOTE: the verifier function internally hashes the message, return it as is

        // match algorithm {
        //     MessageDigest::Sha256 => Ok(Sha256::digest(data).to_vec()),
        //     MessageDigest::Sha384 => Ok(Sha384::digest(data).to_vec()),
        //     MessageDigest::Sha512 => Ok(Sha512::digest(data).to_vec()),
        // }
        Ok(data.into())
    }
}

struct CertWrapper<'a>(&'a TbsCertificate<'a>);

impl<'a> SigningPublicKey for CertWrapper<'a> {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        if self.0.subject_pki.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
            return Err(CoseError::UnsupportedError("Unsupported key type".into()));
        }
        match self.0.subject_pki.subject_public_key.data.len() {
            65 => Ok((SignatureAlgorithm::ES256, MessageDigest::Sha256)),
            97 => Ok((SignatureAlgorithm::ES384, MessageDigest::Sha384)),
            129 => Ok((SignatureAlgorithm::ES512, MessageDigest::Sha512)),
            _ => Err(CoseError::UnsupportedError("Unsupported key type".into())),
        }
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        if self.0.signature.algorithm != OID_SIG_ECDSA_WITH_SHA384 {
            return Err(CoseError::UnsupportedError(
                "Unsupported signature type".into(),
            ));
        }
        let pubkey = UnparsedPublicKey::new(
            &ECDSA_P384_SHA384_FIXED,
            &self.0.subject_pki.subject_public_key.data,
        );
        pubkey
            .verify(digest, signature)
            .map_err(|_| CoseError::UnverifiedSignature)
            .map(|_| true)
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::attestation::{AWS_ROOT_KEY, AttestationExpectations, MOCK_ROOT_KEY};

    use super::verify;

    // generated using `curl <ip>:<port>/attestation/raw`
    // on the attestation server of a real instance
    #[test]
    fn test_aws_none_specified() {
        let attestation =
            std::fs::read(file!().rsplit_once('/').unwrap().0.to_owned() + "/testcases/aws.bin")
                .unwrap();

        let decoded = verify(&attestation, Default::default()).unwrap();

        assert_eq!(decoded.timestamp_ms, 0x0000019ba6c8dab7);
        assert_eq!(
            decoded.pcrs[0],
            hex!(
                "6e7fd58cca2dcd0b6ca3186c260e47f33d33e4c63b9819609d5b75efb55453529fed4098a7383bfca18d3ca869ff202f"
            )
        );
        assert_eq!(
            decoded.pcrs[1],
            hex!(
                "c10ef05cbff856c3b0b83793118e887985b0ab263162db25badf0affcb01746494a984db2ba517608c2eade447d2dbe9"
            )
        );
        assert_eq!(
            decoded.pcrs[2],
            hex!(
                "518923b0f955d08da077c96aaba522b9decede61c599cea6c41889cfbea4ae4d50529d96fe4d1afdafb65e7f95bf23c4"
            )
        );
        assert_eq!(
            decoded.pcrs[3],
            hex!(
                "98441c7f7625d10058c47683aec486ce311c633235eb555593a7ee791121e3578ae72d04ecef661f272d59058b77af35"
            )
        );
        assert_eq!(
            decoded.pcrs[4],
            hex!(
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        assert_eq!(
            decoded.pcrs[5],
            hex!(
                "39c33c06e6a163f8f04f23b43d1b342677abfcd3bebbd3777bf0429fadb6a7ef5e2e533c0bf7d6dc9aec44370b29d5f4"
            )
        );
        assert_eq!(
            decoded.pcrs[6],
            hex!(
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        assert_eq!(
            decoded.pcrs[7],
            hex!(
                "6dac65857819c581c671ab7edafac3cdf85700c880392d98127af1c94e305f96baa73564f721bf0cee3b190d90c2750f"
            )
        );
        assert_eq!(
            decoded.pcrs[8],
            hex!(
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        assert_eq!(
            decoded.pcrs[9],
            hex!(
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        assert_eq!(
            decoded.pcrs[10],
            hex!(
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        assert_eq!(
            decoded.pcrs[11],
            hex!(
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        assert_eq!(decoded.user_data.as_ref(), hex!("1234"));
        assert_eq!(decoded.public_key.as_ref(), hex!("abcd"));
        assert_eq!(decoded.root_public_key.as_ref(), AWS_ROOT_KEY);
        assert_eq!(
            decoded.image_id,
            hex!("b3dc7d48651dec3f088737ce37e0806a28e516e0caa01d54cf9438176a1c4d00")
        );
    }

    // generated using `curl <ip>:<port>/attestation/raw`
    // on the attestation server of a real Nitro enclave
    #[test]
    fn test_aws_all_specified() {
        let attestation =
            std::fs::read(file!().rsplit_once('/').unwrap().0.to_owned() + "/testcases/aws.bin")
                .unwrap();

        let decoded = verify(
            &attestation,
            AttestationExpectations {
                timestamp_ms: Some(0x0000019ba6c8dab7),
                age_ms: Some((
                    300000,
                    0x0000019ba6c8dab7 + 300000,
                )),
                pcrs: [
                    Some(hex!( "6e7fd58cca2dcd0b6ca3186c260e47f33d33e4c63b9819609d5b75efb55453529fed4098a7383bfca18d3ca869ff202f")),
                    Some(hex!( "c10ef05cbff856c3b0b83793118e887985b0ab263162db25badf0affcb01746494a984db2ba517608c2eade447d2dbe9")),
                    Some(hex!("518923b0f955d08da077c96aaba522b9decede61c599cea6c41889cfbea4ae4d50529d96fe4d1afdafb65e7f95bf23c4")),
                    Some(hex!("98441c7f7625d10058c47683aec486ce311c633235eb555593a7ee791121e3578ae72d04ecef661f272d59058b77af35")),
                    Some(hex!("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
                    Some(hex!("39c33c06e6a163f8f04f23b43d1b342677abfcd3bebbd3777bf0429fadb6a7ef5e2e533c0bf7d6dc9aec44370b29d5f4")),
                    Some(hex!("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
                    Some(hex!("6dac65857819c581c671ab7edafac3cdf85700c880392d98127af1c94e305f96baa73564f721bf0cee3b190d90c2750f")),
                    Some(hex!("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
                    Some(hex!("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
                    Some(hex!("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
                    Some(hex!("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))
                ],
                public_key: Some(&hex!("abcd")),
                user_data: Some(&hex!("1234")),
                root_public_key: Some(&AWS_ROOT_KEY),
                image_id: Some(&hex!("b3dc7d48651dec3f088737ce37e0806a28e516e0caa01d54cf9438176a1c4d00")),
            },
        )
        .unwrap();

        assert_eq!(decoded.timestamp_ms, 0x0000019ba6c8dab7);
        assert_eq!(
            decoded.pcrs[0],
            hex!(
                "6e7fd58cca2dcd0b6ca3186c260e47f33d33e4c63b9819609d5b75efb55453529fed4098a7383bfca18d3ca869ff202f"
            )
        );
        assert_eq!(
            decoded.pcrs[1],
            hex!(
                "c10ef05cbff856c3b0b83793118e887985b0ab263162db25badf0affcb01746494a984db2ba517608c2eade447d2dbe9"
            )
        );
        assert_eq!(
            decoded.pcrs[2],
            hex!(
                "518923b0f955d08da077c96aaba522b9decede61c599cea6c41889cfbea4ae4d50529d96fe4d1afdafb65e7f95bf23c4"
            )
        );
        assert_eq!(
            decoded.pcrs[3],
            hex!(
                "98441c7f7625d10058c47683aec486ce311c633235eb555593a7ee791121e3578ae72d04ecef661f272d59058b77af35"
            )
        );
        assert_eq!(
            decoded.pcrs[4],
            hex!(
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        assert_eq!(
            decoded.pcrs[5],
            hex!(
                "39c33c06e6a163f8f04f23b43d1b342677abfcd3bebbd3777bf0429fadb6a7ef5e2e533c0bf7d6dc9aec44370b29d5f4"
            )
        );
        assert_eq!(
            decoded.pcrs[6],
            hex!(
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        assert_eq!(
            decoded.pcrs[7],
            hex!(
                "6dac65857819c581c671ab7edafac3cdf85700c880392d98127af1c94e305f96baa73564f721bf0cee3b190d90c2750f"
            )
        );
        assert_eq!(
            decoded.pcrs[8],
            hex!(
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        assert_eq!(
            decoded.pcrs[9],
            hex!(
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        assert_eq!(
            decoded.pcrs[10],
            hex!(
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        assert_eq!(
            decoded.pcrs[11],
            hex!(
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        assert_eq!(decoded.user_data.as_ref(), hex!("1234"));
        assert_eq!(decoded.public_key.as_ref(), hex!("abcd"));
        assert_eq!(decoded.root_public_key.as_ref(), AWS_ROOT_KEY);
        assert_eq!(
            decoded.image_id,
            hex!("b3dc7d48651dec3f088737ce37e0806a28e516e0caa01d54cf9438176a1c4d00")
        );
    }

    // generated using `curl <ip>:<port>/attestation/raw?public_key=abcd&user_data=1234`
    // on a custom mock attestation server running locally
    #[test]
    fn test_mock_none_specified() {
        let attestation =
            std::fs::read(file!().rsplit_once('/').unwrap().0.to_owned() + "/testcases/mock.bin")
                .unwrap();

        let decoded = verify(&attestation, Default::default()).unwrap();

        assert_eq!(decoded.timestamp_ms, 0x0000019babf13dfd);
        assert_eq!(decoded.pcrs[0], [4; 48]);
        assert_eq!(decoded.pcrs[1], [5; 48]);
        assert_eq!(decoded.pcrs[2], [6; 48]);
        assert_eq!(decoded.pcrs[3], [7; 48]);
        assert_eq!(decoded.pcrs[4], [8; 48]);
        assert_eq!(decoded.pcrs[5], [9; 48]);
        assert_eq!(decoded.pcrs[6], [10; 48]);
        assert_eq!(decoded.pcrs[7], [11; 48]);
        assert_eq!(decoded.pcrs[8], [12; 48]);
        assert_eq!(decoded.pcrs[9], [13; 48]);
        assert_eq!(decoded.pcrs[10], [14; 48]);
        assert_eq!(decoded.pcrs[11], [15; 48]);
        assert_eq!(decoded.user_data.as_ref(), hex!("1234"));
        assert_eq!(decoded.public_key.as_ref(), hex!("abcd"));
        assert_eq!(decoded.root_public_key.as_ref(), MOCK_ROOT_KEY);
        assert_eq!(
            decoded.image_id,
            hex!("e3caee4ad768d705b977a3687c74b25ff89e4dbd71091e16e04b3f9f867c926b")
        );
    }

    // generated using `curl <ip>:<port>/attestation/raw?public_key=abcd&user_data=1234`
    // on a custom mock attestation server running locally
    #[test]
    fn test_mock_all_specified() {
        let attestation =
            std::fs::read(file!().rsplit_once('/').unwrap().0.to_owned() + "/testcases/mock.bin")
                .unwrap();

        let decoded = verify(
            &attestation,
            AttestationExpectations {
                timestamp_ms: Some(0x0000019babf13dfd),
                age_ms: Some((300000, 0x0000019babf13dfd + 300000)),
                pcrs: [
                    Some([4; 48]),
                    Some([5; 48]),
                    Some([6; 48]),
                    Some([7; 48]),
                    Some([8; 48]),
                    Some([9; 48]),
                    Some([10; 48]),
                    Some([11; 48]),
                    Some([12; 48]),
                    Some([13; 48]),
                    Some([14; 48]),
                    Some([15; 48]),
                ],
                public_key: Some(&hex!("abcd")),
                user_data: Some(&hex!("1234")),
                root_public_key: Some(&MOCK_ROOT_KEY),
                image_id: Some(&hex!(
                    "e3caee4ad768d705b977a3687c74b25ff89e4dbd71091e16e04b3f9f867c926b"
                )),
            },
        )
        .unwrap();

        assert_eq!(decoded.timestamp_ms, 0x0000019babf13dfd);
        assert_eq!(decoded.pcrs[0], [4; 48]);
        assert_eq!(decoded.pcrs[1], [5; 48]);
        assert_eq!(decoded.pcrs[2], [6; 48]);
        assert_eq!(decoded.pcrs[3], [7; 48]);
        assert_eq!(decoded.pcrs[4], [8; 48]);
        assert_eq!(decoded.pcrs[5], [9; 48]);
        assert_eq!(decoded.pcrs[6], [10; 48]);
        assert_eq!(decoded.pcrs[7], [11; 48]);
        assert_eq!(decoded.pcrs[8], [12; 48]);
        assert_eq!(decoded.pcrs[9], [13; 48]);
        assert_eq!(decoded.pcrs[10], [14; 48]);
        assert_eq!(decoded.pcrs[11], [15; 48]);
        assert_eq!(decoded.user_data.as_ref(), hex!("1234"));
        assert_eq!(decoded.public_key.as_ref(), hex!("abcd"));
        assert_eq!(decoded.root_public_key.as_ref(), MOCK_ROOT_KEY);
        assert_eq!(
            decoded.image_id,
            hex!("e3caee4ad768d705b977a3687c74b25ff89e4dbd71091e16e04b3f9f867c926b")
        );
    }
}
