pub fn get_attestation_doc(pub_key: &[u8], user_data: &[u8]) -> Result<Vec<u8>, String> {
    return nitro_tpm_attest::attestation_document(
        Some(user_data.to_vec()),
        None, // nonce
        Some(pub_key.to_vec()),
    )
    .map_err(|e| format!("{e:?}"));
}

pub fn get_hex_attestation_doc(pub_key: &[u8], user_data: &[u8]) -> Result<String, String> {
    let attestation = get_attestation_doc(pub_key, user_data)?;
    return Ok(hex::encode(attestation));
}
