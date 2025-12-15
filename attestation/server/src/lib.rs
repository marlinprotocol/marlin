use axum::http::StatusCode;

pub fn get_attestation_doc(
    pub_key: &[u8],
    user_data: &[u8],
) -> Result<Vec<u8>, (StatusCode, String)> {
    return nitro_tpm_attest::attestation_document(
        Some(user_data.to_vec()),
        None, // nonce
        Some(pub_key.to_vec()),
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")));
}

pub fn get_hex_attestation_doc(
    pub_key: &[u8],
    user_data: &[u8],
) -> Result<String, (StatusCode, String)> {
    let attestation = get_attestation_doc(pub_key, user_data)?;
    return Ok(hex::encode(attestation));
}
