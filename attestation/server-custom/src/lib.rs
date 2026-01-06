use axum::http::StatusCode;

pub fn get_attestation_doc(
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    return nitro_tpm_attest::attestation_document(
        user_data,
        None, // nonce
        Some(pub_key.to_vec()),
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")));
}

pub fn get_hex_attestation_doc(
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> Result<String, (StatusCode, String)> {
    get_attestation_doc(pub_key, user_data, nonce).map(hex::encode)
}
