use axum::http::StatusCode;

pub fn get_attestation_doc(
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> Result<Vec<u8>, (StatusCode, String)> {
    return nitro_tpm_attest::attestation_document(
        user_data.map(Vec::from),
        nonce.map(Vec::from),
        public_key.map(Vec::from),
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")));
}

pub fn get_hex_attestation_doc(
    public_key: Option<&[u8]>,
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
) -> Result<String, (StatusCode, String)> {
    get_attestation_doc(public_key, user_data, nonce).map(hex::encode)
}
