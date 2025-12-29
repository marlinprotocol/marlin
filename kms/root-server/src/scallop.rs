use std::time::{SystemTime, UNIX_EPOCH};

use oyster::{
    attestation::{self, AWS_ROOT_KEY, AttestationExpectations},
    scallop::{Key, ScallopAuthStore},
};

#[derive(Clone, Default)]
pub struct AuthStore {}

// holds image id
pub type AuthStoreState = [u8; 32];

impl ScallopAuthStore for AuthStore {
    type State = AuthStoreState;

    fn verify(&mut self, attestation: &[u8], key: Key) -> Option<Self::State> {
        let Ok(now) = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|x| x.as_millis() as u64)
        else {
            return None;
        };

        let Ok(decoded) = attestation::verify(
            attestation,
            AttestationExpectations {
                // TODO: hardcoded, make it a param
                age_ms: Some((300000, now)),
                root_public_key: Some(&AWS_ROOT_KEY),
                public_key: Some(&key),
                // do not care about PCRs
                // will derive different keys for each set
                // do not care about user data
                // _could_ potentially enforce zero user data
                // but do not see a good reason as to why
                ..Default::default()
            },
        ) else {
            return None;
        };

        return Some(decoded.image_id);
    }
}
