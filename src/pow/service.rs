use super::{Error, Prover};
use std::{thread, time};

const BACKOFF_SECS: u64 = 5;

pub struct K2powService {
    k2pow_service: String,
}

impl K2powService {
    pub fn new(k2pow_service: String) -> Self {
        Self { k2pow_service }
    }
}

impl Prover for K2powService {
    fn prove(
        &self,
        nonce_group: u8,
        challenge: &[u8; 8],
        difficulty: &[u8; 32],
        miner_id: &[u8; 32],
    ) -> Result<u64, Error> {
        let client = reqwest::blocking::Client::new();
        let uri = format!(
            "{}/job/{}/{}/{}/{}",
            self.k2pow_service,
            hex::encode(miner_id),
            nonce_group,
            hex::encode(challenge),
            hex::encode(difficulty)
        );
        let backoff = time::Duration::from_secs(BACKOFF_SECS);

        loop {
            let res = client.get(&uri).send().unwrap();
            let status = res.status();
            let txt = res.text().unwrap();
            let res = match status {
                reqwest::StatusCode::OK => Ok(txt.parse::<u64>().unwrap()),
                reqwest::StatusCode::INTERNAL_SERVER_ERROR => Err(Error::Internal(txt.into())),
                reqwest::StatusCode::CREATED => {
                    thread::sleep(backoff);
                    continue;
                }
                reqwest::StatusCode::TOO_MANY_REQUESTS => {
                    thread::sleep(backoff);
                    continue;
                }
                _ => Err(Error::Internal("unknown status code returned".into())),
            };
            return res;
        }
    }
    fn par(&self) -> bool {
        true
    }
}
