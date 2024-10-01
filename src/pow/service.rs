use super::{Error, Prover};
use futures::future;
use reqwest;
use std::ops::Range;
use std::{thread, time};
use tokio::runtime::Runtime;

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
            let res = match client.get(&uri).send() {
                Ok(res) => res,
                Err(err) => {
                    log::warn!("get job error: {}. backing off before retry", err);
                    thread::sleep(backoff);
                    continue;
                }
            };
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

    fn prove_many(
        &self,
        nonce_groups: Range<u32>,
        challenge: &[u8; 8],
        difficulty: &[u8; 32],
        miner_id: &[u8; 32],
    ) -> Result<Vec<(u32, u64)>, Error> {
        // Create a new Tokio runtime
        let rt = Runtime::new().unwrap();
        let k2p = self.k2pow_service.clone();
        // Block on the runtime and run async code
        rt.block_on(async {
            // Create tasks for each URL
            let mut tasks = vec![];

            nonce_groups.into_iter().for_each(|nonce| {
                let uri = format!(
                    "{}/job/{}/{}/{}/{}",
                    &k2p,
                    hex::encode(miner_id),
                    nonce,
                    hex::encode(challenge),
                    hex::encode(difficulty)
                );

                let task = tokio::spawn(async move {
                    let client = reqwest::Client::new();
                    let backoff = time::Duration::from_secs(BACKOFF_SECS);

                    loop {
                        let res = match client.get(&uri).send().await {
                            Ok(res) => res,
                            Err(err) => {
                                log::warn!("get job error: {}. backing off before retry", err);
                                thread::sleep(backoff); // need to change to tokio
                                continue;
                            }
                        };
                        let status = res.status();
                        let txt = res.text().await.unwrap(); // todo this should have a
                                                             // match
                        let res = match status {
                            reqwest::StatusCode::OK => Ok((nonce, txt.parse::<u64>().unwrap())),
                            reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
                                Err(Error::Internal(txt.into()))
                            }
                            reqwest::StatusCode::CREATED => {
                                thread::sleep(backoff); // tokio sleep
                                continue;
                            }
                            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                                thread::sleep(backoff); //tokio sleep
                                continue;
                            }
                            _ => Err(Error::Internal("unknown status code returned".into())),
                        };
                        return res;
                    }
                });
                tasks.push(task);
            });

            match future::join_all(tasks)
                .await
                .into_iter()
                .collect::<Result<Vec<Result<(u32, u64), Error>>, tokio::task::JoinError>>()
            {
                Ok(results) => results
                    .into_iter()
                    .collect::<Result<Vec<(u32, u64)>, Error>>(),
                Err(e) => Err(Error::Internal(e.into())),
            }
        })
    }

    fn par(&self) -> bool {
        true
    }
}
