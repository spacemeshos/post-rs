use super::{Error, Prover};
use futures::future;
use reqwest;
use std::ops::Range;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::Semaphore;
use tokio::time::sleep;

pub struct K2powService {
    k2pow_service: String,
    semaphore: Arc<Semaphore>,
    backoff: Duration,
}

impl K2powService {
    pub fn new(k2pow_service: String, parallelism: usize, backoff: Duration) -> Self {
        let semaphore = Arc::new(Semaphore::new(parallelism));
        Self {
            k2pow_service,
            semaphore,
            backoff,
        }
    }
}

impl Prover for K2powService {
    fn prove(&self, _: u8, _: &[u8; 8], _: &[u8; 32], _: &[u8; 32]) -> Result<u64, Error> {
        panic!("not implemented");
    }

    fn prove_many(
        &self,
        nonce_groups: Range<u32>,
        challenge: &[u8; 8],
        difficulty: &[u8; 32],
        miner_id: &[u8; 32],
    ) -> Result<Vec<(u32, u64)>, Error> {
        let rt = Runtime::new().unwrap();
        let k2p = self.k2pow_service.clone();
        rt.block_on(async {
            let mut tasks = vec![];
            let backoff = self.backoff;
            nonce_groups.into_iter().for_each(|nonce| {
                let uri = format!(
                    "{}/job/{}/{}/{}/{}",
                    &k2p,
                    hex::encode(miner_id),
                    nonce,
                    hex::encode(challenge),
                    hex::encode(difficulty)
                );
                let semaphore = self.semaphore.clone();

                let task = async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let client = reqwest::Client::new();

                    loop {
                        let res = match client.get(&uri).send().await {
                            Ok(res) => res,
                            Err(err) => {
                                log::warn!("get job error: {}. backing off before retry", err);
                                sleep(backoff).await;
                                continue;
                            }
                        };
                        let status = res.status();
                        let txt = match res.text().await {
                            Ok(text) => text,
                            Err(err) => {
                                log::warn!(
                                    "read response error: {}. backing off before retry",
                                    err
                                );
                                sleep(backoff).await;
                                continue;
                            }
                        };

                        let res = match status {
                            reqwest::StatusCode::OK => Ok((nonce, txt.parse::<u64>().unwrap())),
                            reqwest::StatusCode::INTERNAL_SERVER_ERROR => {
                                Err(Error::Internal(txt.into()))
                            }
                            reqwest::StatusCode::CREATED => {
                                sleep(backoff).await;
                                continue;
                            }
                            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                                sleep(backoff).await;
                                continue;
                            }
                            _ => Err(Error::Internal("unknown status code returned".into())),
                        };
                        return res;
                    }
                };
                tasks.push(task);
            });

            future::join_all(tasks)
                .await
                .into_iter()
                .collect::<Result<Vec<(u32, u64)>, Error>>()
        })
    }

    fn par(&self) -> bool {
        true
    }
}
