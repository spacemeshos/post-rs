use crate::{create_thread_pool, PoW};
use post::pow::Prover;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum JobError {
    #[error("too many active jobs")]
    TooManyJobs,
}

#[cfg_attr(test, mockall::automock)]
pub trait GetOrCreate {
    fn get_or_create(&self, job: Job) -> Result<JobState, JobError>;
}
pub struct JobManager {
    jobs: Arc<Mutex<HashMap<Job, JobState>>>,
    cores: u8,
    randomx_mode: crate::RandomXMode,
    randomx_large_pages: bool,
}

impl JobManager {
    pub fn new(cores: u8, randomx_mode: crate::RandomXMode, randomx_large_pages: bool) -> Self {
        JobManager {
            jobs: Arc::new(Mutex::new(HashMap::new())),
            cores,
            randomx_mode,
            randomx_large_pages,
        }
    }
}

impl GetOrCreate for JobManager {
    fn get_or_create(&self, job: Job) -> Result<JobState, JobError> {
        let mut hs = self.jobs.lock().unwrap();
        match hs.get(&job) {
            Some(j) => Ok(j.clone()),
            None => {
                let other = hs.values().find(|v| matches!(v, JobState::InProgress));
                if other.is_some() {
                    return Err(JobError::TooManyJobs);
                }

                let mut randomx_flags = match self.randomx_mode {
                    crate::RandomXMode::Fast => {
                        post::pow::randomx::RandomXFlag::get_recommended_flags()
                            | post::pow::randomx::RandomXFlag::FLAG_FULL_MEM
                    }
                    crate::RandomXMode::Light => {
                        post::pow::randomx::RandomXFlag::get_recommended_flags()
                    }
                };
                if self.randomx_large_pages {
                    eprintln!("Using large pages for RandomX");
                    randomx_flags |= post::pow::randomx::RandomXFlag::FLAG_LARGE_PAGES;
                }

                eprintln!("RandomX flags: {}", randomx_flags);

                tracing::info!(
                    "took k2pow job: nonce group: {}, challenge: {}, difficulty: {}, miner {}",
                    job.nonce_group,
                    hex::encode(job.challenge),
                    hex::encode(job.difficulty),
                    hex::encode(job.miner)
                );
                let cores = match self.cores {
                    0 => crate::Cores::All,
                    v => crate::Cores::Any(v as usize),
                };
                let job_clone = job.clone();
                let jobs = self.jobs.clone();
                let _ = std::thread::spawn(move || {
                    let pool = create_thread_pool(cores, |_| {}).unwrap();
                    let result = pool.install(|| -> Result<u64, post::pow::Error> {
                        let pow = PoW::new(randomx_flags).unwrap();
                        tracing::debug!(
                    "proving k2pow: nonce group: {}, challenge: {}, difficulty: {}, miner {}",
                    job_clone.nonce_group,
                    hex::encode(job_clone.challenge),
                    hex::encode(job_clone.difficulty),
                    hex::encode(job_clone.miner)
                );
                        let res = pow.prove(
                            job_clone.nonce_group,
                            &job_clone.challenge,
                            &job_clone.difficulty,
                            &job_clone.miner,
                        )?;
                        tracing::debug!("k2pow result: {}", res);
                        Ok(res)
                    });

                    let mut hs = jobs.lock().unwrap();
                    let val = hs.get_mut(&job_clone).unwrap();
                    *val = JobState::Done(match result {
                        Ok(v) => Ok(v),
                        Err(e) => Err(e.to_string()),
                    });
                });

                hs.insert(job, JobState::InProgress);
                Ok(JobState::Created)
            }
        }
    }
}
/*

*/
#[derive(Clone, Debug, PartialEq)]
pub enum JobState {
    Created,
    InProgress,
    Done(Result<u64, String>),
}

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct Job {
    pub nonce_group: u8,
    pub challenge: [u8; 8],
    pub difficulty: [u8; 32],
    pub miner: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::{GetOrCreate, JobError, JobState};

    #[tokio::test]
    async fn test_job_manager() {
        let job_manager = super::JobManager::new(1, crate::RandomXMode::Light, false);
        let job = super::Job {
            nonce_group: 11,
            challenge: [1, 2, 3, 4, 5, 6, 7, 8],
            difficulty: [0xff; 32],
            miner: [
                1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4,
                5, 6, 7, 8,
            ],
        };
        assert_eq!(
            job_manager.get_or_create(job.clone()),
            Ok(JobState::Created)
        );
        // try to insert the same one twice
        assert_eq!(
            job_manager.get_or_create(job.clone()),
            Ok(JobState::InProgress)
        );

        // try to insert a new job but expect too many jobs
        let mut job2 = job.clone();
        job2.nonce_group = 14;
        assert_eq!(
            job_manager.get_or_create(job2.clone()),
            Err(JobError::TooManyJobs)
        );
        assert_eq!(
            job_manager.get_or_create(job.clone()),
            Ok(JobState::InProgress)
        );

        // loop until the calculation sets the correct result in the hashmap.
        // since the test difficulty is easy, this shouldn't take long.
        loop {
            match job_manager.get_or_create(job.clone()) {
                Ok(JobState::Done(Ok(_))) => break,
                Ok(JobState::Done(Err(_))) => panic!("shouldnt happen"),
                Ok(JobState::Created) => panic!("shouldnt happen"),
                Ok(JobState::InProgress) => {
                    std::thread::sleep(std::time::Duration::from_millis(50))
                }
                Err(_) => panic!(),
            }
        }
        // since the first job is now marked as errored, we can insert job 2
        assert_eq!(job_manager.get_or_create(job2), Ok(JobState::Created));
    }
}
