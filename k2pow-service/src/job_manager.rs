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

/// JobStatus is used to expose job state to external callers
#[derive(Clone, Debug, PartialEq)]
pub enum JobStatus {
    Created,
    InProgress,
    Done(Result<u64, String>),
}

#[derive(Debug)]
enum JobState {
    InProgress(std::thread::JoinHandle<Result<u64, post::pow::Error>>),
    Done(Result<u64, String>),
}

impl std::convert::Into<JobStatus> for JobState {
    fn into(self) -> JobStatus {
        match self {
            JobState::InProgress(_) => JobStatus::InProgress,
            JobState::Done(result) => JobStatus::Done(result),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct Job {
    pub nonce_group: u8,
    pub challenge: [u8; 8],
    pub difficulty: [u8; 32],
    pub miner: [u8; 32],
}

#[cfg_attr(test, mockall::automock)]
pub trait GetOrCreate {
    fn get_or_create(&self, job: Job) -> Result<JobStatus, JobError>;
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
    fn check_finished(&self, job: &Job) {
        let mut hs = self.jobs.lock().unwrap();
        let entry = hs.remove_entry(job);
        match entry {
            Some((key, JobState::InProgress(handle))) => {
                if handle.is_finished() {
                    let val = match handle.join() {
                        Ok(result) => JobState::Done(match result {
                            Ok(v) => Ok(v),
                            Err(e) => Err(e.to_string()),
                        }),
                        Err(e) => std::panic::resume_unwind(e),
                    };
                    hs.insert(key, val);
                    return;
                }
                hs.insert(key, JobState::InProgress(handle));
            }
            Some((key, JobState::Done(res))) => {
                hs.insert(key, JobState::Done(res));
            }
            None => return,
        }
    }
}

impl GetOrCreate for JobManager {
    fn get_or_create(&self, job: Job) -> Result<JobStatus, JobError> {
        self.check_finished(&job);
        let mut hs = self.jobs.lock().unwrap();

        match hs.get(&job) {
            Some(JobState::InProgress(_)) => Ok(JobStatus::InProgress),
            Some(JobState::Done(result)) => Ok(JobStatus::Done(result.clone())),
            None => {
                let other = hs.values().find(|v| matches!(v, JobState::InProgress(_)));
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
                let handle = std::thread::spawn(move || {
                    let pool = create_thread_pool(cores, |_| {}).unwrap();
                    pool.install(|| -> Result<u64, post::pow::Error> {
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
                    })
                });

                hs.insert(job, JobState::InProgress(handle));
                Ok(JobStatus::Created)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GetOrCreate, JobError, JobStatus};

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

        match job_manager.get_or_create(job.clone()) {
            Ok(JobStatus::Created) => (),
            _ => panic!("shouldnt happen"),
        };
        // try to insert the same one twice
        match job_manager.get_or_create(job.clone()) {
            Ok(JobStatus::InProgress) => (),
            _ => panic!("shouldnt happen"),
        };

        // try to insert a new job but expect too many jobs
        let mut job2 = job.clone();
        job2.nonce_group = 14;
        match job_manager.get_or_create(job2.clone()) {
            Err(JobError::TooManyJobs) => (),
            _ => panic!("shouldnt happen"),
        };
        match job_manager.get_or_create(job.clone()) {
            Ok(JobStatus::InProgress) => (),
            _ => panic!("shouldnt happen"),
        };

        // loop until the calculation sets the correct result in the hashmap.
        // since the test difficulty is easy, this shouldn't take long.
        loop {
            match job_manager.get_or_create(job.clone()) {
                Ok(JobStatus::Done(Ok(_))) => break,
                Ok(JobStatus::Done(Err(_))) => panic!("shouldnt happen"),
                Ok(JobStatus::Created) => panic!("shouldnt happen"),
                Ok(JobStatus::InProgress) => {
                    std::thread::sleep(std::time::Duration::from_millis(50))
                }
                Err(_) => panic!(),
            }
        }
        // since the first job is now marked as errored, we can insert job 2
        match job_manager.get_or_create(job2) {
            Ok(JobStatus::Created) => (),
            _ => panic!("shouldnt happen"),
        }
    }
}
