use crate::{create_thread_pool, PoW};
use post::pow::Prover;
use std::collections::HashMap;
use std::sync::Mutex;
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
    InProgress(Option<std::thread::JoinHandle<Result<u64, post::pow::Error>>>),
    Done(Result<u64, String>),
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

struct Jobs {
    in_progress: Option<Job>,
    states: HashMap<Job, JobState>,
}
pub struct JobManager {
    jobs: Mutex<Jobs>,
    cores: u8,
    randomx_mode: crate::RandomXMode,
    randomx_large_pages: bool,
}

impl JobManager {
    pub fn new(cores: u8, randomx_mode: crate::RandomXMode, randomx_large_pages: bool) -> Self {
        JobManager {
            jobs: Mutex::new(Jobs {
                in_progress: None,
                states: HashMap::new(),
            }),
            cores,
            randomx_mode,
            randomx_large_pages,
        }
    }
    fn check_finished(&self) {
        let mut hs = self.jobs.lock().unwrap();
        if hs.in_progress.is_none() {
            return;
        }
        let job = hs.in_progress.as_ref().unwrap().clone();
        let entry = hs.states.get_mut(&job).unwrap();
        let result = if let JobState::InProgress(handle) = entry {
            if handle.as_ref().unwrap().is_finished() {
                let val = match handle.take().unwrap().join() {
                    Ok(result) => JobState::Done(match result {
                        Ok(v) => Ok(v),
                        Err(e) => Err(e.to_string()),
                    }),
                    Err(e) => std::panic::resume_unwind(e),
                };
                Some(val)
            } else {
                None
            }
        } else {
            None
        };
        drop(entry);
        if let Some(result) = result {
            let key = hs.in_progress.take().unwrap();
            hs.states.insert(key, result);
        }
    }
}

impl GetOrCreate for JobManager {
    fn get_or_create(&self, job: Job) -> Result<JobStatus, JobError> {
        self.check_finished();
        let mut hs = self.jobs.lock().unwrap();
        if let Some((in_prof, _)) = hs.in_progress {
            if job == in_prof {
                return Ok(JobStatus::InProgress);
            }
        }
        match hs.states.get(&job) {
            Some(JobState::InProgress(_)) => Ok(JobStatus::InProgress),
            Some(JobState::Done(result)) => Ok(JobStatus::Done(result.clone())),
            None => {
                if let Some(_) = hs.in_progress {
                    // if we're here it means:
                    // - there's a job in progress
                    // - it's not this job (covered by the first check after check_finished)
                    // - it's not done either (covered by the earlier match arm)
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

                hs.in_progress = Some((job, JobState::InProgress(handle)));
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
