use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

pub struct JobManager {
    jobs: Mutex<HashMap<Job, JobState>>,
}

#[derive(Error, Debug, PartialEq)]
pub enum JobError {
    #[error("job not found")]
    JobNotFound,

    #[error("too many active jobs")]
    TooManyJobs,
}

#[cfg_attr(test, mockall::automock)]
pub trait GetOrCreate: Send + Sync + 'static {
    fn get_or_create(
        &self,
        job: Job,
    ) -> impl std::future::Future<Output = Result<JobState, JobError>> + Send;
}

impl GetOrCreate for JobManager {
    async fn get_or_create(&self, job: Job) -> Result<JobState, JobError> {
        let mut hs = self.jobs.lock().await;
        match hs.get(&job).cloned() {
            Some(j) => Ok(j),
            None => {
                let other = hs
                    .values()
                    .find(|v| matches!(v, JobState::Created | JobState::InProgress));
                if other.is_some() {
                    return Err(JobError::TooManyJobs);
                }
                hs.insert(job, JobState::Created);
                Ok(JobState::Created)
            }
        }
    }
}

impl JobManager {
    pub fn new() -> Self {
        JobManager {
            jobs: Mutex::new(HashMap::new()),
        }
    }

    pub async fn take(&self) -> Option<Job> {
        let mut hs = self.jobs.lock().await;
        for (k, v) in hs.iter_mut() {
            if let JobState::Created = *v {
                *v = JobState::InProgress;
                return Some(k.clone());
            }
        }
        None
    }

    pub async fn update(&self, job: Job, state: JobState) -> Result<(), JobError> {
        let mut hs = self.jobs.lock().await;
        match hs.entry(job) {
            Entry::Occupied(mut e) => {
                *e.get_mut() = state;
                Ok(())
            }
            Entry::Vacant(_) => Err(JobError::JobNotFound),
        }
    }
}

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
        let job_manager = super::JobManager::new();
        let job = super::Job {
            nonce_group: 11,
            challenge: [1, 2, 3, 4, 5, 6, 7, 8],
            difficulty: [
                1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4,
                5, 6, 7, 8,
            ],
            miner: [
                1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4,
                5, 6, 7, 8,
            ],
        };
        assert_eq!(job_manager.take().await, None);
        assert_eq!(
            job_manager.get_or_create(job.clone()).await,
            Ok(JobState::Created)
        );
        // try to insert the same one twice
        assert_eq!(
            job_manager.get_or_create(job.clone()).await,
            Ok(JobState::Created)
        );

        // try to insert a new job but expect too many jobs
        let mut job2 = job.clone();
        job2.nonce_group = 14;
        assert_eq!(
            job_manager.get_or_create(job2.clone()).await,
            Err(JobError::TooManyJobs)
        );
        assert_eq!(
            job_manager.get_or_create(job.clone()).await,
            Ok(JobState::Created)
        );
        assert_eq!(job_manager.take().await, Some(job.clone()));
        // expect take() to mutate the job state to be in progress
        assert_eq!(
            job_manager.get_or_create(job.clone()).await,
            Ok(JobState::InProgress)
        );
        let err = Err("abcd".into());
        assert_eq!(
            job_manager
                .update(job.clone(), JobState::Done(err.clone()))
                .await,
            Ok(())
        );
        assert_eq!(
            job_manager.get_or_create(job.clone()).await,
            Ok(JobState::Done(err))
        );

        // since the first job is now marked as errored, we can insert job 2
        assert_eq!(job_manager.get_or_create(job2).await, Ok(JobState::Created));
    }
}
