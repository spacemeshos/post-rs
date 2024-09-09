use crate::job_manager::{GetOrCreate, JobManager};
use axum::extract::Path;
use axum::response::IntoResponse;
use axum::routing::{get, Router};
use axum::{
    extract::State,
    http::{Request, StatusCode},
    response::Response,
};
use clap::{arg, Parser, ValueEnum};
use post::config::Cores;
use post::pow::randomx::PoW;
use post::pow::Prover;
use post::prove::create_thread_pool;
use serde::Deserialize;
use serde_with::serde_as;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tower_http::{classify::ServerErrorsFailureClass, trace::TraceLayer};
use tracing::{info_span, Span};
use tracing_log::LogTracer;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

mod job_manager;
use job_manager::{JobError, JobState};

const POLL_EVERY_SECS: u64 = 1;

#[derive(Parser, Debug)]
#[command(version)]
struct Cli {
    /// the address to listen to http job requests on.
    #[arg(short, long, default_value = "0.0.0.0:3000")]
    bind_address: String,

    /// the number of cores to use. the optimal value depends
    /// on the type of CPU used. `0` means use all cores.
    #[arg(long, default_value = "0")]
    cores: u8,

    #[arg(long, default_value_t = RandomXMode::Fast)]
    randomx_mode: RandomXMode,

    /// allocate RandomX memory in large pages.
    #[arg(long, default_value = "false")]
    randomx_large_pages: bool,
}

/// RandomX modes of operation
///
/// They are interchangeable as they give the same results but have different
/// purpose and memory requirements.
#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum, serde::Serialize)]
enum RandomXMode {
    /// Fast mode for proving. Requires 2080 MiB of memory.
    Fast,
    /// Light mode for verification. Requires only 256 MiB of memory, but runs significantly slower
    Light,
}

impl std::fmt::Display for RandomXMode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RandomXMode::Fast => write!(f, "fast"),
            RandomXMode::Light => write!(f, "light"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    LogTracer::init()?;
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("INFO"));
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let job_manager = Arc::new(job_manager::JobManager::new());
    _ = tokio::task::spawn(consume(
        job_manager.clone(),
        args.cores,
        args.randomx_mode,
        args.randomx_large_pages,
    ));
    let router = router(job_manager);
    tracing::info!(
        "starting http server with bind address: {}",
        args.bind_address
    );
    let listener = tokio::net::TcpListener::bind(args.bind_address)
        .await
        .unwrap();
    axum::serve(listener, router).await.unwrap();

    Ok(())
}

fn router<T: GetOrCreate>(job_manager: Arc<T>) -> Router {
    Router::new()
        .route("/", get(root))
        .route(
            "/job/:miner/:nonce_group/:challenge/:difficulty",
            get(get_job),
        )
        .with_state(job_manager)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    let matched_path = request.uri().to_string();

                    info_span!(
                        "http_request",
                        method = ?request.method(),
                        uri =  matched_path,
                        status = tracing::field::Empty,
                    )
                })
                .on_response(|response: &Response, _latency: Duration, span: &Span| {
                    span.record("status", response.status().as_str());
                    tracing::info!("served request");
                })
                .on_failure(
                    |error: ServerErrorsFailureClass, _latency: Duration, span: &Span| {
                        match error {
                            ServerErrorsFailureClass::StatusCode(code) => {
                                span.record("status", code.as_str());
                            }
                            ServerErrorsFailureClass::Error(err) => {
                                span.record("error", &err);
                            }
                        }
                        tracing::error!("request fail");
                    },
                ),
        )
}
async fn consume(
    job_manager: Arc<JobManager>,
    cores: u8,
    randomx_mode: RandomXMode,
    randomx_large_pages: bool,
) {
    let mut randomx_flags = match randomx_mode {
        RandomXMode::Fast => {
            post::pow::randomx::RandomXFlag::get_recommended_flags()
                | post::pow::randomx::RandomXFlag::FLAG_FULL_MEM
        }
        RandomXMode::Light => post::pow::randomx::RandomXFlag::get_recommended_flags(),
    };
    if randomx_large_pages {
        eprintln!("Using large pages for RandomX");
        randomx_flags |= post::pow::randomx::RandomXFlag::FLAG_LARGE_PAGES;
    }
    eprintln!("RandomX flags: {}", randomx_flags);

    loop {
        sleep(Duration::from_secs(POLL_EVERY_SECS)).await;
        let job = match job_manager.take().await {
            None => continue,
            Some(v) => v,
        };
        tracing::info!(
            "took k2pow job: nonce group: {}, challenge: {}, difficulty: {}, miner {}",
            job.nonce_group,
            hex::encode(job.challenge),
            hex::encode(job.difficulty),
            hex::encode(job.miner)
        );
        let cores = match cores {
            0 => Cores::All,
            v => Cores::Any(v as usize),
        };
        let handle = tokio::task::spawn_blocking(move || -> Result<u64, post::pow::Error> {
            let pool = create_thread_pool(cores, |_| {}).unwrap();
            pool.install(|| -> Result<u64, post::pow::Error> {
                let pow = PoW::new(randomx_flags).unwrap();
                tracing::debug!(
                    "proving k2pow: nonce group: {}, challenge: {}, difficulty: {}, miner {}",
                    job.nonce_group,
                    hex::encode(job.challenge),
                    hex::encode(job.difficulty),
                    hex::encode(job.miner)
                );
                let res =
                    pow.prove(job.nonce_group, &job.challenge, &job.difficulty, &job.miner)?;
                tracing::debug!("k2pow result: {}", res);
                Ok(res)
            })
        })
        .await;

        let done = match handle.unwrap() {
            Ok(ok) => Ok(ok),
            Err(e) => Err(e.to_string()),
        };
        if let Err(e) = job_manager.update(job, JobState::Done(done)).await {
            tracing::error!("failed updating job with result: {:?}", e);
        }
    }
}

const ROOT_RESPONSE: &str = "{ 'message': 'ok' }";
async fn root() -> impl IntoResponse {
    ROOT_RESPONSE
}

#[serde_as]
#[derive(Deserialize)]
struct HexStr<const COUNT: usize>(#[serde_as(as = "serde_with::hex::Hex")] [u8; COUNT]);

impl<const COUNT: usize> HexStr<COUNT> {
    fn array(self) -> [u8; COUNT] {
        self.0
    }
}

async fn get_job<T: GetOrCreate>(
    State(manager): State<Arc<T>>,
    Path((miner, nonce_group, challenge, difficulty)): Path<(
        HexStr<32>,
        u8,
        HexStr<8>,
        HexStr<32>,
    )>,
) -> Result<job_manager::JobState, job_manager::JobError> {
    manager
        .get_or_create(job_manager::Job {
            nonce_group,
            challenge: challenge.array(),
            difficulty: difficulty.array(),
            miner: miner.array(),
        })
        .await
}

impl IntoResponse for job_manager::JobError {
    fn into_response(self) -> Response {
        match self {
            JobError::JobNotFound => (StatusCode::NOT_FOUND, "").into_response(),
            JobError::TooManyJobs => (StatusCode::TOO_MANY_REQUESTS, "").into_response(),
        }
    }
}

impl IntoResponse for job_manager::JobState {
    fn into_response(self) -> Response {
        match self {
            JobState::Created => (StatusCode::CREATED, "").into_response(),
            JobState::InProgress => (StatusCode::CREATED, "").into_response(),
            JobState::Done(Ok(res)) => (StatusCode::OK, format!("{res}")).into_response(),
            JobState::Done(Err(err)) => {
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::job_manager::Job;
    use super::router;
    use crate::job_manager;
    use axum_test::TestServer;
    use mockall::predicate::eq;
    use std::sync::Arc;
    const JOB: Job = Job {
        nonce_group: 11,
        challenge: [1, 2, 3, 4, 5, 6, 7, 8],
        difficulty: [
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
            6, 7, 8,
        ],
        miner: [
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5,
            6, 7, 8,
        ],
    };

    #[tokio::test]
    async fn test_root() {
        let mut mock_manager = job_manager::MockGetOrCreate::new();
        mock_manager.expect_get_or_create().times(0);
        let job_manager = job_manager::JobManager::new();
        let router = router(Arc::new(job_manager));
        let server = TestServer::new(router).unwrap();
        let response = server.get("/").await;
        assert_eq!(response.text(), super::ROOT_RESPONSE);
    }

    #[tokio::test]
    async fn test_get_job_created() {
        let (nonce_group, challenge, difficulty, miner) = (
            JOB.nonce_group,
            hex::encode(JOB.challenge),
            hex::encode(JOB.difficulty),
            hex::encode(JOB.miner),
        );
        let mut mock_manager = job_manager::MockGetOrCreate::new();
        mock_manager
            .expect_get_or_create()
            .with(eq(JOB))
            .times(2)
            .returning(|_| Box::pin(std::future::ready(Ok(job_manager::JobState::Created))));
        let router = router(Arc::new(mock_manager));
        let server = TestServer::new(router).unwrap();
        let url = format!("/job/{miner}/{nonce_group}/{challenge}/{difficulty}");
        let response = server.get(&url).await;
        assert_eq!(response.status_code(), axum::http::StatusCode::CREATED);

        // requesting the same is idempotent
        let response = server.get(&url).await;
        assert_eq!(response.status_code(), axum::http::StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_get_job_done() {
        let (nonce_group, challenge, difficulty, miner) = (
            JOB.nonce_group,
            hex::encode(JOB.challenge),
            hex::encode(JOB.difficulty),
            hex::encode(JOB.miner),
        );
        const RESULT: u64 = 1111;

        let mut mock_manager = job_manager::MockGetOrCreate::new();
        mock_manager
            .expect_get_or_create()
            .with(eq(JOB))
            .times(1)
            .returning(|_| {
                Box::pin(std::future::ready(Ok(job_manager::JobState::Done(Ok(
                    RESULT,
                )))))
            });
        let router = router(Arc::new(mock_manager));
        let server = TestServer::new(router).unwrap();
        let url = format!("/job/{miner}/{nonce_group}/{challenge}/{difficulty}");
        let response = server.get(&url).await;
        assert_eq!(response.status_code(), axum::http::StatusCode::OK);
        assert_eq!(response.text(), format!("{RESULT}"));
    }

    #[tokio::test]
    async fn test_get_job_error() {
        let (nonce_group, challenge, difficulty, miner) = (
            JOB.nonce_group,
            hex::encode(JOB.challenge),
            hex::encode(JOB.difficulty),
            hex::encode(JOB.miner),
        );
        let err = String::from("error message");

        let mut mock_manager = job_manager::MockGetOrCreate::new();
        mock_manager
            .expect_get_or_create()
            .with(eq(JOB))
            .times(1)
            .returning(move |_| {
                Box::pin(std::future::ready(Ok(job_manager::JobState::Done(Err(
                    String::from("error message"),
                )))))
            });
        let router = router(Arc::new(mock_manager));
        let server = TestServer::new(router).unwrap();
        let url = format!("/job/{miner}/{nonce_group}/{challenge}/{difficulty}");
        let response = server.get(&url).await;
        assert_eq!(
            response.status_code(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(response.text(), format!("{err}"));
    }
}
