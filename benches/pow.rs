use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};

use pprof::criterion::{Output, PProfProfiler};
use scrypt_jane::scrypt::ScryptParams;

const CHALLENGE: &[u8; 32] = b"hello world, CHALLENGE me!!!!!!!";

fn bench_k2_pow(c: &mut Criterion) {
    c.bench_function("k2_pow", |b| {
        b.iter(|| {
            post::pow::find_k2_pow(
                CHALLENGE,
                0,
                ScryptParams::new(8, 0, 0),
                black_box(0x0FFFFFFF_FFFFFFFF),
            )
        })
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(1000, Output::Flamegraph(None)));
    targets=bench_k2_pow
);

criterion_main!(benches);
