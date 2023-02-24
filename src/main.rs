use std::{fs, io::Read, process::exit, sync::mpsc, time::SystemTime};

fn main() {
    let mut f = fs::File::open("/dev/random").expect("can't read from /dev/random");
    let gb = 1;
    let mut stream = vec![0u8; gb << 30];
    let challenge = b"3213123122dsadsa";
    let mut prover = post::Prover::<1>::new(challenge, u64::MAX >> 28);
    let (tx, rx) = mpsc::channel();

    for _ in 0..10 {
        let start = SystemTime::now();
        match f.read_exact(&mut stream) {
            Err(err) => {
                println!("reader failed {err}");
                exit(1);
            }
            Ok(()) => {
                println!("got data in {:?}", start.elapsed().unwrap());
                let start = SystemTime::now();
                prover.prove(&stream, |nonce, index| {
                    match tx.send((nonce, index)) {
                        Ok(()) => Ok(()),
                        Err(_) => Err(()),
                    }
                });
                println!(
                    "proving finished in {:?} for file of size {:?}. estimated throughput {:?} GB/s",
                    start.elapsed().unwrap(),
                    stream.len(),
                    gb as f64 * (1000 as f64 / start.elapsed().unwrap().as_millis() as f64),
                );
            }
        };
    }
    drop(tx);
    while let Ok((nonce, index)) = rx.recv() {
        println!("nonce={nonce} index={index}");
    }
}
