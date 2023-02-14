use std::{env, fs, io::Read, process::exit, sync::mpsc, time::SystemTime};

fn main() {
    let mut args = env::args();
    args.next().unwrap();
    let path = args.next().expect("expected file as first arg");
    let mut f = fs::File::open(path).expect("file is not found");
    let size = f.metadata().unwrap().len();

    let mut stream = vec![0u8; size as usize];
    let challenge = b"3213123122dsadsa";
    let d = u64::MAX >> 28;
    let (tx, rx) = mpsc::channel();

    let start = SystemTime::now();
    match f.read(&mut stream) {
        Err(err) => {
            println!("reader failed {err}");
            exit(1);
        }
        Ok(size) => {
            println!("got data in {:?}", start.elapsed().unwrap());
            let start = SystemTime::now();
            post::prove(&stream, challenge, d, &tx);
            println!(
                "proving finished in {:?} for file of size {:?}",
                start.elapsed().unwrap(),
                size
            );
        }
    };
    drop(tx);
    while let Ok((nonce, index)) = rx.recv() {
        println!("nonce={nonce} index={index}");
    }
}
