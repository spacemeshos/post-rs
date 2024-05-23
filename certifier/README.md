# POST certifier service
A certifier service that creates certificates for a node confirming it holds a valid POST proof.

The client (presumably the spacemesh node) submits a POST proof with its metadata to the certifier on /certify HTTP endpoint. The certifier validates the proof and, if valid - signs the nodeID and returns the signature. If the proof is invalid it returns a 403 status code.

The client can later use this certificate to register in a poet. The poet is supposed to know the certifier's public key and verify the signature over a node ID.

## Usage
```
Usage: certifier [OPTIONS] [COMMAND]

Commands:
  generate-keys  generate keypair and write it to standard out. the keypair is encoded as json
  help           Print this message or the help of the given subcommand(s)

Options:
  -c, --config <CONFIG>  [env: CERTIFIER_CONFIG_PATH=] [default: config.yml]
  -h, --help             Print help
  -V, --version          Print version
```

### running a service
To run a service, execute the certifier w/o additional command and provide a path to config (either via --config or CERTIFIER_CONFIG_PATH env variable).

#### Configuration
The config structure is defined [here](src/configuration.rs). An example config:

```yaml
listen: "127.0.0.1:8080"
signing_key: <BASE64-encoded ed25519 private key>
certificate_expiration: 2w
post_cfg:
  k1: 26
  k2: 37
  pow_difficulty: "000dfb23b0979b4b000000000000000000000000000000000000000000000000"

init_cfg:
  min_num_units: 4
  max_num_units: 99999
  labels_per_unit: 4294967296
  scrypt:
    n: 8192
    r: 1
    p: 1

metrics: "127.0.0.1:9090"
randomx_mode: Fast

limits:
  # How many requests can be processed in parallel.
  # As PoST verification is CPU-bound, it defaults to the number of CPUs.
  max_concurrent_requests: 4
  # How many requests can be queued, waiting to be processed.
  max_pending_requests: 1000
  # Maximum size of request body (the proof JSON)
  max_body_size: 1024
```

Each field can also be provided as env variable prefixed with CERTIFIER. For example, `CERTIFIER_SIGNING_KEY`.

##### Expiring certificates
The certificates don't expire by default. To create certificates that expire after certain time duration,
set `certificate_expiration` field in the config. It understands units supported by the [duration_str](https://docs.rs/duration-str/0.7.1/duration_str/index.html) crate (i.e "1d", "2w").

##### Concurrency limit
It's important to configure the maximum number of requests that will be processed in parallel.
The POST verification is heavy on CPU and hence a value higher than the number of CPU cores might lead to drop in performance and increase latency.
It will use the number of available CPU cores if not set.

##### RandomX mode
Randomx is used for K2 PoW verification. There are two modes:
- `Fast`: uses about 2080MiB memory, runs fast
- `Light` (default): uses about 256MiB memory, but runs significantly slower (about x10 slower)

The modes give the same results, they differ in speed and memory consumption only.

#### Docker
There is a docker image created to simplify deployment: `spacemeshos/certifier-service`.

### Generating keys
Run `certifier generate-keys` to obtain randomly generated new keys.
```sh
❯ certifier generate-keys
{
  "public_key": "N2QnP1E3QmrPIjHt8QPvQXThNjDVKfatr0ncttXn7+Q=",
  "secret_key": "DoU0xoVZ1gf/FDvz4K9PldiYCCeiFPhQmWbHd+X6Yjo="
}
```

## Log level
The log level can be controlled via `RUST_LOG` enviroment variable. It can be set to [error, warn, info, debug, trace, off].
