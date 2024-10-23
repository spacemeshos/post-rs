## Remote K2PoW service worker

This binary is tasked with the role of performing k2pow calculations necessary for PoST in the spacemesh protocol.

K2pow is expensive and is not required except for specific phases of the protocol, therefore, it is a good candidate
for being pulled out into an ephemeral environment that could predictibly be spun-up, used, then turned off (aka rented).

The workers are generally imagined to be used behind a pseudo-smart load-balancer that can try different workers for a single task.

On the post service side, one can throttle how many workers are intended to be tried simultaniously, and then k2pow can be done in parallel,
on different machine. This is controlled by the `parallelism` setting in the post service. E.g. if there are `10` workers and one post service,
one should set the parallelism setting to `10`. If there are multiple workers and multiple post services, use the relative amount (`workers/post services`).

The number of cores, randomx mode and randomx large pages settings are CPU and setup dependent.

Every worker supports having only _one_ job executing at the time. Queuing of future tasks is not possible at the moment. Requests are served therefore in a first-come-first-served manner.

### API

The service uses a simple HTTP API with the following endpoints:

#### Health endpoint

`GET /` - health endpoint, returns an `HTTP 200 OK` with a basic response

#### Job endpoint

`GET "/job/{miner}/{nonce_group}/{challenge}/{difficulty}"` - the main endpoint that provides the functionality in question, where

- `miner` is the miner id, `32` bytes encoded in hex (no preceding `0x` needed).
- `nonce_group` is the nonce group `uint8` as a regular string.
- `challenge` is the challenge, `8` bytes encoded in hex (no preceding `0x` needed).
- `difficulty` is the difficulty, `32` bytes encoded in hex (no preceding `0x` needed).

This endpoint may yield different responses depending on the state of the node:
- `HTTP 201 CREATED` - the job has been created and is processing (the first call and subsequent calls will yield the same status code)
- `HTTP 200 OK` - the job has been completed and the result is then encoded in the body as a `uint64` encoded as a string.
- `HTTP 500 INTERNAL SERVER ERROR` - the job had encountered an error. The error is written to the response as a string.
- `HTTP 429 TOO MANY REQUESTS` - the worker is busy and cannot accept the job at the moment. The client should backoff and retry later. It will be returned when worker is doing the job for OTHER than requested params (if params match and the job is still being processed it will return `201` as written above)

Note: the `miner` prefix is first in order to allow for flexibility in how to route requests within the load-balancer.

### Setup

While a single post service can use a single k2pow service as a processing backend, this is a rather specific use case where one uses one high-performance k2pow service machine with multiple post-services that are significantly less powerful. It's also worth noting that k2pow requires RandomX-optimized hardware, while the post-service requires AES-NI optimized hardware.

More advanced setup would interact through a load balancer. The load balancer should try sequencially to send the job between the different
workers, ideally sweeping through them until a vacant one is found. Once it sweeps through all of them, it should propagate the error back to
the post service. The post service knows to backoff and wait before trying again to send the job. The backoff period is also configurable.
The load balancer needs to remember which node was queried so that the same request can later scrape the result (instead of sending the job to a new node). One of the ways to "remember" it is using sharding based on the `miner` part of the URI.
The post service will keep requesting using the same endpoint always, this means that even in the case of a worker restart, the job can eventually get through.
The one caveat here is that if a worker is restarted, the load balancer behavior may be affected (it keeps forwarding the same GET request to the same worker, which is _not necessarily_ executing that job.

The individual k2pow workers have no persistence enabled.
Individual k2pow results are remembered and kept within the duration of a session, but not across sessions. This means that if they crashed/restarted no previous results would be remembered.

There is example configuration for HAProxy loab balancer in the [haproxy.cfg](./examples/haproxy/haproxy.cfg) with the [README.md](./examples/haproxy/README.md)
