# Example Load Balancer Configuration for k2pow-service

This readme demonstrates the example Load Balancer configuration for the k2pow service.

Using this or a similar approach, one can:

* Use multiple workers for a k2pow-service to process multiple k2pow operations simultaneously.
* Utilize multiple machines to do so and hide them behind a single address.

This example uses HAProxy as a load balancer, but any other load balancer can be used.

The example configuration file is in `haproxy.cfg`.

The configuration file is set up to use 3 workers, but this can be adjusted by changing the `server` lines in the
`backend k2pow` section.

Theoretically, you can run that HAProxy config in a Docker container with the following command:

```bash
docker run --net host -d --name my-running-haproxy -v `pwd`/hpx:/usr/local/etc/haproxy haproxy:3.0
```

However, you will NOT be able to hot reload the HAProxy process while keeping the sticky information. Therefore, it is
recommended NOT to run it as a Docker container in production (or at least not as that simple container from above).

## Config explanation

The main aspect that requires explanation is the sticky part.
Given that the jobs are sent to the k2pow service as `GET "/job/{miner}/{nonce_group}/{challenge}/{difficulty}"`, we
configure `acl uri_parts path_reg ^/job/([^/]+)/([^/]+)` so we can set the sticky session to the miner and nonce_group
part of the URL.

Then, thanks to `retry-on 429 503 response-timeout conn-failure`, we keep retrying on normal errors AND 429, which is
by default sent by the k2pow service when it's already calculating a proof. This way, HAProxy will retry the request to
another server for up to `retries 4`. In the end, because of `hash-type consistent`, HAProxy will remember which server
was used for the given miner and nonce_group and will always send the request to the same server.
