# Post Service
Post service allows to separate expensive PoST proving from a node by allowing to generate a proof on a different machine. It connects to the node via GRPC (on an address pointed by `--address`) and awaits commands from the node.

## How to run
First of all, the service currently doesn't support initializing PoST data. The data must be initialized separately (presumably using [postcli](https://github.com/spacemeshos/post/tree/develop/cmd/postcli) and placed in a directory pointed to by `--dir`).

#### Example running on an un-encrypted channel, with the default configuration of _threads_ and _nonces_
```sh
service --address=http://my-node-address.org --dir=./post-data
```

#### Example running on an encrypted (mTLS) channel, with the custom  _threads_ and _nonces_
For mTLS, you need to pass the certificate and private key of the post-service with `--cert` and `-key`, as well as the CA of the server with `--ca-cert`:
```sh
service --address=https://my-node-address.org --cert=client.pem --key=client-key.pem --ca-cert=server-rootCA.pem --dir=./post-data --threads=8 --nonces=288
```

A full usage/help can be viewed with
```sh
service --help
```

## Operator API
The operator API is a set of GRPC endpoints allowing control of the post service.

The GRPC API supports reflection for easy use with tools like [grpcurl](https://github.com/fullstorydev/grpcurl).

It is enabled by providing `--operator-address=<address>`, i.e. `--operator-address=127.0.0.1:50051` CLI argument.

### Example usage
#### Querying post service status
```sh
❯ grpcurl -plaintext  localhost:50051  spacemesh.v1.PostServiceOperator/Status
{
  "status": "IDLE"
}
```