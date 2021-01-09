# sbotz

a simplistic secure-scuttlebot client written in Zig

## use
1. install Zig (at time of writing, only works with master version of Zig)
1. clone repo `git clone https://github.com/stripedpajamas/sbotz.git && cd sbotz`
1. run the example: `zig run src/example.zig`. the example tries to connect to local ssb-server and calls `createLogStream`

the `src/example.zig` file shows how the client library could be used.

i don't really know how `build.zig` files work yet so there isn't one.

## what is it
i mostly just tried to implement what [the protocol guide](https://ssbc.github.io/scuttlebutt-protocol-guide) says.

- `shs.zig` implements the handshake / session key generation logic
- `box.zig` uses the SHS module to run the handshake and then wraps some reader/writer (e.g. socket)'s read/write methods with boxed versions
- `rpc.zig` wraps some reader/writer with the RPC stuff
- `client.zig` takes in a reader/writer (socket), uses box to orchestrate the handshake, and exposes `call` to make ssb calls to the other end (e.g. `whoami`, `createHistoryStream`, etc.)
- `keys.zig` a small helper library to load up local keys from `~/.ssb/secret`

## license
GPLv3

