# sbotz

a simplistic secure-scuttlebot client written in Zig

## use
1. install Zig (at time of writing, only works with master version of Zig)
1. clone repo `git clone https://github.com/stripedpajamas/sbotz.git && cd sbotz`
1. run the example: `zig run src/example.zig`. the example tries to connect to local ssb-server and calls `createLogStream`

the `src/example.zig` file shows how the client library could be used.

i don't really know how `build.zig` files work yet so there isn't one.

## license
GPLv3

