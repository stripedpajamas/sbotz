const std = @import("std");
const shs = @import("./shs.zig");
const box = @import("./box.zig");
const rpc = @import("./rpc.zig");

const fs = std.fs;
const net = std.net;
const mem = std.mem;

pub const Client = struct {
    conn: fs.File,
    boxed_conn: box.BoxedConnection,
    rpc_conn: rpc.RPCConnection(box.BoxedConnection),

    allocator: *mem.Allocator,

    pub fn init(allocator: *mem.Allocator, opts: shs.HandshakeOptions) !Client {
        var server_addr = try net.Address.parseIp4("127.0.0.1", 8008);
        var conn = try net.tcpConnectToAddress(server_addr);

        var boxed_conn = try box.BoxedConnection.init(opts, conn);

        var rpc_conn = rpc.RPCConnection(box.BoxedConnection).init(allocator, &boxed_conn);

        return Client{
            .allocator = allocator,
            .conn = conn,
            .boxed_conn = boxed_conn,
            .rpc_conn = rpc_conn,
        };
    }

    pub fn deinit(self: *Client) void {
        // TODO send goodbye
        self.conn.close();
    }

    // sends whoami request to ssb server, allocates for response
    pub fn whoami(self: *Client) ![]const u8 {
        const body = "{\"name\":[\"whoami\"],\"type\":\"sync\",\"args\":[]}";
        _ = try self.rpc_conn.writeMessage(rpc.Message{
            .header = rpc.Header{
                .flags = .{
                    .stream = false,
                    .end_err = false,
                    .body_type = rpc.Header.BodyType.JSON,
                },
                .body_len = body.len,
                .req_num = 1,
            },
            .body = body[0..],
        });

        if (try self.rpc_conn.readNextMessage()) |msg| {
            return msg.body;
        } else {
            return error.NoResponse;
        }
    }
};
