const std = @import("std");
const shs = @import("./shs.zig");
const box = @import("./box.zig");
const rpc = @import("./rpc.zig");

const fs = std.fs;
const net = std.net;
const mem = std.mem;

const AutoHashMap = std.AutoHashMap;

const log = std.log.scoped(.ssb);

pub const Client = struct {
    conn: fs.File,
    boxed_conn: box.BoxedConnection,
    rpc_conn: rpc.RPCConnection(box.BoxedConnection),

    request_id: i32 = 1,
    allocator: *mem.Allocator,

    // callbacks return a bool indicating whether or not the values can be freed
    pub const Callback = fn (value: []const u8) bool;
    pub const StreamCallback = fn (value: []const u8, end: bool) bool;

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

    pub fn getRid(self: *Client) i32 {
        var val = self.request_id;
        self.request_id += 1;
        return val;
    }

    fn processResponse(self: *Client, rid: i32, cb: Callback) !void {
        while (try self.rpc_conn.readNextMessage()) |msg| {
            if (msg.header.req_num == -1 * rid) {
                var should_free = cb(msg.body);
                if (should_free) {
                    self.allocator.free(msg.body);
                }
                if (msg.header.flags.end_err) {
                    return;
                }
            } else {
                // discard everything but the stuff we want
                self.allocator.free(msg.body);
            }
        }
    }

    fn processStreamResponse(self: *Client, rid: i32, cb: StreamCallback) !void {
        while (try self.rpc_conn.readNextMessage()) |msg| {
            if (msg.header.req_num == -1 * rid) {
                if (msg.header.flags.end_err) {
                    // if this is the end of the line, say goodbye
                    try self.goodbye(msg);
                    return;
                }

                var should_free = cb(msg.body, msg.header.flags.end_err);
                if (should_free) {
                    self.allocator.free(msg.body);
                }
            } else {
                // discard everything but the stuff we want
                self.allocator.free(msg.body);
            }
        }
    }

    pub fn goodbye(self: *Client, original: ?rpc.Message) !void {
        const body = "true";

        if (original) |orig| {
            _ = try self.rpc_conn.writeMessage(rpc.Message{
                .header = rpc.Header{
                    .flags = .{
                        .stream = orig.header.flags.stream,
                        .end_err = true,
                        .body_type = rpc.Header.BodyType.JSON,
                    },
                    .body_len = body.len,
                    .req_num = -1 * orig.header.req_num,
                },
                .body = body[0..],
            });
        }
    }

    pub fn whoami(self: *Client, cb: Callback) !void {
        const body = "{\"name\":[\"whoami\"],\"type\":\"sync\",\"args\":[]}";
        const rid = self.getRid();

        _ = try self.rpc_conn.writeMessage(rpc.Message{
            .header = rpc.Header{
                .flags = .{
                    .stream = false,
                    .end_err = false,
                    .body_type = rpc.Header.BodyType.JSON,
                },
                .body_len = body.len,
                .req_num = rid,
            },
            .body = body[0..],
        });

        try self.processResponse(rid, cb);
    }

    pub const HistoryStreamArgs = struct {
        id: [53]u8,
        seq: u32 = 0,
        live: bool = false,
    };

    pub fn createHistoryStream(self: *Client, args: HistoryStreamArgs, cb: StreamCallback) !void {
        const body_head = "{\"name\":[\"createHistoryStream\"],\"type\":\"source\",\"args\":[";
        const body_tail = "]}";

        var body = std.ArrayList(u8).init(self.allocator);
        defer body.deinit();

        var writer = body.writer();
        try writer.writeAll(body_head[0..]);
        try std.json.stringify(args, .{}, writer);
        try writer.writeAll(body_tail[0..]);

        const rid = self.getRid();

        _ = try self.rpc_conn.writeMessage(rpc.Message{
            .header = rpc.Header{
                .flags = .{
                    .stream = true,
                    .end_err = false,
                    .body_type = rpc.Header.BodyType.JSON,
                },
                .body_len = body.items.len,
                .req_num = rid,
            },
            .body = body.items,
        });

        try self.processStreamResponse(rid, cb);
    }
};
