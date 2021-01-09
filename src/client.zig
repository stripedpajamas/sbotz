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

    // callback returns a bool indicating whether or not the values can be freed
    pub const Callback = fn (value: []const u8, end_err: bool) bool;

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
        self.rpc_conn.goodbye() catch |err| {
            log.err("failed to cleanly close rpc connection: {}", .{err});
        };

        self.boxed_conn.goodbye() catch |err| {
            log.err("failed to cleanly close box connection: {}", .{err});
        };

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
                var should_free = cb(msg.body, msg.header.flags.end_err);
                if (should_free) {
                    self.allocator.free(msg.body);
                }

                if (msg.header.flags.end_err) {
                    // if this is the end of the line, say goodbye
                    try self.goodbye(msg);
                    break;
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

    pub fn call(self: *Client, name: []const []const u8, msg_type: MessageType, args: anytype, cb: Callback) !void {
        const rid = self.getRid();

        var body = try createMessageBody(self.allocator, name, msg_type, args);
        defer self.allocator.free(body);

        _ = try self.rpc_conn.writeMessage(rpc.Message{
            .header = rpc.Header{
                .flags = .{
                    .stream = msg_type == MessageType.source,
                },
                .body_len = body.len,
                .req_num = rid,
            },
            .body = body,
        });

        try self.processResponse(rid, cb);
    }
};

pub const MessageType = enum {
    source,
    sync,
    // async, // TODO how tf to do this kind

    pub fn jsonStringify(value: MessageType, opts: std.json.StringifyOptions, out_stream: anytype) !void {
        try out_stream.writeByte('"');
        try out_stream.writeAll(@tagName(value));
        try out_stream.writeByte('"');
    }
};

pub fn Message(comptime args_type: type) type {
    return struct {
        name: []const []const u8,
        type: MessageType,
        args: [1]args_type,

        const Self = @This();

        pub fn init(name: []const []const u8, msg_type: MessageType, args: args_type) Self {
            return Self{
                .name = name,
                .type = msg_type,
                .args = [_]args_type{args},
            };
        }
    };
}

// caller owns returned string
fn createMessageBody(allocator: *mem.Allocator, name: []const []const u8, msg_type: MessageType, args: anytype) ![]u8 {
    var msg = Message(@TypeOf(args)).init(name, msg_type, args);
    var body = std.ArrayList(u8).init(allocator);
    errdefer body.deinit();

    try std.json.stringify(msg, .{}, body.writer());

    return body.toOwnedSlice();
}
