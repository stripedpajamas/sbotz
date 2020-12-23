const std = @import("std");
const box = @import("./box.zig");
const shs = @import("./shs.zig");

const fs = std.fs;
const mem = std.mem;
const crypto = std.crypto;

const log = std.log.scoped(.rpc_codec);

const BoxedConnection = box.BoxedConnection;

pub const RPCConnection = struct {
    boxed_conn: BoxedConnection,

    pub const header_size: usize = 9;

    pub const BodyType = enum {
        Binary,
        String,
        JSON,
    };

    pub const Flags = struct {
        stream: bool,
        end_err: bool,
        body_type: BodyType,
    };

    pub fn init(opts: shs.HandshakeOptions, conn: fs.File, remote_pk: [32]u8) !RPCConnection {
        var boxed_conn = try BoxedConnection.init(opts, conn, remote_pk);

        return RPCConnection{
            .boxed_conn = boxed_conn,
        };
    }

    pub fn write(self: *RPCConnection, payload: []const u8) !void {
        try self.boxed_conn.write(payload);
    }

    // adds the rpc header to the cmd payload
    pub fn encode(allocator: *mem.Allocator, cmd: []const u8, req_num: i32, flags: Flags) ![]const u8 {
        var out = try allocator.alloc(u8, cmd.len + RPCConnection.header_size);
        var flag_byte: u8 = 0;
        if (flags.stream) {
            flag_byte |= 0b1000;
        }
        if (flags.end_err) {
            flag_byte |= 0b0100;
        }
        switch (flags.body_type) {
            BodyType.String => {
                flag_byte |= 0b0001;
            },
            BodyType.JSON => {
                flag_byte |= 0b0010;
            },
            BodyType.Binary => {},
        }

        out[0] = flag_byte;

        // next 4 bytes are body length as a 32-bit BE uint
        mem.writeIntBig(u32, out[1..5], @truncate(u32, cmd.len));
        // next 4 bytes are request num as a 32-bit BE int
        mem.writeIntBig(i32, out[5..9], req_num); // write the request number
        mem.copy(u8, out[9..], cmd);

        return out;
    }

    pub fn whoami(allocator: *mem.Allocator) ![]u8 {
        var req = .{
            .name = &[_][]const u8{"whoami"},
            .type = "sync",
            .args = &[_][]const u8{},
        };

        var str = std.ArrayList(u8).init(allocator);
        try std.json.stringify(req, .{}, str.writer());

        return str.toOwnedSlice();
    }
};

test "rpc request" {
    var allocator = std.testing.allocator;

    var req = try RPCConnection.whoami(allocator);
    defer allocator.free(req);

    std.log.warn("{}", .{req});
}
