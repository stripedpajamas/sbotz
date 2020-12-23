const std = @import("std");
const shs = @import("./shs.zig");

const fs = std.fs;
const mem = std.mem;
const crypto = std.crypto;

const log = std.log.scoped(.box);

const HEADER_SIZE: usize = 34;
const MAX_PAYLOAD_SIZE: usize = 4096;

pub const BoxedConnection = struct {
    session: shs.Session,
    conn: fs.File,

    // orchestrates the handshake
    pub fn new(opts: shs.HandshakeOptions, conn: fs.File, remote_pk: [32]u8) !BoxedConnection {
        var session = try shs.newSession(opts, remote_pk);
        var writer = conn.writer();
        var reader = conn.reader();

        var hello_msg: [64]u8 = undefined;
        session.hello(&hello_msg);
        var written = try writer.write(&hello_msg);
        log.info("sent {} byte hello msg", .{written});

        var server_hello: [64]u8 = undefined;
        try reader.readNoEof(&server_hello);
        log.info("received server hello msg", .{});

        var valid_hello = try session.verifyHello(&server_hello);
        if (!valid_hello) {
            log.err("server hello message is invalid", .{});
            return error.InvalidServerHello;
        }

        var auth_msg: [112]u8 = undefined;
        try session.auth(&auth_msg);
        written = try writer.write(&auth_msg);
        log.info("sent {} byte auth msg", .{written});

        var server_auth: [80]u8 = undefined;
        reader.readNoEof(&server_auth) catch |err| {
            std.log.err("incomplete auth msg returned; here's the buffer: {}", .{server_auth});
            return err;
        };
        log.info("received server auth msg", .{});

        var valid_auth = try session.verifyAuth(&server_auth);
        if (!valid_auth) {
            log.err("server auth message is invalid", .{});
            return error.InvalidServerAuth;
        }

        log.info("handshake complete", .{});

        return BoxedConnection{
            .session = session,
            .conn = conn,
        };
    }

    // splits up payload into 4096-byte chunks and sends them encrypted down the wire
    pub fn write(self: *BoxedConnection, payload: []const u8) !void {
        var buf: [HEADER_SIZE + MAX_PAYLOAD_SIZE]u8 = undefined;

        var chunk_size = MAX_PAYLOAD_SIZE;
        var idx: usize = 0;
        while (idx < payload.len) : (idx += chunk_size) {
            var chunk = if (idx + chunk_size >= payload.len) payload[idx..] else payload[idx .. idx + chunk_size];
            var enc_size = self.session.seal(chunk, &buf);

            var written = try self.conn.write(buf[0..enc_size]);
            log.info("wrote {} byte payload", .{written});
        }
    }

    // reads next header and body in the connection stream into out
    // returns size of response
    pub fn readNextBox(self: *BoxedConnection, out: []u8) !?usize {
        var header: [HEADER_SIZE]u8 = undefined;
        var reader = self.conn.reader();

        if (reader.readNoEof(&header)) |_| {
            log.info("received box header", .{});
            var msg_header = try self.session.openHeader(header);

            log.info("opened box header; expecting {} byte body", .{msg_header.msg_len});

            var sized_out = out[0..msg_header.msg_len];

            try reader.readNoEof(sized_out);
            try self.session.openBody(msg_header, sized_out, sized_out);

            return msg_header.msg_len;
        } else |err| switch (err) {
            error.EndOfStream => {
                // no more messages
                return null;
            },
            else => {
                return err;
            },
        }
    }
};
