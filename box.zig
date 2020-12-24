const std = @import("std");
const shs = @import("./shs.zig");

const fs = std.fs;
const mem = std.mem;
const crypto = std.crypto;
const SessionKeys = shs.SessionKeys;
const Handshake = shs.Handshake;
const HandshakeOptions = shs.HandshakeOptions;

const log = std.log.scoped(.box);

pub const BoxedConnection = struct {
    session_keys: SessionKeys,
    conn: fs.File,

    pub const MessageHeader = struct {
        msg_len: usize,
        tag: [16]u8,
    };

    pub const header_size: usize = 34;
    pub const max_payload_size: usize = 4096;

    // orchestrates the handshake and saves session keys for future comms
    pub fn init(opts: HandshakeOptions, conn: fs.File) !BoxedConnection {
        var handshake = try Handshake.init(opts);

        var writer = conn.writer();
        var reader = conn.reader();

        var hello_msg: [64]u8 = undefined;
        handshake.hello(&hello_msg);
        var written = try writer.write(&hello_msg);
        log.info("sent {} byte hello msg", .{written});

        var server_hello: [64]u8 = undefined;
        try reader.readNoEof(&server_hello);
        log.info("received server hello msg", .{});

        var valid_hello = try handshake.verifyHello(&server_hello);
        if (!valid_hello) {
            log.err("server hello message is invalid", .{});
            return error.InvalidServerHello;
        }

        var auth_msg: [112]u8 = undefined;
        try handshake.auth(&auth_msg);
        written = try writer.write(&auth_msg);
        log.info("sent {} byte auth msg", .{written});

        var server_auth: [80]u8 = undefined;
        reader.readNoEof(&server_auth) catch |err| {
            std.log.err("incomplete auth msg returned; here's the buffer: {}", .{server_auth});
            return err;
        };
        log.info("received server auth msg", .{});

        if (handshake.verifyAuth(&server_auth)) |keys| {
            log.info("handshake complete", .{});
            return BoxedConnection{
                .session_keys = keys,
                .conn = conn,
            };
        } else {
            log.err("server auth message is invalid", .{});
            return error.InvalidServerAuth;
        }
    }

    // splits up payload into 4096-byte chunks and sends them encrypted down the wire
    pub fn write(self: *BoxedConnection, payload: []const u8) !void {
        var buf: [header_size + max_payload_size]u8 = undefined;

        var chunk_size = max_payload_size;
        var idx: usize = 0;
        while (idx < payload.len) : (idx += chunk_size) {
            var chunk = if (idx + chunk_size >= payload.len) payload[idx..] else payload[idx .. idx + chunk_size];
            var enc_size = self.seal(chunk, &buf);

            var written = try self.conn.write(buf[0..enc_size]);
            log.info("wrote {} byte payload", .{written});
        }
    }

    // reads next header and body in the connection stream into out
    // returns size of response
    pub fn readNextBox(self: *BoxedConnection, out: []u8) !?usize {
        var header: [header_size]u8 = undefined;
        var reader = self.conn.reader();

        if (reader.readNoEof(&header)) |_| {
            log.info("received box header", .{});
            var msg_header = try self.openHeader(header);

            log.info("opened box header; expecting {} byte body", .{msg_header.msg_len});

            var sized_out = out[0..msg_header.msg_len];

            try reader.readNoEof(sized_out);
            try self.openBody(msg_header, sized_out, sized_out);

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

    // out must be 34 + msg.len in size; returns the sealed payload size
    pub fn seal(self: *BoxedConnection, msg: []const u8, out: []u8) usize {
        assert(out.len >= msg.len + 34);
        assert(msg.len <= 4096);

        var tag_nonce: [24]u8 = undefined;
        var body_nonce: [24]u8 = undefined;

        mem.copy(u8, &tag_nonce, &self.keys.send_nonce);
        increment(&self.keys.send_nonce);
        mem.copy(u8, &body_nonce, &self.keys.send_nonce);
        increment(&self.keys.send_nonce);

        // seal body into position 18 of out;
        // we'll chop off the 16-byte auth tag,
        // prepend the body length as 2-bytes, encrypt it (18-bytes),
        // and prepend it along with its own 16-byte auth tag
        // as the first 34-bytes in front of the original encrypted body
        crypto.nacl.SecretBox.seal(out[18 .. 18 + msg.len + 16], msg, body_nonce, self.keys.send_key);
        var tag: [18]u8 = undefined;
        mem.writeIntBig(u16, tag[0..2], @truncate(u16, msg.len));
        mem.copy(u8, tag[2..], out[18..34]);

        crypto.nacl.SecretBox.seal(out[0..34], &tag, tag_nonce, self.keys.send_key);

        return msg.len + 34;
    }

    pub fn openHeader(self: *BoxedConnection, header: [34]u8) !MessageHeader {
        var tag_nonce: [24]u8 = undefined;
        mem.copy(u8, &tag_nonce, &self.keys.recv_nonce);
        increment(&self.keys.recv_nonce);

        var out: [18]u8 = undefined;
        try crypto.nacl.SecretBox.open(&out, &header, tag_nonce, self.keys.recv_key);

        var msg_len = mem.readIntBig(u16, out[0..2]);

        var parsed_header = MessageHeader{
            .msg_len = msg_len,
            .tag = undefined,
        };

        mem.copy(u8, &parsed_header.tag, out[2..]);
        return parsed_header;
    }

    // out must be at least body.len
    pub fn openBody(self: *BoxedConnection, header: MessageHeader, body: []const u8, out: []u8) !void {
        assert(out.len >= body.len);

        var body_nonce: [24]u8 = undefined;
        mem.copy(u8, &body_nonce, &self.keys.recv_nonce);
        increment(&self.keys.recv_nonce);

        var body_and_tag: [4130]u8 = undefined;
        mem.copy(u8, body_and_tag[0..], &header.tag);
        mem.copy(u8, body_and_tag[16..], body);

        var payload_len: usize = 16 + header.msg_len;

        try crypto.nacl.SecretBox.open(out, body_and_tag[0..payload_len], body_nonce, self.keys.recv_key);
    }
};

// increment buffer, treating it as a big endian int
fn increment(buf: []u8) void {
    var idx: usize = buf.len - 1;
    var byte: u16 = 1;
    while (idx >= 0) : (idx -= 1) {
        byte += buf[idx];
        buf[idx] = @truncate(u8, byte);
        byte = byte >> 8;
        if (idx == 0) break;
    }
}

test "increment" {
    const Test = struct {
        input: []const u8,
        expected: []const u8,
    };
    const test_cases = [_]Test{
        Test{
            .input = &[_]u8{0x00},
            .expected = &[_]u8{0x01},
        },
        Test{
            .input = &[_]u8{ 0xff, 0xfe },
            .expected = &[_]u8{ 0xff, 0xff },
        },
        Test{
            .input = &[_]u8{ 0xff, 0xff },
            .expected = &[_]u8{ 0x00, 0x00 },
        },
    };

    var buf: [24]u8 = undefined;
    for (test_cases) |tc| {
        mem.copy(u8, buf[0..], tc.input);
        increment(buf[0..tc.input.len]);
        std.testing.expectEqualSlices(u8, buf[0..tc.input.len], tc.expected);
    }
}
