const std = @import("std");
const shs = @import("./shs.zig");

const net = std.net;
const HandshakeClient = shs.HandshakeClient;

const network_id = [_]u8{
    0xd4, 0xa1, 0xcb, 0x88, 0xa6, 0x6f, 0x02, 0xf8,
    0xdb, 0x63, 0x5c, 0xe2, 0x64, 0x41, 0xcc, 0x5d,
    0xac, 0x1b, 0x08, 0x42, 0x0c, 0xea, 0xac, 0x23,
    0x08, 0x39, 0xb7, 0x55, 0x84, 0x5a, 0x9f, 0xfb,
};

pub fn main() !void {
    var allocator = std.testing.allocator;
    var keyfile = try shs.loadKeyfile(allocator);

    var client = HandshakeClient.init(shs.HandshakeOptions{
        .keypair = keyfile.keypair,
        .network_id = network_id,
    });

    var server_addr = try net.Address.parseIp4("127.0.0.1", 8008);
    var conn = try net.tcpConnectToAddress(server_addr);

    var writer = conn.writer();
    var reader = conn.reader();

    var session = try client.newSession(keyfile.keypair.public_key);

    var hello_msg: [64]u8 = undefined;
    session.hello(&hello_msg);
    _ = try writer.write(&hello_msg);

    var server_hello: [64]u8 = undefined;
    try reader.readNoEof(&server_hello);

    var valid_hello = try session.verify_hello(&server_hello);
    if (!valid_hello) {
        std.log.err("received invalid hello (wrong net id?)\n", .{});
        return;
    }

    var auth_msg: [112]u8 = undefined;
    try session.auth(&auth_msg);
    _ = try writer.write(&auth_msg);

    var server_auth: [80]u8 = undefined;
    try reader.readNoEof(&server_auth);

    std.log.info("{x}\n", .{server_auth});
}
