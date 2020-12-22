const std = @import("std");
const shs = @import("./shs.zig");
const box = @import("./box.zig");
const keys = @import("./keys.zig");

const net = std.net;
const HandshakeClient = shs.HandshakeClient;
const BoxedConnection = box.BoxedConnection;

pub fn main() !void {
    var allocator = std.testing.allocator;
    var keyfile = try keys.loadKeyfile(allocator);

    var client = HandshakeClient.init(shs.HandshakeOptions{
        .keypair = keyfile.keypair,
        .network_id = keys.network_id,
    });

    var server_addr = try net.Address.parseIp4("127.0.0.1", 8008);
    var conn = try net.tcpConnectToAddress(server_addr);

    var boxed_conn = BoxedConnection.new(&client, conn, keyfile.keypair.public_key);
}
