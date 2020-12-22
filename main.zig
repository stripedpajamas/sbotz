const std = @import("std");
const shs = @import("./shs.zig");
const box = @import("./box.zig");
const keys = @import("./keys.zig");

const net = std.net;
const HandshakeClient = shs.HandshakeClient;
const BoxedConnection = box.BoxedConnection;

pub const log_level: std.log.Level = .info;

pub fn main() !void {
    var allocator = std.testing.allocator;
    var keyfile = try keys.loadKeyfile(allocator);

    var client = HandshakeClient.init(shs.HandshakeOptions{
        .keypair = keyfile.keypair,
        .network_id = keys.network_id,
    });

    var server_addr = try net.Address.parseIp4("127.0.0.1", 8008);
    var conn = try net.tcpConnectToAddress(server_addr);

    var boxed_conn = try BoxedConnection.new(&client, conn, keyfile.keypair.public_key);

    // testing
    var payload: [256]u8 = undefined;
    payload[0] = 0b00000010; // signifies we are dealing with json
    var request = "{\"name\":[\"createHistoryStream\"],\"type\":\"source\",\"args\":[{\"id\":\"@Ho4BoSabuGW6RBt7Gj1WDcBG60cLr5MyF1NDy4ardvg=.ed25519\"]}";
    std.mem.writeIntBig(u32, payload[1..5], request.len); // write the body length
    std.mem.writeIntBig(u32, payload[5..9], 1); // write the request number
    std.mem.copy(u8, payload[9..], request); // write the request to the payload

    var to_send = payload[0 .. 9 + request.len];

    try boxed_conn.write(to_send);

    var response = try boxed_conn.readNextMessage(allocator);
    std.log.info("{x}\n{}", .{ response, response });
}
