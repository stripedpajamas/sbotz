const std = @import("std");
const shs = @import("./shs.zig");
const box = @import("./box.zig");
const keys = @import("./keys.zig");

const net = std.net;
const BoxedConnection = box.BoxedConnection;

pub const log_level: std.log.Level = .info;

pub fn main() !void {
    var allocator = std.testing.allocator;
    var keyfile = try keys.loadKeyfile(allocator);

    const opts = shs.HandshakeOptions{
        .keypair = keyfile.keypair,
        .network_id = keys.network_id,
    };

    var server_addr = try net.Address.parseIp4("127.0.0.1", 8008);
    var conn = try net.tcpConnectToAddress(server_addr);

    var boxed_conn = try BoxedConnection.new(opts, conn, keyfile.keypair.public_key);

    // TODO write some RPC translation layer
    var payload: [256]u8 = undefined;
    payload[0] = 0b00000010; // signifies we are dealing with json
    // var request = "{\"name\":[\"createHistoryStream\"],\"type\":\"source\",\"args\":[{\"id\":\"@Ho4BoSabuGW6RBt7Gj1WDcBG60cLr5MyF1NDy4ardvg=.ed25519\"]}";
    var request = "{\"name\":[\"whoami\"],\"type\":\"sync\",\"args\":[]}";
    std.mem.writeIntBig(u32, payload[1..5], request.len); // write the body length
    std.mem.writeIntBig(i32, payload[5..9], 100); // write the request number
    std.mem.copy(u8, payload[9..], request); // write the request to the payload

    var to_send = payload[0 .. 9 + request.len];

    try boxed_conn.write(to_send);

    var response: [4096]u8 = undefined;
    var res_size = try boxed_conn.readNextBox(&response);

    std.log.info("received {} byte box", .{res_size});

    if (res_size) |sz| {
        var res = response[0..sz];
        std.log.info("total size: {}", .{res.len});
        std.log.info("flags: {x}", .{res[0]});
        std.log.info("body len: {}", .{std.mem.readIntBig(u32, res[1..5])});
        std.log.info("req num: {}", .{std.mem.readIntBig(i32, res[5..9])});
    }

    res_size = try boxed_conn.readNextBox(&response);

    std.log.info("received {} byte box", .{res_size});

    if (res_size) |sz| {
        var res = response[0..sz];
        std.log.info("total size: {}", .{res.len});
        std.log.info("is it dope? {}", .{res});
        // std.log.info("flags: {x}", .{res[0]});
        // std.log.info("body len: {x}", .{res[1..5]});
        // std.log.info("req num: {x}", .{res[5..9]});
    }
}
