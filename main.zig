const std = @import("std");
const shs = @import("./shs.zig");
const box = @import("./box.zig");
const rpc = @import("./rpc.zig");
const keys = @import("./keys.zig");

const net = std.net;
const RPCConnection = rpc.RPCConnection;

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

    var rpc_conn = try RPCConnection.init(opts, conn, keyfile.keypair.public_key);

    var whoami_req = try RPCConnection.whoami(allocator);
    var req = try RPCConnection.encode(allocator, whoami_req, 100, .{
        .stream = false,
        .end_err = false,
        .body_type = RPCConnection.BodyType.JSON,
    });

    try rpc_conn.write(req);

    var response: [4096]u8 = undefined;
    var res_size = try rpc_conn.boxed_conn.readNextBox(&response);

    std.log.info("received {} byte box", .{res_size});

    if (res_size) |sz| {
        var res = response[0..sz];
        std.log.info("total size: {}", .{res.len});
        std.log.info("flags: {x}", .{res[0]});
        std.log.info("body len: {}", .{std.mem.readIntBig(u32, res[1..5])});
        std.log.info("req num: {}", .{std.mem.readIntBig(i32, res[5..9])});
    }

    res_size = try rpc_conn.boxed_conn.readNextBox(&response);

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
