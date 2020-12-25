const std = @import("std");
const ssb = @import("./client.zig");
const keys = @import("./keys.zig");

pub const log_level: std.log.Level = .info;

pub fn main() !void {
    var allocator = std.testing.allocator;
    var keyfile = try keys.loadKeyfile(allocator);

    var client = try ssb.Client.init(allocator, .{
        .keypair = keyfile.keypair,
        .network_id = keys.network_id,
        .remote_pk = keyfile.keypair.public_key,
    });
    defer client.deinit();

    var id = try client.whoami();
    defer allocator.free(id);

    std.log.info("who i am: {}", .{id});
}
