const std = @import("std");
const ssb = @import("./client.zig");
const keys = @import("./keys.zig");

var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};

pub const log_level: std.log.Level = .warn;

fn printMsg(value: []const u8, end: bool) bool {
    const stdout = std.io.getStdOut().writer();
    stdout.print("{}\n", .{value}) catch |err| {
        std.log.err("failed to write output: {}", .{err});
    };
    return true;
}

pub fn main() !void {
    const gpa = &general_purpose_allocator.allocator;
    defer {
        _ = general_purpose_allocator.deinit();
    }
    var arena_instance = std.heap.ArenaAllocator.init(gpa);
    defer arena_instance.deinit();
    const arena = &arena_instance.allocator;

    var allocator = arena;

    var keyfile = try keys.loadKeyfile(allocator);

    var client = try ssb.Client.init(allocator, .{
        .keypair = keyfile.keypair,
        .network_id = keys.network_id,
        .remote_pk = keyfile.keypair.public_key,
    });
    defer client.deinit();

    try client.createHistoryStream(.{
        .id = keyfile.id,
    }, printMsg);
}
