const std = @import("std");
const mem = std.mem;

const Keypair = struct {
    curve: []const u8,
    id: []const u8,
    public: []const u8,
    private: []const u8,

    pub fn parseKeyFile(allocator: *mem.Allocator, keyfile: []const u8) !Keypair {
        // remove all the bs comment lines (start with #)
        var clean_file: [384]u8 = undefined;

        var kf_idx: usize = 0;
        var cf_idx: usize = 0;
        var in_comment = false;
        while (kf_idx < keyfile.len) : (kf_idx += 1) {
            var char = keyfile[kf_idx];
            if (char == '\n') {
                in_comment = false;
                continue;
            }

            if (char == '#') {
                in_comment = true;
                continue;
            }

            if (!in_comment) {
                clean_file[cf_idx] = char;
                cf_idx += 1;
            }
        }

        // json parse the result
        var json_stream = std.json.TokenStream.init(clean_file[0..cf_idx]);
        const keypair = try std.json.parse(Keypair, &json_stream, .{
            .allocator = allocator,
        });

        return keypair;
    }
};

fn loadKeypair(allocator: *mem.Allocator) !?Keypair {
    const home_dir = if (std.os.getenv("HOME")) |home|
        home
    else
        return null;

    const path_parts = &[_][]const u8{
        home_dir,
        ".ssb",
    };

    const path = try std.fs.path.join(allocator, path_parts);
    defer allocator.free(path);

    const dir = try std.fs.cwd().openDir(path, .{});
    const keyfile = try dir.readFileAlloc(allocator, "secret", 1024);

    const keypair = try Keypair.parseKeyFile(allocator, keyfile);

    return keypair;
}

pub fn ssbKeys(allocator: *mem.Allocator) ?[]const u8 {}

pub fn main() !void {
    var allocator = std.testing.allocator;
    var keypair = (try loadKeypair(allocator)) orelse unreachable;
    std.log.info("{}\n", .{keypair});
}
