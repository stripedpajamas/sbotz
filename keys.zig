const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const b64decoder = std.base64.standard_decoder;

pub const network_id = [_]u8{
    0xd4, 0xa1, 0xcb, 0x88, 0xa6, 0x6f, 0x02, 0xf8,
    0xdb, 0x63, 0x5c, 0xe2, 0x64, 0x41, 0xcc, 0x5d,
    0xac, 0x1b, 0x08, 0x42, 0x0c, 0xea, 0xac, 0x23,
    0x08, 0x39, 0xb7, 0x55, 0x84, 0x5a, 0x9f, 0xfb,
};

pub const Keyfile = struct {
    id: []const u8,
    keypair: crypto.sign.Ed25519.KeyPair,

    pub fn parseKeyFile(allocator: *mem.Allocator, keyfile: []const u8) !Keyfile {
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
        const FullKeyfile = struct {
            id: []const u8,
            curve: []const u8,
            public: []const u8,
            private: []const u8,
        };
        var json_stream = std.json.TokenStream.init(clean_file[0..cf_idx]);
        const parsed_keyfile = try std.json.parse(FullKeyfile, &json_stream, .{
            .allocator = allocator,
        });

        var keypair = crypto.sign.Ed25519.KeyPair{
            .public_key = undefined,
            .secret_key = undefined,
        };

        // keys are b64'd and have ".ed25519" on the end, so slice that off and decode
        try b64decoder.decode(&keypair.public_key, parsed_keyfile.public[0 .. parsed_keyfile.public.len - 8]);
        try b64decoder.decode(&keypair.secret_key, parsed_keyfile.private[0 .. parsed_keyfile.private.len - 8]);

        return Keyfile{
            .id = parsed_keyfile.id,
            .keypair = keypair,
        };
    }
};

pub fn loadKeyfile(allocator: *mem.Allocator) !Keyfile {
    const home_dir = if (std.os.getenv("HOME")) |home|
        home
    else
        return error.FailedToLocateKeyfile;

    const path_parts = &[_][]const u8{
        home_dir,
        ".ssb",
    };

    const path = try std.fs.path.join(allocator, path_parts);
    defer allocator.free(path);

    const dir = try std.fs.cwd().openDir(path, .{});
    const keyfile_raw = try dir.readFileAlloc(allocator, "secret", 1024);

    return try Keyfile.parseKeyFile(allocator, keyfile_raw);
}
