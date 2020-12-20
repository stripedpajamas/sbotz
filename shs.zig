const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const Hmac = crypto.auth.hmac.sha2.HmacSha512;

const ScuttlebuttKey = struct {
    curve: []const u8,
    id: []const u8,
    public: []const u8,
    private: []const u8,

    pub fn parseKeyFile(allocator: *mem.Allocator, keyfile: []const u8) !ScuttlebuttKey {
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
        const keypair = try std.json.parse(ScuttlebuttKey, &json_stream, .{
            .allocator = allocator,
        });

        return keypair;
    }
};

pub fn loadKeypair(allocator: *mem.Allocator) !?ScuttlebuttKey {
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

    const keypair = try ScuttlebuttKey.parseKeyFile(allocator, keyfile);

    return keypair;
}

pub const HandshakeOptions = struct {
    keypair: ScuttlebuttKey,
    network_id: [32]u8,
};

pub const HandshakeClient = struct {
    allocator: *mem.Allocator,
    opts: HandshakeOptions,

    pub fn init(allocator: *mem.Allocator, opts: HandshakeOptions) HandshakeClient {
        return HandshakeClient{
            .allocator = allocator,
            .opts = opts,
        };
    }

    const Session = struct {
        client: *HandshakeClient,
        eph_keypair: crypto.nacl.SealedBox.KeyPair,

        pub const hello_len: usize = 64;

        pub fn hello(session: *Session) ![]const u8 {
            // concat(
            //   nacl_auth(
            //     msg: client_ephemeral_pk,
            //     key: network_identifier
            //   ),
            //   client_ephemeral_pk
            // )
            var out = try session.client.allocator.alloc(u8, hello_len);
            errdefer session.client.allocator.free(out);

            Hmac.create(out[0..Hmac.mac_length], &session.eph_keypair.public_key, &session.client.opts.network_id);
            mem.copy(u8, out[out.len - session.eph_keypair.public_key.len ..], &session.eph_keypair.public_key);

            return out;
        }
    };

    pub fn newSession(self: *HandshakeClient) !Session {
        // generate ephemeral keys for this session
        var eph_keypair = try crypto.nacl.SealedBox.KeyPair.create(null);

        return Session{
            .client = self,
            .eph_keypair = eph_keypair,
        };
    }

    pub fn whoami(self: *HandshakeClient) []const u8 {
        return self.opts.keypair.public;
    }
};
