const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const b64decoder = std.base64.standard_decoder;
const Hmac = crypto.auth.hmac.sha2.HmacSha512;

const Keyfile = struct {
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

pub const HandshakeOptions = struct {
    keypair: crypto.sign.Ed25519.KeyPair,
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
        remote_pk: [32]u8,

        remote_eph_pk: [32]u8,
        shared_secret_ab: [32]u8,
        shared_secret_aB: [32]u8,
        shared_secret_Ab: [32]u8,

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

        pub fn verify_hello(session: *Session, msg: []const u8) !bool {
            const rec_auth_tag = msg[0..32];
            const remote_eph_pk = msg[32..];

            var auth_tag: [Hmac.mac_length]u8 = undefined;
            Hmac.create(&auth_tag, remote_eph_pk, &session.client.opts.network_id);

            var valid = mem.eql(u8, rec_auth_tag, auth_tag[0..32]);

            if (!valid) {
                return valid;
            }

            // save the remote eph pk and compute shared secrets
            mem.copy(u8, &session.remote_eph_pk, remote_eph_pk);

            session.shared_secret_ab = try crypto.dh.X25519.scalarmult(session.eph_keypair.secret_key, session.remote_eph_pk);

            return valid;
        }

        pub fn auth(session: *Session) []const u8 {}
    };

    pub fn newSession(self: *HandshakeClient, remote_pk: [32]u8) !Session {
        // generate ephemeral keys for this session
        var eph_keypair = try crypto.nacl.SealedBox.KeyPair.create(null);

        return Session{
            .client = self,
            .remote_pk = remote_pk,
            .eph_keypair = eph_keypair,
            .remote_eph_pk = undefined,
            .shared_secret_ab = undefined,
            .shared_secret_aB = undefined,
            .shared_secret_Ab = undefined,
        };
    }

    pub fn whoami(self: *HandshakeClient) []const u8 {
        return self.opts.keypair.public;
    }
};
