const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const b64decoder = std.base64.standard_decoder;
const Hmac = crypto.auth.hmac.sha2.HmacSha512;
const assert = std.debug.assert;

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
    opts: HandshakeOptions,

    pub fn init(opts: HandshakeOptions) HandshakeClient {
        return HandshakeClient{
            .opts = opts,
        };
    }

    const Session = struct {
        client: *HandshakeClient,
        eph_keypair: crypto.nacl.SealedBox.KeyPair,
        remote_pk: [32]u8,

        remote_eph_pk: [32]u8,
        shared_secret_ab: [32]u8,
        shared_secret_ab_hash: [32]u8,
        shared_secret_aB: [32]u8,
        shared_secret_Ab: [32]u8,
        sig_A: [64]u8,

        send_key: [32]u8,
        recv_key: [32]u8,
        send_nonce: [24]u8,
        recv_nonce: [24]u8,

        const MessageHeader = struct {
            msg_len: usize,
            tag: [16]u8,
        };

        pub fn hello(session: *Session, out: *[64]u8) void {
            // concat(
            //   nacl_auth(
            //     msg: client_ephemeral_pk,
            //     key: network_identifier
            //   ),
            //   client_ephemeral_pk
            // )
            Hmac.create(out[0..Hmac.mac_length], &session.eph_keypair.public_key, &session.client.opts.network_id);
            mem.copy(u8, out[out.len - session.eph_keypair.public_key.len ..], &session.eph_keypair.public_key);
        }

        pub fn verifyHello(session: *Session, msg: []const u8) !bool {
            std.debug.assert(msg.len == 64);
            // concat(
            //   nacl_auth(
            //     msg: server_ephemeral_pk,
            //     key: network_identifier
            //   ),
            //   server_ephemeral_pk
            // )
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
            crypto.hash.sha2.Sha256.hash(&session.shared_secret_ab, &session.shared_secret_ab_hash, .{});

            // second shared secret requires converting server pk into x25519
            var remote_pk_x25519 = try crypto.dh.X25519.publicKeyFromEd25519(session.remote_pk);
            session.shared_secret_aB = try crypto.dh.X25519.scalarmult(session.eph_keypair.secret_key, remote_pk_x25519);

            // third shared secret requires converting our own sk into x25519
            var local_keypair_x25519 = try crypto.dh.X25519.KeyPair.fromEd25519(session.client.opts.keypair);
            session.shared_secret_Ab = try crypto.dh.X25519.scalarmult(local_keypair_x25519.secret_key, session.remote_eph_pk);

            return valid;
        }

        pub fn auth(session: *Session, out: *[112]u8) !void {
            // detached_signature_A = nacl_sign_detached(
            //   msg: concat(
            //     network_identifier,
            //     server_longterm_pk,
            //     sha256(shared_secret_ab)
            //   ),
            //   key: client_longterm_sk
            // )
            //
            var sig_payload: [96]u8 = undefined;
            mem.copy(u8, sig_payload[0..], &session.client.opts.network_id);
            mem.copy(u8, sig_payload[32..], &session.remote_pk);
            mem.copy(u8, sig_payload[64..], &session.shared_secret_ab_hash);

            const sig = try crypto.sign.Ed25519.sign(&sig_payload, session.client.opts.keypair, null);
            mem.copy(u8, &session.sig_A, &sig);

            // nacl_secret_box(
            //   msg: concat(
            //     detached_signature_A,
            //     client_longterm_pk
            //   ),
            //   nonce: 24_bytes_of_zeros,
            //   key: sha256(
            //     concat(
            //       network_identifier,
            //       shared_secret_ab,
            //       shared_secret_aB
            //     )
            //   )
            // )
            var msg: [96]u8 = undefined;
            mem.copy(u8, msg[0..], &sig);
            mem.copy(u8, msg[64..], &session.client.opts.keypair.public_key);
            const nonce: [24]u8 = [_]u8{0x00} ** 24;

            var key_payload: [96]u8 = undefined;
            var key: [32]u8 = undefined;
            mem.copy(u8, key_payload[0..], &session.client.opts.network_id);
            mem.copy(u8, key_payload[32..], &session.shared_secret_ab);
            mem.copy(u8, key_payload[64..], &session.shared_secret_aB);
            crypto.hash.sha2.Sha256.hash(&key_payload, &key, .{});

            crypto.nacl.SecretBox.seal(out[0..], &msg, nonce, key);
        }

        pub fn verifyAuth(session: *Session, msg: []const u8) !bool {
            std.debug.assert(msg.len == 80);

            // detached_signature_B = assert_nacl_secretbox_open(
            //   ciphertext: msg4,
            //   nonce: 24_bytes_of_zeros,
            //   key: sha256(
            //     concat(
            //       network_identifier,
            //       shared_secret_ab,
            //       shared_secret_aB,
            //       shared_secret_Ab
            //     )
            //   )
            // )
            var key_payload: [128]u8 = undefined;
            var key: [32]u8 = undefined;
            mem.copy(u8, key_payload[0..], &session.client.opts.network_id);
            mem.copy(u8, key_payload[32..], &session.shared_secret_ab);
            mem.copy(u8, key_payload[64..], &session.shared_secret_aB);
            mem.copy(u8, key_payload[96..], &session.shared_secret_Ab);
            crypto.hash.sha2.Sha256.hash(&key_payload, &key, .{});

            const nonce: [24]u8 = [_]u8{0x00} ** 24;
            var sig: [64]u8 = undefined;
            try crypto.nacl.SecretBox.open(&sig, msg, nonce, key);

            // assert_nacl_sign_verify_detached(
            //   sig: detached_signature_B,
            //   msg: concat(
            //     network_identifier,
            //     detached_signature_A,
            //     client_longterm_pk,
            //     sha256(shared_secret_ab)
            //   ),
            //   key: server_longterm_pk
            // )

            var msg_payload: [160]u8 = undefined;
            mem.copy(u8, msg_payload[0..], &session.client.opts.network_id);
            mem.copy(u8, msg_payload[32..], &session.sig_A);
            mem.copy(u8, msg_payload[96..], &session.client.opts.keypair.public_key);
            mem.copy(u8, msg_payload[128..], &session.shared_secret_ab_hash);
            try crypto.sign.Ed25519.verify(sig, &msg_payload, session.remote_pk);

            // generate session keys and starting nonces for further communication
            // send_key = sha256(sha256(sha256(net_id || ab || aB || Ab)) || remote_pk)
            // recv_key = sha256(sha256(sha256(net_id || ab || aB || Ab)) || local_pk)
            var key_internal: [128]u8 = undefined;
            mem.copy(u8, key_internal[0..], &session.client.opts.network_id);
            mem.copy(u8, key_internal[32..], &session.shared_secret_ab);
            mem.copy(u8, key_internal[64..], &session.shared_secret_aB);
            mem.copy(u8, key_internal[96..], &session.shared_secret_Ab);
            crypto.hash.sha2.Sha256.hash(&key_internal, key_internal[0..32], .{});
            crypto.hash.sha2.Sha256.hash(key_internal[0..32], key_internal[0..32], .{});

            var send_key_internal: [64]u8 = undefined;
            mem.copy(u8, send_key_internal[0..], key_internal[0..32]);
            mem.copy(u8, send_key_internal[32..], &session.remote_pk);
            crypto.hash.sha2.Sha256.hash(&send_key_internal, &session.send_key, .{});

            var recv_key_internal: [64]u8 = undefined;
            mem.copy(u8, recv_key_internal[0..], key_internal[0..32]);
            mem.copy(u8, recv_key_internal[32..], &session.client.opts.keypair.public_key);
            crypto.hash.sha2.Sha256.hash(&recv_key_internal, &session.recv_key, .{});

            var nonce_hmac: [Hmac.mac_length]u8 = undefined;
            Hmac.create(&nonce_hmac, &session.remote_eph_pk, &session.client.opts.network_id);
            mem.copy(u8, &session.send_nonce, nonce_hmac[0..24]);

            Hmac.create(&nonce_hmac, &session.eph_keypair.public_key, &session.client.opts.network_id);
            mem.copy(u8, &session.recv_nonce, nonce_hmac[0..24]);
            return true;
        }

        // out must be 34 + msg.len in size
        pub fn seal(session: *Session, msg: []const u8, out: []u8) void {
            assert(out.len >= msg.len + 34);
            assert(msg.len <= 4096);

            var tag_nonce: [24]u8 = undefined;
            var body_nonce: [24]u8 = undefined;

            mem.copy(u8, &tag_nonce, &session.send_nonce);
            increment(&session.send_nonce);
            mem.copy(u8, &body_nonce, &session.send_nonce);
            increment(&session.send_nonce);

            // seal body into position 18 of out;
            // we'll chop off the 16-byte auth tag,
            // prepend the body length as 2-bytes, encrypt it (18-bytes),
            // and prepend it along with its own 16-byte auth tag
            // as the first 34-bytes in front of the original encrypted body
            crypto.nacl.SecretBox.seal(out[18..], msg, body_nonce, session.send_key);
            var tag: [18]u8 = undefined;
            mem.writeIntBig(u16, tag[0..2], msg.len);
            mem.copy(u8, tag[2..], out[18..34]);

            crypto.nacl.SecretBox.seal(out[0..34], tag, tag_nonce, session.send_key);
        }

        pub fn openHeader(session: *Session, header: [34]u8) !MessageHeader {
            var tag_nonce: [24]u8 = undefined;
            mem.copy(u8, &tag_nonce, &session.recv_nonce);
            increment(&session.recv_nonce);

            var out: [34]u8 = undefined;
            try crypto.nacl.SecretBox.open(&out, tag, tag_nonce, session.recv_key);

            var msg_len = mem.readIntBit(u16, out[0..2]);

            var header = MessageHeader{
                .msg_len = msg_len,
                .tag = undefined,
            };

            mem.copy(u8, &tag, out);
            return header;
        }

        // out must be at least body.len + 16
        pub fn openBody(session: *Session, header: MessageHeader, body: []const u8, out: []u8) !void {
            assert(out.len >= body.len + 16);

            var body_nonce: [24]u8 = undefined;
            mem.copy(u8, &body_nonce, &session.recv_nonce);
            increment(&session.recv_nonce);

            mem.copy(u8, out[0..], &header.tag);
            mem.copy(u8, out[16..], &body);

            try crypto.nacl.SecretBox.open(&out, out, body_nonce, session.recv_key);
        }
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
            .shared_secret_ab_hash = undefined,
            .shared_secret_aB = undefined,
            .shared_secret_Ab = undefined,
            .sig_A = undefined,
            .send_key = undefined,
            .recv_key = undefined,
            .send_nonce = undefined,
            .recv_nonce = undefined,
        };
    }
};

fn increment(buf: []u8) void {
    var idx: usize = 0;
    var byte: u16 = 1;
    while (idx < buf.len) : (idx += 1) {
        byte = byte +% buf[idx];
        buf[idx] = @truncate(u8, byte);
        byte = byte >> 8;
    }
}

test "increment" {
    const Test = struct {
        input: []const u8,
        expected: []const u8,
    };
    const test_cases = [_]Test{
        Test{
            .input = &[_]u8{0x00},
            .expected = &[_]u8{0x01},
        },
        Test{
            .input = &[_]u8{ 0xfe, 0xff },
            .expected = &[_]u8{ 0xff, 0xff },
        },
        Test{
            .input = &[_]u8{ 0xff, 0xff },
            .expected = &[_]u8{ 0x00, 0x00 },
        },
    };

    var buf: [24]u8 = undefined;
    for (test_cases) |tc| {
        mem.copy(u8, buf[0..], tc.input);
        increment(buf[0..tc.input.len]);
        std.testing.expectEqualSlices(u8, buf[0..tc.input.len], tc.expected);
    }
}
