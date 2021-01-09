const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const Hmac = crypto.auth.hmac.sha2.HmacSha512;
const assert = std.debug.assert;

const log = std.log.scoped(.shs);

pub const HandshakeOptions = struct {
    keypair: crypto.sign.Ed25519.KeyPair,
    network_id: [32]u8,
    remote_pk: [32]u8,
};

pub const SessionKeys = struct {
    send_key: [32]u8 = undefined,
    recv_key: [32]u8 = undefined,
    send_nonce: [24]u8 = undefined,
    recv_nonce: [24]u8 = undefined,
};

pub const Handshake = struct {
    keypair: crypto.sign.Ed25519.KeyPair,
    network_id: [32]u8,

    eph_keypair: crypto.nacl.SealedBox.KeyPair,
    remote_pk: [32]u8,

    remote_eph_pk: [32]u8 = undefined,
    shared_secret_ab: [32]u8 = undefined,
    shared_secret_ab_hash: [32]u8 = undefined,
    shared_secret_aB: [32]u8 = undefined,
    shared_secret_Ab: [32]u8 = undefined,
    sig_A: [64]u8 = undefined,

    pub fn init(opts: HandshakeOptions) !Handshake {
        // generate ephemeral keys for this handshake
        var eph_keypair = try crypto.nacl.SealedBox.KeyPair.create(null);

        var handshake = Handshake{
            .keypair = opts.keypair,
            .network_id = opts.network_id,
            .remote_pk = opts.remote_pk,
            .eph_keypair = eph_keypair,
        };

        return handshake;
    }

    pub fn hello(handshake: *Handshake, out: *[64]u8) void {
        // concat(
        //   nacl_auth(
        //     msg: client_ephemeral_pk,
        //     key: network_identifier
        //   ),
        //   client_ephemeral_pk
        // )
        Hmac.create(out[0..Hmac.mac_length], &handshake.eph_keypair.public_key, &handshake.network_id);
        mem.copy(u8, out[out.len - handshake.eph_keypair.public_key.len ..], &handshake.eph_keypair.public_key);
    }

    pub fn verifyHello(handshake: *Handshake, msg: []const u8) !bool {
        assert(msg.len == 64);
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
        Hmac.create(&auth_tag, remote_eph_pk, &handshake.network_id);

        var valid = mem.eql(u8, rec_auth_tag, auth_tag[0..32]);

        if (!valid) {
            return valid;
        }

        // save the remote eph pk and compute shared secrets
        mem.copy(u8, &handshake.remote_eph_pk, remote_eph_pk);
        handshake.shared_secret_ab = try crypto.dh.X25519.scalarmult(handshake.eph_keypair.secret_key, handshake.remote_eph_pk);
        crypto.hash.sha2.Sha256.hash(&handshake.shared_secret_ab, &handshake.shared_secret_ab_hash, .{});

        // second shared secret requires converting server pk into x25519
        var remote_pk_x25519 = try crypto.dh.X25519.publicKeyFromEd25519(handshake.remote_pk);
        handshake.shared_secret_aB = try crypto.dh.X25519.scalarmult(handshake.eph_keypair.secret_key, remote_pk_x25519);

        // third shared secret requires converting our own sk into x25519
        var local_keypair_x25519 = try crypto.dh.X25519.KeyPair.fromEd25519(handshake.keypair);
        handshake.shared_secret_Ab = try crypto.dh.X25519.scalarmult(local_keypair_x25519.secret_key, handshake.remote_eph_pk);

        return valid;
    }

    pub fn auth(handshake: *Handshake, out: *[112]u8) !void {
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
        mem.copy(u8, sig_payload[0..], &handshake.network_id);
        mem.copy(u8, sig_payload[32..], &handshake.remote_pk);
        mem.copy(u8, sig_payload[64..], &handshake.shared_secret_ab_hash);

        const sig = try crypto.sign.Ed25519.sign(&sig_payload, handshake.keypair, null);
        mem.copy(u8, &handshake.sig_A, &sig);

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
        mem.copy(u8, msg[64..], &handshake.keypair.public_key);
        const nonce: [24]u8 = [_]u8{0x00} ** 24;

        var key_payload: [96]u8 = undefined;
        var key: [32]u8 = undefined;
        mem.copy(u8, key_payload[0..], &handshake.network_id);
        mem.copy(u8, key_payload[32..], &handshake.shared_secret_ab);
        mem.copy(u8, key_payload[64..], &handshake.shared_secret_aB);
        crypto.hash.sha2.Sha256.hash(&key_payload, &key, .{});

        crypto.nacl.SecretBox.seal(out[0..], &msg, nonce, key);
    }

    pub fn verifyAuth(handshake: *Handshake, msg: []const u8) !SessionKeys {
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
        mem.copy(u8, key_payload[0..], &handshake.network_id);
        mem.copy(u8, key_payload[32..], &handshake.shared_secret_ab);
        mem.copy(u8, key_payload[64..], &handshake.shared_secret_aB);
        mem.copy(u8, key_payload[96..], &handshake.shared_secret_Ab);
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
        mem.copy(u8, msg_payload[0..], &handshake.network_id);
        mem.copy(u8, msg_payload[32..], &handshake.sig_A);
        mem.copy(u8, msg_payload[96..], &handshake.keypair.public_key);
        mem.copy(u8, msg_payload[128..], &handshake.shared_secret_ab_hash);
        try crypto.sign.Ed25519.verify(sig, &msg_payload, handshake.remote_pk);

        // generate handshake keys and starting nonces for further communication
        var keys = SessionKeys{};

        // send_key = sha256(sha256(sha256(net_id || ab || aB || Ab)) || remote_pk)
        // recv_key = sha256(sha256(sha256(net_id || ab || aB || Ab)) || local_pk)
        var key_internal: [128]u8 = undefined;
        mem.copy(u8, key_internal[0..], &handshake.network_id);
        mem.copy(u8, key_internal[32..], &handshake.shared_secret_ab);
        mem.copy(u8, key_internal[64..], &handshake.shared_secret_aB);
        mem.copy(u8, key_internal[96..], &handshake.shared_secret_Ab);
        crypto.hash.sha2.Sha256.hash(&key_internal, key_internal[0..32], .{});
        crypto.hash.sha2.Sha256.hash(key_internal[0..32], key_internal[0..32], .{});

        var send_key_internal: [64]u8 = undefined;
        mem.copy(u8, send_key_internal[0..], key_internal[0..32]);
        mem.copy(u8, send_key_internal[32..], &handshake.remote_pk);
        crypto.hash.sha2.Sha256.hash(&send_key_internal, &keys.send_key, .{});

        var recv_key_internal: [64]u8 = undefined;
        mem.copy(u8, recv_key_internal[0..], key_internal[0..32]);
        mem.copy(u8, recv_key_internal[32..], &handshake.keypair.public_key);
        crypto.hash.sha2.Sha256.hash(&recv_key_internal, &keys.recv_key, .{});

        var nonce_hmac: [Hmac.mac_length]u8 = undefined;
        Hmac.create(&nonce_hmac, &handshake.remote_eph_pk, &handshake.network_id);
        mem.copy(u8, &keys.send_nonce, nonce_hmac[0..24]);

        Hmac.create(&nonce_hmac, &handshake.eph_keypair.public_key, &handshake.network_id);
        mem.copy(u8, &keys.recv_nonce, nonce_hmac[0..24]);

        return keys;
    }
};
