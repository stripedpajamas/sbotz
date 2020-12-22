const std = @import("std");
const shs = @import("./shs.zig");

const fs = std.fs;
const HandshakeClient = shs.HandshakeClient;

pub const BoxedConnection = struct {
    session: *HandshakeClient.Session,

    pub fn new(hs_client: *HandshakeClient, conn: fs.File, remote_pk: [32]u8) !BoxedConnection {
        var session = try hs_client.newSession(remote_pk);
        var writer = conn.writer();
        var reader = conn.reader();

        var hello_msg: [64]u8 = undefined;
        session.hello(&hello_msg);
        _ = try writer.write(&hello_msg);

        var server_hello: [64]u8 = undefined;
        try reader.readNoEof(&server_hello);

        var valid_hello = try session.verifyHello(&server_hello);
        if (!valid_hello) {
            return error.InvalidServerHello;
        }

        var auth_msg: [112]u8 = undefined;
        try session.auth(&auth_msg);
        _ = try writer.write(&auth_msg);

        var server_auth: [80]u8 = undefined;
        try reader.readNoEof(&server_auth);

        var valid_auth = try session.verifyAuth(&server_auth);
        if (!valid_auth) {
            return error.InvalidServerAuth;
        }

        return BoxedConnection{
            .session = &session,
        };
    }
};
