const std = @import("std");

const fs = std.fs;
const mem = std.mem;

const log = std.log.scoped(.rpc);

pub const header_size: usize = 9;

pub const Header = struct {
    pub const BodyType = enum {
        Binary,
        String,
        JSON,
    };

    pub const Flags = struct {
        stream: bool,
        end_err: bool = false,
        body_type: BodyType = BodyType.JSON,
    };

    flags: Flags,
    body_len: usize,
    req_num: i32,

    pub fn init(header: [header_size]u8) Header {
        var flags = Flags{
            .stream = header[0] & 8 == 8,
            .end_err = header[0] & 4 == 4,
            .body_type = switch (header[0] & 3) {
                0 => BodyType.Binary,
                1 => BodyType.String,
                2 => BodyType.JSON,
                else => unreachable,
            },
        };

        var body_len = @as(usize, mem.readIntBig(u32, header[1..5]));
        var req_num = mem.readIntBig(i32, header[5..9]);

        return Header{
            .flags = flags,
            .body_len = body_len,
            .req_num = req_num,
        };
    }

    pub fn serialize(header: Header, out: *[header_size]u8) void {
        var flag_byte: u8 = 0;
        if (header.flags.stream) {
            flag_byte |= 0b1000;
        }
        if (header.flags.end_err) {
            flag_byte |= 0b0100;
        }
        switch (header.flags.body_type) {
            BodyType.String => {
                flag_byte |= 0b0001;
            },
            BodyType.JSON => {
                flag_byte |= 0b0010;
            },
            BodyType.Binary => {},
        }

        out[0] = flag_byte;

        // next 4 bytes are body length as a 32-bit BE uint
        mem.writeIntBig(u32, out[1..5], @truncate(u32, header.body_len));
        // next 4 bytes are request num as a 32-bit BE int
        mem.writeIntBig(i32, out[5..9], header.req_num); // write the request number
    }
};

pub const Message = struct {
    header: Header,
    body: []const u8,

    // out must be body.len + header_size
    pub fn serialize(msg: Message, out: []u8) void {
        std.debug.assert(out.len == body.len + header_size);

        Header.serialize(out[0..header_size]);
        mem.copy(u8, out[header_size..], body);
    }
};

const goodbye_header = [_]u8{0} ** header_size;

pub fn RPCConnection(comptime ReaderWriterType: type) type {
    return struct {
        // underlying file/connection
        conn: *ReaderWriterType,

        allocator: *mem.Allocator,
        goodbye_sent: bool = false,

        const Self = @This();

        pub fn init(allocator: *mem.Allocator, conn: *ReaderWriterType) Self {
            return Self{
                .allocator = allocator,
                .conn = conn,
            };
        }

        // reads out next header, or returns null if there isn't one
        pub fn readNextHeader(self: Self) !?Header {
            if (self.goodbye_sent) {
                return error.GoodbyeAlreadySent;
            }
            var header: [header_size]u8 = undefined;
            const n = try self.conn.read(&header);

            if (n != header_size) {
                return null;
            }

            if (mem.eql(u8, &header, &goodbye_header)) {
                log.info("remote said goodbye", .{});
                return null;
            }

            var msg_header = Header.init(header);

            return msg_header;
        }

        // caller owns returned body slice
        pub fn readNextMessage(self: *Self) !?Message {
            if (self.goodbye_sent) {
                return error.GoodbyeAlreadySent;
            }
            var header = try self.readNextHeader();

            if (header) |h| {
                log.info("opened rpc header; expecting {} byte msg", .{h.body_len});
                var out = try self.allocator.alloc(u8, h.body_len);

                const n = try self.conn.read(out);

                if (n != out.len) {
                    log.err("received {} bytes instead of the {} expectation", .{
                        n,
                        h.body_len,
                    });
                    return error.EndOfStream;
                }

                return Message{
                    .header = h,
                    .body = out,
                };
            } else {
                // there is no next header; underlying source has dried up
                return null;
            }
        }

        pub fn writeMessage(self: *Self, msg: Message) !usize {
            if (self.goodbye_sent) {
                return error.GoodbyeAlreadySent;
            }
            log.info("sending this message: {}", .{msg});
            var payload = std.ArrayList(u8).init(self.allocator);
            defer payload.deinit();

            var writer = payload.writer();

            var header: [header_size]u8 = undefined;
            msg.header.serialize(&header);
            try writer.writeAll(&header);

            try writer.writeAll(msg.body);

            return self.conn.write(payload.items);
        }

        pub fn goodbye(self: *Self) !void {
            log.info("sending empty header to signal end", .{});

            _ = try self.conn.write(&goodbye_header);
            self.goodbye_sent = true;
        }
    };
}
