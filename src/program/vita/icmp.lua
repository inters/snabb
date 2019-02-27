-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(..., package.seeall)

local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")
local icmp = require("lib.protocol.icmp.header")
local counter = require("core.counter")
local lib = require("core.lib")
local ffi = require("ffi")
local min, max, floor = math.min, math.max, math.floor

ICMP4 = {
   name = "ICMP4",
   config = {
      node_ip4 = {required=true},
      nexthop_mtu = {},
      max_pps = {default=100}
   },
   shm = {
      rxerrors = {counter},
      protocol_errors = {counter},
      type_not_implemented_errors = {counter},
      code_not_implemented_errors = {counter},
      destination_unreachable = {counter},
      net_unreachable = {counter},
      host_unreachable = {counter},
      protocol_unreachable = {counter},
      port_unreachable = {counter},
      fragmentation_needed = {counter},
      source_route_failed = {counter},
      time_exceeded = {counter},
      transit_ttl_exceeded = {counter},
      fragment_reassembly_time_exceeded = {counter},
      parameter_problem = {counter},
      redirect = {counter},
      redirect_net = {counter},
      redirect_host = {counter},
      redirect_tos_net = {counter},
      redirect_tos_host = {counter},
      echo_request = {counter}
   },
   PROTOCOL = 1, -- ICMP = 1
   payload_offset = ipv4:sizeof() + icmp:sizeof(),
   handlers = {}
}

ICMP4.payload_base_t = ffi.typeof([[struct {
      uint8_t unused[4];
      uint8_t excerpt[28];
   } __attribute__((packed))]])

ICMP4.fragmentation_needed_t = ffi.typeof([[struct {
      uint8_t unused[2];
      uint16_t nexthop_mtu;
   } __attribute__((packed))]])

ICMP4.payload_t = ffi.typeof([[union {
      $ base;
      $ fragmentation_needed;
   } __attribute__((packed))]],
   ICMP4.payload_base_t,
   ICMP4.fragmentation_needed_t)

ICMP4.payload_ptr_t = ffi.typeof("$ *", ICMP4.payload_t)

function ICMP4:new (conf)
   local o = {
      ip4 = ipv4:new({
            ttl = 64,
            protocol = ICMP4.PROTOCOL,
            src = ipv4:pton(conf.node_ip4)
      }),
      ip4_in = ipv4:new({}),
      icmp_in = icmp:new(),
      icmp = icmp:new(),
      nexthop_mtu = conf.nexthop_mtu or 1024,
      nexthop_mtu_configured = conf.nexthop_mtu ~= nil,
      throttle = lib.throttle(1),
      max_pps = conf.max_pps,
      buckets = {rx = 0, tx = 0},
      num_buckets = 2,
      logger = nil
   }
   for bucket, _ in pairs(o.buckets) do
      o.buckets[bucket] = floor(o.max_pps / o.num_buckets)
   end
   return setmetatable(o, {__index=ICMP4})
end

function ICMP4:link ()
   if not self.logger then
      self.logger = lib.logger_new({module = self.appname})
   end
   if self.input.fragmentation_needed and not self.nexthop_mtu_configured then
      self.logger:log(("WARNING, 'fragmentation_needed' link attached but nexthop_mtu not configured, defaulting to %d.")
            :format(self.nexthop_mtu))
   end
end

function ICMP4:log (p)
   local payload = ffi.cast(ICMP4.payload_ptr_t, p.data + ICMP4.payload_offset)
   local payload_length = p.length - ICMP4.payload_offset
   local excerpt = ffi.string(
      payload.base.excerpt,
      min(payload_length - ffi.sizeof(payload.base.unused),
          ffi.sizeof(payload.base.excerpt))
   )
   self.logger:log(("received message from %s [type %d code %d packet %s ...]")
         :format(ipv4:ntop(self.ip4_in:src()),
                 self.icmp_in:type(),
                 self.icmp_in:code(),
                 lib.hexdump(excerpt)))
end

-- Destination Unreachable
ICMP4.handlers[3] = function (self, p)
   self:log(p)
   packet.free(p)
   counter.add(self.shm.destination_unreachable)
   counter.add(
      ({ [0] = self.shm.net_unreachable,
         [1] = self.shm.host_unreachable,
         [2] = self.shm.protocol_unreachable,
         [3] = self.shm.port_unreachable,
         [4] = self.shm.fragmentation_needed,
         [5] = self.shm.source_route_failed })
      [self.icmp_in:code()]
         or self.shm.code_not_implemented_errors
   )
end

-- Time Exceeded
ICMP4.handlers[11] = function (self, p)
   self:log(p)
   packet.free(p)
   counter.add(self.shm.time_exceeded)
   counter.add(
      ({ [0] = self.shm.transit_ttl_exceeded,
         [1] = self.shm.fragment_reassembly_time_exceeded })
      [self.icmp_in:code()]
         or self.shm.code_not_implemented_errors
   )
end

-- Parameter Problem
ICMP4.handlers[12] = function (self, p)
   self:log(p)
   packet.free(p)
   counter.add(self.shm.parameter_problem)
end

-- Redirect
ICMP4.handlers[5] = function (self, p)
   self:log(p)
   packet.free(p)
   counter.add(self.shm.redirect)
   counter.add(
      ({ [0] = self.shm.redirect_net,
         [1] = self.shm.redirect_host,
         [2] = self.shm.redirect_tos_net,
         [3] = self.shm.redirect_tos_host })
      [self.icmp_in:code()]
         or self.shm.code_not_implemented_errors
   )
end

-- Echo
ICMP4.handlers[8] = function (self, p)
   -- Copy payload.
   local reply = packet.from_pointer(self:msg_payload(p))
   -- Prepend ICMP header.
   self.icmp:type(0)
   self.icmp:code(0)
   self.icmp:checksum(reply.data, reply.length)
   reply = packet.prepend(reply, self.icmp:header(), icmp:sizeof())
   -- Prepend IP header.
   self.ip4:dst(self.ip4_in:src())
   self.ip4:total_length(reply.length + ipv4:sizeof())
   self.ip4:checksum()
   reply = packet.prepend(reply, self.ip4:header(), ipv4:sizeof())
   -- Send reply.
   link.transmit(self.output.output, reply)
   packet.free(p)
   counter.add(self.shm.echo_request)
end

function ICMP4:msg_payload (p)
   local payload = p.data + ICMP4.payload_offset
   local declared_length = self.ip4_in:total_length() - ICMP4.payload_offset
   local actual_length = p.length - ICMP4.payload_offset
   local length = max(0, min(actual_length, declared_length))
   return payload, length
end

function ICMP4:handle_msg (p)
   -- Ensure packet is a valid ICMP message, and not a fragment.
   if not self.ip4_in:new_from_mem(p.data, p.length)
      or self.ip4_in:protocol() ~= ICMP4.PROTOCOL
      or self.ip4_in:is_fragment()
      or not self.icmp_in:new_from_mem(p.data + ipv4:sizeof(),
                                       p.length - ipv4:sizeof())
      or not self.icmp_in:checksum_check(self:msg_payload(p))
   then
      packet.free(p)
      counter.add(self.shm.rxerrors)
      counter.add(self.shm.protocol_errors)
      return
   end
   -- Ensure we have a handler for ICMP type of packet.
   local handler = self.handlers[self.icmp_in:type()]
   if not handler then
      packet.free(p)
      counter.add(self.shm.rxerrors)
      counter.add(self.shm.type_not_implemented_errors)
      return
   end
   -- Handle incoming message.
   handler(self, p)
end

function ICMP4:send_msg (msgtype, code, p, opt)
   opt = opt or {}
   local msg = packet.resize(packet.allocate(), ffi.sizeof(ICMP4.payload_t))
   local payload = ffi.cast(ICMP4.payload_ptr_t, msg.data)
   -- Set fields, copy packet excerpt.
   if opt.nexthop_mtu then
      payload.fragmentation_needed.nexthop_mtu = lib.htons(opt.nexthop_mtu)
   end
   local excerpt_length = min(p.length, ffi.sizeof(payload.base.excerpt))
   ffi.copy(payload.base.excerpt, p.data, excerpt_length)
   -- Prepend ICMP header
   self.icmp:type(msgtype)
   self.icmp:code(code)
   self.icmp:checksum(msg.data, msg.length)
   msg = packet.prepend(msg, self.icmp:header(), icmp:sizeof())
   -- Prepend IP header.
   assert(self.ip4_in:new_from_mem(p.data, p.length))
   self.ip4:dst(self.ip4_in:src())
   self.ip4:total_length(ipv4:sizeof() + msg.length)
   self.ip4:checksum()
   msg = packet.prepend(msg, self.ip4:header(), ipv4:sizeof())
   -- Send message, free packet.
   link.transmit(self.output.output, msg)
   packet.free(p)
end

function ICMP4:rate_limit (bucket)
   if self.throttle() then
      self.buckets[bucket] =
         min(floor(self.buckets[bucket] + self.max_pps / self.num_buckets),
             self.max_pps)
   end
   if self.buckets[bucket] > 0 then
      self.buckets[bucket] = self.buckets[bucket] - 1
      return true
   end
end

function ICMP4:push ()
   -- Process ingoing messages.
   while not link.empty(self.input.input) and self:rate_limit('rx') do
      self:handle_msg(link.receive(self.input.input))
   end

   -- Process outgoing messages.
   if self.input.protocol_unreachable then
      while not link.empty(self.input.protocol_unreachable)
      and self:rate_limit('tx') do
         self:send_msg(3, 2, link.receive(self.input.protocol_unreachable))
      end
   end
   if self.input.fragmentation_needed then
      while not link.empty(self.input.fragmentation_needed)
      and self:rate_limit('tx') do
         self:send_msg(3, 4, link.receive(self.input.fragmentation_needed), {
                         nexthop_mtu = self.nexthop_mtu
         })
      end
   end
   if self.input.transit_ttl_exceeded then
      while not link.empty(self.input.transit_ttl_exceeded)
      and self:rate_limit('tx') do
         self:send_msg(11, 0, link.receive(self.input.transit_ttl_exceeded))
      end
   end
   -- ...remainder is NYI.
end


ICMP6 = {
   name = "ICMP6",
   config = {
      node_ip6 = ICMP4.config.node_ip4,
      nexthop_mtu = ICMP4.config.nexthop_mtu,
      max_pps = ICMP4.config.max_pps
   },
   shm = {
      rxerrors = {counter},
      protocol_errors = {counter},
      type_not_implemented_errors = {counter},
      code_not_implemented_errors = {counter},
      destination_unreachable = {counter},
      net_unreachable = {counter},
      destination_denied = {counter},
      scope_denied = {counter},
      host_unreachable = {counter},
      port_unreachable = {counter},
      source_denied = {counter},
      net_denied = {counter},
      packet_too_big = {counter},
      time_exceeded = {counter},
      transit_hop_limit_exceeded = {counter},
      fragment_reassembly_time_exceeded = {counter},
      parameter_problem = {counter},
      header_field_problem = {counter},
      next_header_problem = {counter},
      option_problem = {counter},
      echo_request = {counter}
   },
   PROTOCOL = 58, -- ICMPv6 = 58
   MIN_MTU = 1280, -- IPv6 minimum MTU
   payload_offset = ipv6:sizeof() + icmp:sizeof(),
   handlers = {}
}

ICMP6.payload_base_t = ffi.typeof([[struct {
      uint8_t unused[4];
      uint8_t excerpt[40];
   } __attribute__((packed))]])

ICMP6.packet_too_big_t = ffi.typeof([[struct {
      uint32_t nexthop_mtu;
   } __attribute__((packed))]])

ICMP6.parameter_problem_t = ffi.typeof([[struct {
      uint32_t pointer;
   } __attribute__((packed))]])

ICMP6.payload_t = ffi.typeof([[union {
      $ base;
      $ packet_too_big;
      $ parameter_problem;
   } __attribute__((packed))]],
   ICMP6.payload_base_t,
   ICMP6.packet_too_big_t,
   ICMP6.parameter_problem_t)

ICMP6.payload_ptr_t = ffi.typeof("$ *", ICMP6.payload_t)

function ICMP6:new (conf)
   local o = {
      ip6 = ipv6:new({
            hop_limit = 64,
            next_header = ICMP6.PROTOCOL,
            src = ipv6:pton(conf.node_ip6)
      }),
      ip6_in = ipv6:new({}),
      icmp_in = icmp:new(),
      icmp = icmp:new(),
      nexthop_mtu = conf.nexthop_mtu or 1280,
      nexthop_mtu_configured = conf.nexthop_mtu ~= nil,
      throttle = lib.throttle(1),
      max_pps = conf.max_pps,
      buckets = {rx = 0, tx = 0},
      num_buckets = 2,
      logger = nil
   }
   for bucket, _ in pairs(o.buckets) do
      o.buckets[bucket] = floor(o.max_pps / o.num_buckets)
   end
   return setmetatable(o, {__index=ICMP6})
end

function ICMP6:link ()
   if not self.logger then
      self.logger = lib.logger_new({module = self.appname})
   end
   -- input link aliases
   self.input.packet_too_big =
      self.input.packet_too_big or self.input.fragmentation_needed
   self.input.transit_hop_limit_exceeded =
      self.input.transit_hop_limit_exceeded or self.input.transit_ttl_exceeded
   -- a helpful warning
   if self.input.packet_too_big and not self.nexthop_mtu_configured then
      self.logger:log(("WARNING, 'packet_too_big' or 'fragmentation_needed' link attached but nexthop_mtu not configured, defaulting to %d.")
            :format(self.nexthop_mtu))
   end
end

function ICMP6:log (p)
   local payload = ffi.cast(ICMP6.payload_ptr_t, p.data + ICMP6.payload_offset)
   local payload_length = p.length - ICMP6.payload_offset
   local excerpt = ffi.string(
      payload.base.excerpt,
      min(payload_length - ffi.sizeof(payload.base.unused),
          ffi.sizeof(payload.base.excerpt))
   )
   self.logger:log(("received message from %s [type %d code %d packet %s ...]")
         :format(ipv6:ntop(self.ip6_in:src()),
                 self.icmp_in:type(),
                 self.icmp_in:code(),
                 lib.hexdump(excerpt)))
end

-- Destination Unreachable
ICMP6.handlers[1] = function (self, p)
   self:log(p)
   packet.free(p)
   counter.add(self.shm.destination_unreachable)
   counter.add(
      ({ [0] = self.shm.net_unreachable,
         [1] = self.shm.destination_denied,
         [2] = self.shm.scope_denied,
         [3] = self.shm.host_unreachable,
         [4] = self.shm.port_unreachable,
         [5] = self.shm.source_denied,
         [6] = self.shm.net_denied })
      [self.icmp_in:code()]
         or self.shm.code_not_implemented_errors
   )
end

-- Packet Too Big
ICMP6.handlers[2] = function (self, p)
   self:log(p)
   packet.free(p)
   counter.add(self.shm.packet_too_big)
end

-- Time Exceeded
ICMP6.handlers[3] = function (self, p)
   self:log(p)
   packet.free(p)
   counter.add(self.shm.time_exceeded)
   counter.add(
      ({ [0] = self.shm.transit_hop_limit_exceeded,
         [1] = self.shm.fragment_reassembly_time_exceeded })
      [self.icmp_in:code()]
         or self.shm.code_not_implemented_errors
   )
end

-- Parameter Problem
ICMP6.handlers[4] = function (self, p)
   self:log(p)
   packet.free(p)
   counter.add(self.shm.parameter_problem)
   counter.add(
      ({ [0] = self.shm.header_field_problem,
         [1] = self.shm.next_header_problem,
         [2] = self.shm.option_problem })
      [self.icmp_in:code()]
         or self.shm.code_not_implemented_errors
   )
end

-- Echo
ICMP6.handlers[128] = function (self, p)
   -- Copy payload.
   local reply = packet.from_pointer(self:msg_payload(p))
   -- Prepend ICMP and IP headers.
   self.ip6:dst(self.ip6_in:src())
   self.ip6:payload_length(reply.length + icmp:sizeof())
   self.icmp:type(129)
   self.icmp:code(0)
   self.icmp:checksum(reply.data, reply.length, self.ip6)
   reply = packet.prepend(reply, self.icmp:header(), icmp:sizeof())
   reply = packet.prepend(reply, self.ip6:header(), ipv6:sizeof())
   -- Send reply.
   link.transmit(self.output.output, reply)
   packet.free(p)
   counter.add(self.shm.echo_request)
end

function ICMP6:msg_payload (p)
   local payload = p.data + ICMP6.payload_offset
   local declared_length = self.ip6_in:payload_length() - icmp:sizeof()
   local actual_length = p.length - ICMP6.payload_offset
   local length = max(0, min(actual_length, declared_length))
   return payload, length
end

function ICMP6:handle_msg (p)
   -- Ensure packet is a valid ICMP message.
   local function parse_and_check (p)
      if not self.ip6_in:new_from_mem(p.data, p.length)
         or self.ip6_in:next_header() ~= ICMP6.PROTOCOL
         or not self.icmp_in:new_from_mem(p.data + ipv6:sizeof(),
                                          p.length - ipv6:sizeof())
      then return false end
      local payload, length = self:msg_payload(p)
      return self.icmp_in:checksum_check(payload, length, self.ip6_in)
   end
   if not parse_and_check(p) then
      packet.free(p)
      counter.add(self.shm.rxerrors)
      counter.add(self.shm.protocol_errors)
      return
   end
   -- Ensure we have a handler for ICMP type of packet.
   local handler = self.handlers[self.icmp_in:type()]
   if not handler then
      packet.free(p)
      counter.add(self.shm.rxerrors)
      counter.add(self.shm.type_not_implemented_errors)
      return
   end
   -- Handle incoming message.
   handler(self, p)
end

function ICMP6:send_msg (msgtype, code, p, opt)
   opt = opt or {}
   local msg = packet.resize(packet.allocate(), ffi.sizeof(ICMP6.payload_t))
   local payload = ffi.cast(ICMP6.payload_ptr_t, msg.data)
   -- Set fields, copy packet excerpt.
   if opt.nexthop_mtu then
      payload.fragmentation_needed.nexthop_mtu = lib.htonl(opt.nexthop_mtu)
   end
   if opt.pointer then
      payload.parameter_problem.pointer = lib.htonl(opt.pointer)
   end
   local excerpt_max = -- As much of invoking packet as possible without the
                       -- ICMPv6 packet exceeding the minimum IPv6 MTU
      ICMP6.MIN_MTU - ICMP6.payload_offset - ffi.sizeof(payload.base.unused)
   local excerpt_length = min(p.length, excerpt_max)
   msg = packet.resize(msg, ffi.sizeof(payload.base.unused) + excerpt_length)
   ffi.copy(payload.base.excerpt, p.data, excerpt_length)
   -- Prepend ICMP and IP headers
   assert(self.ip6_in:new_from_mem(p.data, p.length))
   self.ip6:dst(self.ip6_in:src())
   self.ip6:payload_length(msg.length + icmp:sizeof())
   self.icmp:type(msgtype)
   self.icmp:code(code)
   self.icmp:checksum(msg.data, msg.length, self.ip6)
   msg = packet.prepend(msg, self.icmp:header(), icmp:sizeof())
   msg = packet.prepend(msg, self.ip6:header(), ipv6:sizeof())
   -- Send message, free packet.
   link.transmit(self.output.output, msg)
   packet.free(p)
end

function ICMP6:rate_limit (bucket)
   if self.throttle() then
      self.buckets[bucket] =
         min(floor(self.buckets[bucket] + self.max_pps / self.num_buckets),
             self.max_pps)
   end
   if self.buckets[bucket] > 0 then
      self.buckets[bucket] = self.buckets[bucket] - 1
      return true
   end
end

function ICMP6:push ()
   -- Process ingoing messages.
   while not link.empty(self.input.input) and self:rate_limit('rx') do
      self:handle_msg(link.receive(self.input.input))
   end

   -- Process outgoing messages.
   if self.input.protocol_unreachable then
      while not link.empty(self.input.protocol_unreachable)
      and self:rate_limit('tx') do
         self:send_msg(4, 1, link.receive(self.input.protocol_unreachable), {
                          pointer = 6 -- Next Header
         })
      end
   end
   if self.input.packet_too_big then
      while not link.empty(self.input.packet_too_big)
      and self:rate_limit('tx') do
         self:send_msg(2, 0, link.receive(self.input.packet_too_big), {
                         nexthop_mtu = self.nexthop_mtu
         })
      end
   end
   if self.input.transit_hop_limit_exceeded then
      while not link.empty(self.input.transit_hop_limit_exceeded)
      and self:rate_limit('tx') do
         self:send_msg(3, 0, link.receive(self.input.transit_hop_limit_exceeded))
      end
   end
   -- ...remainder is NYI.
end
