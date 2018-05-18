-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

local counter = require("core.counter")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local arp = require("lib.protocol.arp")
local esp_header = require("lib.protocol.esp")
local esp = require("lib.ipsec.esp")
local exchange = require("program.vita.exchange")
local pf_match = require("pf.match")
local ffi = require("ffi")

-- Ugly hack: given a packet.data pointer we just happen to know the struct
-- packet pointer is two bytes behind.
local function payload_packet (ptr)
   return ffi.cast("struct packet *", ptr - 2)
end


PrivateDispatch = {
   name = "PrivateDispatch",
   shm = {
      rxerrors = {counter},
      ethertype_errors = {counter},
      checksum_errors = {counter}
   }
}

function PrivateDispatch:new ()
   local o = {
      ip4 = ipv4:new({}),
      dispatch = pf_match.compile([[match {
         ip => forward4
         arp => arp
         otherwise => reject_ethertype
      }]])
   }
   return setmetatable(o, {__index=PrivateDispatch})
end

function PrivateDispatch:forward4 (data, length)
   local p = packet.shiftleft(payload_packet(data), ethernet:sizeof())
   assert(self.ip4:new_from_mem(p.data, p.length))
   if self.ip4:checksum_ok() then
      -- Strip datagram of any Ethernet frame padding before encapsulation.
      local d = packet.resize(p, math.min(self.ip4:total_length(), p.length))
      link.transmit(self.output.forward4, d)
   else
      packet.free(p)
      counter.add(self.shm.rxerrors)
      counter.add(self.shm.checksum_errors)
   end
end

function PrivateDispatch:arp (data)
   local p = packet.shiftleft(payload_packet(data), ethernet:sizeof())
   link.transmit(self.output.arp, p)
end

function PrivateDispatch:reject_ethertype (data)
   packet.free(payload_packet(data))
   counter.add(self.shm.rxerrors)
   counter.add(self.shm.ethertype_errors)
end

function PrivateDispatch:push ()
   local input = self.input.input
   while not link.empty(input) do
      local p = link.receive(input)
      self:dispatch(p.data, p.length)
   end
end


PublicDispatch = {
   name = "PublicDispatch",
   shm = {
      rxerrors = {counter},
      ethertype_errors = {counter},
      protocol_errors = {counter}
   }
}

function PublicDispatch:new ()
   local o = {
      ip4 = ipv4:new({}),
      dispatch = pf_match.compile([[match {
         ip proto esp => forward4
         ip proto 99 => protocol
         ip => reject_protocol
         arp => arp
         otherwise => reject_ethertype
      }]])
   }
   return setmetatable(o, {__index=PublicDispatch})
end

function PublicDispatch:forward4 (data)
   local p = packet.shiftleft(payload_packet(data),
                              ethernet:sizeof() + ipv4:sizeof())
   -- NB: Ignore potential differences between IP datagram and Ethernet size
   -- since the minimum ESP packet exceeds 60 bytes in payload.
   link.transmit(self.output.forward4, p)
end

function PublicDispatch:protocol (data)
   local p = packet.shiftleft(payload_packet(data),
                              ethernet:sizeof() + ipv4:sizeof())
   link.transmit(self.output.protocol, p)
end

function PublicDispatch:arp (data)
   local p = packet.shiftleft(payload_packet(data), ethernet:sizeof())
   link.transmit(self.output.arp, p)
end

function PublicDispatch:reject_protocol (data)
   packet.free(payload_packet(data))
   counter.add(self.shm.rxerrors)
   counter.add(self.shm.protocol_errors)
end

function PublicDispatch:reject_ethertype (data)
   packet.free(payload_packet(data))
   counter.add(self.shm.rxerrors)
   counter.add(self.shm.ethertype_errors)
end

function PublicDispatch:push ()
   local input = self.input.input
   while not link.empty(input) do
      local p = link.receive(input)
      self:dispatch(p.data, p.length)
   end
end
