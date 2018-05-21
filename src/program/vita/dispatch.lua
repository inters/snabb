-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

local counter = require("core.counter")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local pf_match = require("pf.match")
local ffi = require("ffi")


PrivateDispatch = {
   name = "PrivateDispatch",
   config = {
      node_ip4 = {required=true}
   },
   shm = {
      rxerrors = {counter},
      ethertype_errors = {counter},
      checksum_errors = {counter}
   }
}

function PrivateDispatch:new (conf)
   local o = {
      p_box = ffi.new("struct packet *[1]"),
      ip4 = ipv4:new({}),
      dispatch = pf_match.compile(([[match {
         ip icmp[icmptype] = icmp-echo and dst host %s => echo4
         ip icmp and dst host %s => events4
         ip => forward4
         arp => arp
         otherwise => reject_ethertype
      }]]):format(conf.node_ip4, conf.node_ip4))
   }
   return setmetatable(o, {__index=PrivateDispatch})
end

function PrivateDispatch:echo4 ()
   link.transmit(self.output.echo4, self.p_box[0])
end

function PrivateDispatch:events4 ()
   -- Not implemented.
   packet.free(self.p_box[0])
end

function PrivateDispatch:forward4 ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof())
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

function PrivateDispatch:arp ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof())
   link.transmit(self.output.arp, p)
end

function PrivateDispatch:reject_ethertype ()
   packet.free(self.p_box[0])
   counter.add(self.shm.rxerrors)
   counter.add(self.shm.ethertype_errors)
end

function PrivateDispatch:push ()
   local input = self.input.input
   while not link.empty(input) do
      local p = link.receive(input)
      self.p_box[0] = p
      self:dispatch(p.data, p.length)
   end
end


PublicDispatch = {
   name = "PublicDispatch",
   config = {
      node_ip4 = {required=true}
   },
   shm = {
      rxerrors = {counter},
      ethertype_errors = {counter},
      protocol_errors = {counter}
   }
}

function PublicDispatch:new (conf)
   local o = {
      p_box = ffi.new("struct packet *[1]"),
      ip4 = ipv4:new({}),
      dispatch = pf_match.compile(([[match {
         ip proto esp => forward4
         ip proto 99 => protocol
         ip icmp[icmptype] = icmp-echo and dst host %s => echo4
         ip icmp and dst host %s => events4
         ip => reject_protocol
         arp => arp
         otherwise => reject_ethertype
      }]]):format(conf.node_ip4, conf.node_ip4))
   }
   return setmetatable(o, {__index=PublicDispatch})
end

function PublicDispatch:echo4 ()
   link.transmit(self.output.echo4, self.p_box[0])
end

function PublicDispatch:events4 ()
   -- Not implemented.
   packet.free(self.p_box[0])
end

function PublicDispatch:forward4 ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof() + ipv4:sizeof())
   -- NB: Ignore potential differences between IP datagram and Ethernet size
   -- since the minimum ESP packet exceeds 60 bytes in payload.
   link.transmit(self.output.forward4, p)
end

function PublicDispatch:protocol ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof() + ipv4:sizeof())
   link.transmit(self.output.protocol, p)
end

function PublicDispatch:arp ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof())
   link.transmit(self.output.arp, p)
end

function PublicDispatch:reject_protocol ()
   packet.free(self.p_box[0])
   counter.add(self.shm.rxerrors)
   counter.add(self.shm.protocol_errors)
end

function PublicDispatch:reject_ethertype ()
   packet.free(self.p_box[0])
   counter.add(self.shm.rxerrors)
   counter.add(self.shm.ethertype_errors)
end

function PublicDispatch:push ()
   local input = self.input.input
   while not link.empty(input) do
      local p = link.receive(input)
      self.p_box[0] = p
      self:dispatch(p.data, p.length)
   end
end
