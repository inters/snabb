-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

local exchange = require("program.vita.exchange")
local icmp = require("program.vita.icmp")
local counter = require("core.counter")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")
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
         ip dst host %s and icmp => icmp4
         ip dst host %s => protocol4_unreachable
         ip => forward4
         arp => arp
         otherwise => reject_ethertype
      }]]):format(conf.node_ip4, conf.node_ip4))
   }
   return setmetatable(o, {__index=PrivateDispatch})
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

function PrivateDispatch:icmp4 ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof())
   link.transmit(self.output.icmp4, p)
end

function PrivateDispatch:arp ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof())
   link.transmit(self.output.arp, p)
end

function PrivateDispatch:protocol4_unreachable ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof())
   link.transmit(self.output.protocol4_unreachable, p)
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
      node_ip4 = {},
      node_ip6 = {}
   },
   shm = {
      rxerrors = {counter},
      ethertype_errors = {counter},
      protocol_errors = {counter},
      fragment_errors = {counter}
   }
}

function PublicDispatch:new (conf)
   local o = {
      p_box = ffi.new("struct packet *[1]")
   }
   if conf.node_ip4 then
      o.dispatch = pf_match.compile(([[match {
         ip[6:2] & 0x3FFF != 0 => reject_fragment
         ip proto esp => forward4
         ip proto %d => protocol
         ip dst host %s and icmp => icmp4
         ip dst host %s => protocol4_unreachable
         ip => reject_protocol
         arp => arp
         otherwise => reject_ethertype
      }]]):format(exchange.PROTOCOL, conf.node_ip4, conf.node_ip4))
   elseif conf.node_ip6 then
      o.dispatch = pf_match.compile(([[match {
         ip6 proto esp => forward6
         ip6 proto %d => protocol6
         ip6 and icmp6 and (ip6[40] = 135 or ip6[40] = 136) => nd
         ip6 dst host %s and icmp6 => icmp6
         ip6 dst host %s => protocol6_unreachable
         ip6 => reject_protocol
         otherwise => reject_ethertype
      }]]):format(exchange.PROTOCOL, conf.node_ip6, conf.node_ip6, conf.node_ip6))
   else error("Need either node_ip4 or node_ip6.") end
   return setmetatable(o, {__index=PublicDispatch})
end

function PublicDispatch:forward4 ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof() + ipv4:sizeof())
   -- NB: Ignore potential differences between IP datagram and Ethernet size
   -- since the minimum ESP packet exceeds 60 bytes in payload.
   link.transmit(self.output.forward4, p)
end

function PublicDispatch:forward6 ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof() + ipv6:sizeof())
   -- NB: Ignore potential differences between IP datagram and Ethernet size
   -- since the minimum ESP packet exceeds 60 bytes in payload.
   link.transmit(self.output.forward6, p)
end

function PublicDispatch:protocol ()
   if not self.output.protocol then self:reject_protocol(); return end
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof() + ipv4:sizeof())
   link.transmit(self.output.protocol, p)
end

function PublicDispatch:protocol6 ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof() + ipv6:sizeof())
   link.transmit(self.output.protocol, p)
end

function PublicDispatch:icmp4 ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof())
   link.transmit(self.output.icmp4, p)
end

function PublicDispatch:icmp6 ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof())
   link.transmit(self.output.icmp6, p)
end

function PublicDispatch:arp ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof())
   link.transmit(self.output.arp, p)
end

function PublicDispatch:nd ()
   link.transmit(self.output.nd, self.p_box[0])
end

function PublicDispatch:protocol4_unreachable ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof())
   link.transmit(self.output.protocol4_unreachable, p)
end

function PublicDispatch:protocol6_unreachable ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof())
   link.transmit(self.output.protocol6_unreachable, p)
end

function PublicDispatch:reject_fragment ()
   packet.free(self.p_box[0])
   counter.add(self.shm.rxerrors)
   counter.add(self.shm.fragment_errors)
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


InboundDispatch = {
   name = "InboundDispatch",
   config = {
      node_ip4 = {required=true},
   },
   shm = {
      protocol_errors = {counter}
   }
}

function InboundDispatch:new (conf)
   local o = {
      eth4 = ethernet:new{type=0x0800},
      p_box = ffi.new("struct packet *[1]"),
      dispatch = pf_match.compile(([[match {
         ip dst host %s and icmp => icmp4
         ip dst host %s => protocol4_unreachable
         ip => forward4
         otherwise => reject_protocol
      }]]):format(conf.node_ip4, conf.node_ip4))
   }
   return setmetatable(o, {__index=InboundDispatch})
end

function InboundDispatch:forward4 ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof())
   link.transmit(self.output.forward4, p)
end

function InboundDispatch:icmp4 ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof())
   link.transmit(self.output.icmp4, p)
end

function InboundDispatch:protocol4_unreachable ()
   local p = packet.shiftleft(self.p_box[0], ethernet:sizeof())
   link.transmit(self.output.protocol4_unreachable, p)
end

function InboundDispatch:reject_protocol ()
   packet.free(self.p_box[0])
   counter.add(self.shm.protocol_errors)
end

function InboundDispatch:push ()
   local eth_hdr4 = self.eth4:header()
   for _, input in ipairs(self.input) do
      while not link.empty(input) do
         local p = link.receive(input)
         -- Prepend Ethernet pseudo header to please pf.match (we receive plain
         -- IPv4 frames on the input port.)
         p = packet.prepend(p, eth_hdr4, ethernet:sizeof())
         self.p_box[0] = p
         self:dispatch(p.data, p.length)
      end
   end
end
