-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

local counter = require("core.counter")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")

local events = timeline.load_events(engine.timeline(), ...)

DecrementTTL = {
   name = "DecrementTTL",
   shm = {
      checksum_errors = {counter},
      protocol_errors = {counter}
   }
}

function DecrementTTL:new ()
   return setmetatable({ip4 = ipv4:new({})}, {__index=DecrementTTL})
end

function DecrementTTL:push ()
   local output = self.output.output
   local time_exceeded = self.output.time_exceeded
   for _, input in ipairs(self.input) do
      while not link.empty(input) do
         events.decrement_ttl_start()
         local p = link.receive(input)
         local ip4 = self.ip4:new_from_mem(p.data, p.length)
         if ip4 and not ip4:checksum_ok() then
            events.checksum_verification_failed()
            packet.free(p)
            counter.add(self.shm.checksum_errors)
         elseif ip4 and ip4:ttl() > 1 then
            events.checksum_verification_succeeded()
            ip4:ttl_decrement()
            -- Strip IP frame from TFC or Ethernet padding
            local len = math.min(p.length, ip4:total_length())
            link.transmit(output, packet.resize(p, len))
         elseif ip4 then
            link.transmit(time_exceeded, p)
         else
            packet.free(p)
            counter.add(self.shm.protocol_errors)
         end
         events.decrement_ttl_end()
      end
   end
end

DecrementHopLimit = {
   name = "DecrementHopLimit",
   shm = {
      protocol_errors = {counter}
   }
}

function DecrementHopLimit:new ()
   return setmetatable({ip6 = ipv6:new({})}, {__index=DecrementHopLimit})
end

function DecrementHopLimit:push ()
   local output = self.output.output
   local hop_limit_exceeded = self.output.hop_limit_exceeded
   for _, input in ipairs(self.input) do
      while not link.empty(input) do
         events.decrement_hop_limit_start()
         local p = link.receive(input)
         local ip6 = self.ip6:new_from_mem(p.data, p.length)
         if ip6 and ip6:hop_limit() > 1 then
            ip6:hop_limit(ip6:hop_limit() - 1)
            -- Strip IP frame from TFC or Ethernet padding
            local len = math.min(p.length, ip6:payload_length() + ip6:sizeof())
            link.transmit(output, packet.resize(p, len))
         elseif ip6 then
            link.transmit(hop_limit_exceeded, p)
         else
            packet.free(p)
            counter.add(self.shm.protocol_errors)
         end
         events.decrement_hop_limit_end()
      end
   end
end
