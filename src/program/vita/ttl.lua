-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

local counter = require("core.counter")
local ipv4 = require("lib.protocol.ipv4")

DecrementTTL = {
   name = "DecrementTTL",
   shm = {
      rxerrors = {counter},
      ttl_errors = {counter},
      protocol_errors = {counter}
   }
}

function DecrementTTL:new ()
   return setmetatable({ip4 = ipv4:new({})}, {__index=DecrementTTL})
end

function DecrementTTL:push ()
   for _, input in ipairs(self.input) do
      while not link.empty(input) do
         local p = link.receive(input)
         local ip4 = self.ip4:new_from_mem(p.data, p.length)
         if ip4 and ip4:ttl() > 0 then
            ip4:ttl_decrement()
            link.transmit(self.output.output, p)
         elseif ip4 then
            packet.free(p)
            counter.add(self.shm.rxerrors)
            counter.add(self.shm.ttl_errors)
         else
            packet.free(p)
            counter.add(self.shm.rxerrors)
            counter.add(self.shm.protocol_errors)
         end
      end
   end
end
