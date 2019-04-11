-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

local counter = require("core.counter")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")
local esp = require("lib.protocol.esp")
local poptrie = require("lib.poptrie")
local ffi = require("ffi")

local events = timeline.load_events(engine.timeline(), ...)

-- route := { net=(CIDR), gateway=(IP), ... }

PrivateRouter = {
   name = "PrivateRouter",
   config = {
      route4 = {},
      route6 = {},
      mtu = {required=true}
   },
   shm = {
      rxerrors = {counter},
      route_errors = {counter},
      mtu_errors = {counter}
   }
}

function PrivateRouter:new (conf)
   local o = {
      ports = {},
      routes = {},
      mtu = conf.mtu,
      routing_table = poptrie.new{direct_pointing=true, s=24}
   }
   if conf.route4 then
      o.ip = ipv4:new{}
      o.route = self.route4
   elseif conf.route6 then
      o.ip = ipv6:new{}
      o.route = self.route6
   else
      error("Need either route4 or route6.")
   end
   for id, route in pairs(conf.route4 or conf.route6) do
      local index = #o.ports+1
      assert(ffi.cast("uint16_t", index) == index, "index overflow")
      assert(route.net, "Missing net")
      local prefix, length = o.ip:pton_cidr(route.net)
      o.routing_table:add(prefix, length, index)
      o.ports[index] = id
   end
   o.routing_table:build()
   return setmetatable(o, {__index = PrivateRouter})
end

function PrivateRouter:link ()
   for index, port in ipairs(self.ports) do
      self.routes[index] = self.output[port] or false
   end
end

function PrivateRouter:find_route4 (dst)
   return self.routes[self.routing_table:lookup32(dst)]
end

function PrivateRouter:route4 (p)
   assert(self.ip:new_from_mem(p.data, p.length))
   events.private_route_start()
   local route = self:find_route4(self.ip:dst())
   if route then
      events.private_route_lookup_success()
      if p.length <= self.mtu then
         link.transmit(route, p)
      else
         counter.add(self.shm.rxerrors)
         counter.add(self.shm.mtu_errors)
         if bit.band(self.ip:flags(), 2) == 2 then -- Don’t fragment bit set?
            link.transmit(self.output.fragmentation_needed, p)
         else
            packet.free(p)
         end
      end
   else
      events.private_route_lookup_failure()
      packet.free(p)
      counter.add(self.shm.rxerrors)
      counter.add(self.shm.route_errors)
   end
   events.private_route_end()
end

function PrivateRouter:find_route6 (dst)
   return self.routes[self.routing_table:lookup128(dst)]
end

function PrivateRouter:route6 (p)
   assert(self.ip:new_from_mem(p.data, p.length))
   events.private_route_start()
   local route = self:find_route6(self.ip:dst())
   if route then
      events.private_route_lookup_success()
      if p.length <= self.mtu then
         link.transmit(route, p)
      else
         counter.add(self.shm.rxerrors)
         counter.add(self.shm.mtu_errors)
         link.transmit(self.output.fragmentation_needed, p)
      end
   else
      events.private_route_lookup_failure()
      packet.free(p)
      counter.add(self.shm.rxerrors)
      counter.add(self.shm.route_errors)
   end
   events.private_route_end()
end

function PrivateRouter:push ()
   local input = self.input.input
   while not link.empty(input) do
      self:route(link.receive(input))
   end
   local control = self.input.control
   while not link.empty(control) do
      self:route(link.receive(control))
   end
end


PublicRouter = {
   name = "PublicRouter",
   config = {
      sa = {required=true}
   },
   shm = {
      route_errors = {counter}
   }
}

function PublicRouter:new (conf)
   local o = {
      routing_table = ffi.new("uint32_t[?]", 2^16),
      esp = esp:new({})
   }
   self.build_fib(o, conf)
   return setmetatable(o, {__index = PublicRouter})
end

function PublicRouter:reconfig (conf)
   self:build_fib(conf)
   self:link() -- links might have changed before reconfig
end

function PublicRouter:build_fib (conf)
   self.ports = {}
   self.routes = {}
   ffi.fill(self.routing_table, ffi.sizeof(self.routing_table), 0)
   for spi, sa in pairs(conf.sa) do
      local index = #self.ports+1
      assert(spi < 2^16, "SPI overflow")
      assert(ffi.cast("uint32_t", index) == index, "index overflow")
      self.routing_table[spi] = index
      self.ports[index] = sa.route.."_"..spi
   end
end

function PublicRouter:link ()
   for index, port in ipairs(self.ports) do
      self.routes[index] = self.output[port] or false
   end
end

function PublicRouter:find_route (spi)
   return self.routes[self.routing_table[spi]]
end

function PublicRouter:push ()
   local input = self.input.input

   while not link.empty(input) do
      events.public_route_start()
      local p = link.receive(input)
      assert(self.esp:new_from_mem(p.data, p.length))
      local route = self:find_route(self.esp:spi())
      if route then
         events.public_route_lookup_success()
         link.transmit(route, p)
      else
         events.public_route_lookup_failure()
         packet.free(p)
         counter.add(self.shm.route_errors)
      end
      events.public_route_end()
   end
end
