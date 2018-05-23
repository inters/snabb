-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

local counter = require("core.counter")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local esp = require("lib.protocol.esp")
local lpm = require("lib.lpm.lpm4_248").LPM4_248
local ctable = require("lib.ctable")
local ffi = require("ffi")


-- route := { net_cidr4=(CIDR4), gw_ip4=(IPv4), preshared_key=(KEY) }

PrivateRouter = {
   name = "PrivateRouter",
   config = {
      routes = {required=true},
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
      routes = {},
      mtu = conf.mtu,
      ip4 = ipv4:new({})
   }
   for id, route in pairs(conf.routes) do
      o.routes[#o.routes+1] = {
         id = id,
         net_cidr4 = assert(route.net_cidr4, "Missing net_cidr4"),
         link = nil
      }
   end
   return setmetatable(o, {__index = PrivateRouter})
end

function PrivateRouter:link ()
   local keybits = 15 -- see lib/lpm/README.md
   self.routing_table4 = lpm:new({keybits=keybits})
   -- NB: need to add default LPM entry until #1238 is fixed, see
   --    https://github.com/snabbco/snabb/issues/1238#issuecomment-345362030
   -- Zero maps to nil in self.routes (which is indexed starting at one), hence
   -- packets that match the default entry will be dropped (and route_errors
   -- incremented.)
   self.routing_table4:add_string("0.0.0.0/0", 0)
   for index, route in ipairs(self.routes) do
      assert(index < 2^keybits, "index overflow")
      route.link = self.output[route.id]
      if route.link then
         self.routing_table4:add_string(route.net_cidr4, index)
      end
   end
   self.routing_table4:build()
end

function PrivateRouter:find_route4 (dst)
   return self.routes[self.routing_table4:search_bytes(dst)]
end

function PrivateRouter:route (p)
   assert(self.ip4:new_from_mem(p.data, p.length))
   local route = self:find_route4(self.ip4:dst())
   if route then
      if p.length + ethernet:sizeof() <= self.mtu then
         link.transmit(route.link, p)
      else
         counter.add(self.shm.rxerrors)
         counter.add(self.shm.mtu_errors)
         if bit.band(self.ip4:flags(), 2) == 2 then -- Don’t fragment bit set?
            link.transmit(self.output.fragmentation_needed, p)
         else
            packet.free(p)
         end
      end
   else
      packet.free(p)
      counter.add(self.shm.rxerrors)
      counter.add(self.shm.route_errors)
   end
end

function PrivateRouter:push ()
   while not link.empty(self.input.input) do
      self:route(link.receive(self.input.input))
   end
   while not link.empty(self.input.control) do
      self:route(link.receive(self.input.control))
   end
end


PublicRouter = {
   name = "PublicRouter",
   config = {
      routes = {required=true}
   },
   shm = {
      route_errors = {counter}
   }
}

function PublicRouter:new (conf)
   local o = {
      routes = {},
      esp = esp:new({})
   }
   for id, route in pairs(conf.routes) do
      o.routes[#o.routes+1] = {
         id = id,
         spi = assert(route.spi, "Missing SPI"),
         link = nil
      }
   end
   return setmetatable(o, {__index = PublicRouter})
end

function PublicRouter:link ()
   local index_t = ffi.typeof("uint32_t")
   self.routing_table4 = ctable.new{
      key_type = index_t,
      value_type = index_t
   }
   for index, route in ipairs(self.routes) do
      assert(ffi.cast(index_t, index) == index, "index overflow")
      route.link = self.output[route.id]
      if route.link then
         self.routing_table4:add(route.spi, index)
      end
   end
end

function PublicRouter:find_route4 (spi)
   local entry = self.routing_table4:lookup_ptr(spi)
   return entry and self.routes[entry.value]
end

function PublicRouter:push ()
   local input = self.input.input

   while not link.empty(input) do
      local p = link.receive(input)
      assert(self.esp:new_from_mem(p.data, p.length))
      local route = self:find_route4(self.esp:spi())
      if route then
         link.transmit(route.link, p)
      else
         packet.free(p)
         counter.add(self.shm.route_errors)
      end
   end
end
