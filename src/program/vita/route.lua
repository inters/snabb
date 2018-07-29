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
   local keybits = 15 -- see lib/lpm/README.md
   local o = {
      ports = {},
      routes = {},
      mtu = conf.mtu,
      ip4 = ipv4:new({}),
      routing_table4 = lpm:new({keybits=keybits})
   }
   for id, route in pairs(conf.routes) do
      local index = #o.ports+1
      assert(index < 2^keybits, "index overflow")
      o.routing_table4:add_string(
         assert(route.net_cidr4, "Missing net_cidr4"),
         index
      )
      o.ports[index] = id
   end
   -- NB: need to add default LPM entry until #1238 is fixed, see
   --    https://github.com/snabbco/snabb/issues/1238#issuecomment-345362030
   -- Zero maps to nil in o.routes (which is indexed starting at one), hence
   -- packets that match the default entry will be dropped (and route_errors
   -- incremented.)
   o.routing_table4:add_string("0.0.0.0/0", 0)
   o.routing_table4:build()
   return setmetatable(o, {__index = PrivateRouter})
end

function PrivateRouter:link ()
   for index, port in ipairs(self.ports) do
      self.routes[index] = self.output[port] or false
   end
end

function PrivateRouter:find_route4 (dst)
   return self.routes[self.routing_table4:search_bytes(dst)]
end

function PrivateRouter:route (p)
   assert(self.ip4:new_from_mem(p.data, p.length))
   local route = self:find_route4(self.ip4:dst())
   if route then
      if p.length + ethernet:sizeof() <= self.mtu then
         link.transmit(route, p)
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
      spi_to_route = {required=true}
   },
   shm = {
      route_errors = {counter}
   }
}

function PublicRouter:new (conf)
   local index_t = ffi.typeof("uint32_t")
   local o = {
      ports = {},
      routes = {},
      routing_table4 = ctable.new{
         key_type = index_t,
         value_type = index_t
      },
      esp = esp:new({})
   }
   for _, sa in pairs(conf.spi_to_route) do
      local index = #o.ports+1
      assert(ffi.cast(index_t, index) == index, "index overflow")
      o.routing_table4:add(assert(sa.spi, "Missing SPI"), index)
      o.ports[index] = sa.route.."_"..sa.spi
   end
   return setmetatable(o, {__index = PublicRouter})
end

function PublicRouter:link ()
   for index, port in ipairs(self.ports) do
      self.routes[index] = self.output[port] or false
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
         link.transmit(route, p)
      else
         packet.free(p)
         counter.add(self.shm.route_errors)
      end
   end
end
