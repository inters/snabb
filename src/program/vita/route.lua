-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

local counter = require("core.counter")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local esp = require("lib.protocol.esp")
local poptrie = require("lib.poptrie")
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
      ports = {},
      routes = {},
      mtu = conf.mtu,
      ip4 = ipv4:new({}),
      routing_table4 = poptrie.new{direct_pointing=true}
   }
   for id, route in pairs(conf.routes) do
      local index = #o.ports+1
      assert(ffi.cast("uint16_t", index) == index, "index overflow")
      assert(route.net_cidr4, "Missing net_cidr4")
      local prefix, length = ipv4:pton_cidr(route.net_cidr4)
      o.routing_table4:add(ffi.cast("uint32_t *", prefix)[0], length, index)
      o.ports[index] = id
   end
   o.routing_table4:build()
   return setmetatable(o, {__index = PrivateRouter})
end

function PrivateRouter:link ()
   for index, port in ipairs(self.ports) do
      self.routes[index] = self.output[port] or false
   end
end

function PrivateRouter:find_route4 (dst)
   local address = ffi.cast("uint32_t *", dst)[0]
   return self.routes[self.routing_table4:lookup64(address)]
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
      sa = {required=true}
   },
   shm = {
      route_errors = {counter}
   }
}

function PublicRouter:new (conf)
   local o = {
      routing_table4 = ctable.new{
         key_type = ffi.typeof("uint32_t"),
         value_type = ffi.typeof("uint32_t")
      },
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
   -- Update FIB entries for SAs
   for spi, sa in pairs(conf.sa) do
      local index = #self.ports+1
      assert(ffi.cast("uint32_t", index) == index, "index overflow")
      self.routing_table4:add(spi, index, 'update')
      self.ports[index] = sa.route.."_"..spi
   end
   -- Remove obsolete FIB entries
   for entry in self.routing_table4:iterate() do
      if not conf.sa[tonumber(entry.key)] then
         self.routing_table4:remove_ptr(entry)
      end
   end
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
