-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

local counter = require("core.counter")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local arp = require("lib.protocol.arp")
local esp_header = require("lib.protocol.esp")
local esp = require("lib.ipsec.esp")
local exchange = require("program.vita.exchange")
local lpm = require("lib.lpm.lpm4_248").LPM4_248
local ctable = require("lib.ctable")
local ffi = require("ffi")
local packet_buffer


-- route := { net_cidr4=(CIDR4), gw_ip4=(IPv4), preshared_key=(KEY) }

PrivateRouter = {
   name = "PrivateRouter",
   config = {
      routes = {required=true}
   },
   shm = {
      rxerrors = {counter},
      ethertype_errors = {counter},
      protocol_errors = {counter},
      route_errors = {counter}
   }
}

function PrivateRouter:new (conf)
   local o = {
      routes = {},
      eth = ethernet:new({}),
      ip4 = ipv4:new({}),
      fwd4_packets = packet_buffer(),
      arp_packets = packet_buffer()
   }
   for _, route in pairs(conf.routes) do
      o.routes[#o.routes+1] = {
         net_cidr4 = assert(route.net_cidr4, "Missing net_cidr4"),
         link = nil
      }
   end
   return setmetatable(o, {__index = PrivateRouter})
end

function PrivateRouter:link ()
   self.routing_table4 = lpm:new()
   -- NB: need to add default LPM entry until #1238 is fixed, see
   --    https://github.com/snabbco/snabb/issues/1238#issuecomment-345362030
   -- Zero maps to nil in self.routes (which is indexed starting at one), hence
   -- packets that match the default entry will be dropped (and route_errors
   -- incremented.)
   self.routing_table4:add_string("0.0.0.0/0", 0)
   for key, route in ipairs(self.routes) do
      route.link = self.output[config.link_name(route.net_cidr4)]
      self.routing_table4:add_string(route.net_cidr4, key)
   end
   self.routing_table4:build()
end

function PrivateRouter:push ()
   local input = self.input.input

   local fwd4_packets, fwd4_cursor = self.fwd4_packets, 0
   local arp_packets, arp_cursor = self.arp_packets, 0
   while not link.empty(input) do
      local p = link.receive(input)
      local eth = self.eth:new_from_mem(p.data, p.length)
      if eth and eth:type() == 0x0800 then -- IPv4
         fwd4_packets[fwd4_cursor] = packet.shiftleft(p, ethernet:sizeof())
         fwd4_cursor = fwd4_cursor + 1
      elseif eth and eth:type() == arp.ETHERTYPE then
         arp_packets[arp_cursor] = packet.shiftleft(p, ethernet:sizeof())
         arp_cursor = arp_cursor + 1
      else
         packet.free(p)
         counter.add(self.shm.rxerrors)
         counter.add(self.shm.ethertype_errors)
      end
   end

   local new_cursor = 0
   for i = 0, fwd4_cursor - 1 do
      local p = fwd4_packets[i]
      local ip4 = self.ip4:new_from_mem(p.data, ipv4:sizeof())
      if ip4 and ip4:checksum_ok() then
         fwd4_packets[new_cursor] = p
         new_cursor = new_cursor + 1
      else
         packet.free(p)
         counter.add(self.shm.rxerrors)
         counter.add(self.shm.protocol_errors)
      end
   end
   fwd4_cursor = new_cursor

   for i = 0, fwd4_cursor - 1 do
      self:forward4(fwd4_packets[i])
   end

   for i = 0, arp_cursor - 1 do
      link.transmit(self.output.arp, arp_packets[i])
   end
end

function PrivateRouter:find_route4 (dst)
   local route = self.routes[self.routing_table4:search_bytes(dst)]
   return route and route.link
end

function PrivateRouter:forward4 (p)
   self.ip4:new_from_mem(p.data, p.length)
   local route = self:find_route4(self.ip4:dst())
   if route then
      link.transmit(route, p)
   else
      packet.free(p)
      counter.add(self.shm.rxerrors)
      counter.add(self.shm.route_errors)
   end
end


PublicRouter = {
   name = "PublicRouter",
   config = {
      routes = {required=true},
      node_ip4 = {required=true}
   },
   shm = {
      rxerrors = {counter},
      ethertype_errors = {counter},
      protocol_errors = {counter},
      route_errors = {counter},
   }
}

function PublicRouter:new (conf)
   local o = {
      routes = {},
      eth = ethernet:new({}),
      ip4 = ipv4:new({}),
      esp = esp_header:new({}),
      ip4_packets = packet_buffer(),
      fwd4_packets = packet_buffer(),
      protocol_packets = packet_buffer(),
      arp_packets = packet_buffer()
   }
   for _, route in pairs(conf.routes) do
      o.routes[#o.routes+1] = {
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
      route.link = self.output[tostring(route.spi)]
      if route.link then
         self.routing_table4:add(route.spi, index)
      end
   end
end

function PublicRouter:push ()
   local input = self.input.input

   local ip4_packets, ip4_cursor = self.ip4_packets, 0
   local arp_packets, arp_cursor = self.arp_packets, 0
   while not link.empty(input) do
      local p = link.receive(input)
      local eth = self.eth:new_from_mem(p.data, p.length)
      if eth and eth:type() == 0x0800 then -- IPv4
         ip4_packets[ip4_cursor] = packet.shiftleft(p, ethernet:sizeof())
         ip4_cursor = ip4_cursor + 1
      elseif eth and eth:type() == arp.ETHERTYPE then
         arp_packets[arp_cursor] = packet.shiftleft(p, ethernet:sizeof())
         arp_cursor = arp_cursor + 1
      else
         packet.free(p)
         counter.add(self.shm.rxerrors)
         counter.add(self.shm.ethertype_errors)
      end
   end

   local fwd4_packets, fwd4_cursor = self.fwd4_packets, 0
   local protocol_packets, protocol_cursor = self.protocol_packets, 0
   for i = 0, ip4_cursor - 1 do
      local p = ip4_packets[i]
      local ip4 = self.ip4:new_from_mem(p.data, p.length)
              and self.ip4:checksum_ok()
              and self.ip4
      if ip4 and ip4:protocol() == esp.PROTOCOL then
         fwd4_packets[fwd4_cursor] = packet.shiftleft(p, ipv4:sizeof())
         fwd4_cursor = fwd4_cursor + 1
      elseif ip4 and ip4:protocol() == exchange.PROTOCOL then
         protocol_packets[protocol_cursor] = packet.shiftleft(p, ipv4:sizeof())
         protocol_cursor = protocol_cursor + 1
      else
         packet.free(p)
         counter.add(self.shm.rxerrors)
         counter.add(self.shm.protocol_errors)
      end
   end

   for i = 0, fwd4_cursor - 1 do
      self:forward4(fwd4_packets[i])
   end

   for i = 0, protocol_cursor - 1 do
      link.transmit(self.output.protocol, protocol_packets[i])
   end

   for i = 0, arp_cursor - 1 do
      link.transmit(self.output.arp, arp_packets[i])
   end
end

function PublicRouter:find_route4 (spi)
   return self.routes[self.routing_table4:lookup_ptr(spi).value].link
end

function PublicRouter:forward4 (p)
   local route = self.esp:new_from_mem(p.data, p.length)
             and self:find_route4(self.esp:spi())
   if route then
      link.transmit(route, p)
   else
      packet.free(p)
      counter.add(self.shm.rxerrors)
      counter.add(self.shm.route_errors)
   end
end


function packet_buffer ()
   return ffi.new("struct packet *[?]", link.max)
end
