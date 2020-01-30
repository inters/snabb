-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

local shm = require("core.shm")
local counter = require("core.counter")
local lib = require("core.lib")
local ethernet = require("lib.protocol.ethernet")
local arp = require("lib.protocol.arp")
local arp_ipv4 = require("lib.protocol.arp_ipv4")
local ipv4 = require("lib.protocol.ipv4")
local datagram = require("lib.protocol.datagram")
local ffi = require("ffi")

-- NextHop4 forwards IPv4 packets to the next hop and resolves Ethernet
-- addresses via ARP, see https://tools.ietf.org/html/rfc826

NextHop4 = {
   name = "NextHop4",
   config = {
      node_mac = {required=true},
      node_ip4 = {required=true},
      nexthop_ip4 = {required=true},
      nexthop_mac = {},
      synchronize = {default=false}
   },
   shm = {
      arp_requests = {counter},
      arp_replies = {counter},
      arp_errors = {counter},
      addresses_added = {counter},
      addresses_updated = {counter}
   }
}

function NextHop4:new (conf)
   local o = {}
   o.node_mac = ethernet:pton(conf.node_mac)
   o.node_ip4 = ipv4:pton(conf.node_ip4)
   o.nexthop_ip4 = ipv4:pton(conf.nexthop_ip4)

   -- Ethernet frame header (node → nexthop)
   o.eth =  ethernet:new{
      src = o.node_mac
   }

   -- ARP request template
   o.request = {
      p = packet.allocate(),
      arp_ipv4 = arp_ipv4:new{sha=o.node_mac, spa=o.node_ip4}
   }
   local d = datagram:new(o.request.p)
   d:push(o.request.arp_ipv4)
   d:push(arp:new{
             op = 'request',
             pro = arp_ipv4.PROTOCOL,
             pln = arp_ipv4.ADDRESS_BYTES
   })
   d:push(ethernet:new{
             type = arp.ETHERTYPE,
             src = o.node_mac,
             dst = ethernet:pton("FF:FF:FF:FF:FF:FF")
   })
   o.request.p = d:packet()
   o.request.arp_ipv4:new_from_mem(
      o.request.p.data + ethernet:sizeof() + arp:sizeof(),
      o.request.p.length - ethernet:sizeof() - arp:sizeof()
   )

   -- Headers to parse
   o.arp = arp:new{}
   o.arp_ipv4 = arp_ipv4:new{}

   -- Initially, we don’t know the hardware address of our next hop
   o.connected = false
   o.connect_interval = lib.throttle(5)

   -- ...unless its supplied
   if conf.nexthop_mac then
      o.eth:dst(ethernet:pton(conf.nexthop_mac))
      o.connected = true
   end

   -- We can get our next hop by synchronizing with other NextHop4 instances
   o.synchronize = conf.synchronize
   o.sync_interval = lib.throttle(1)

   return setmetatable(o, {__index = NextHop4})
end

function NextHop4:stop ()
   packet.free(self.request.p)
end

function NextHop4:link ()
   -- We receive `arp' messages on the `arp' port, and traffic to be forwarded
   -- on all other input ports.
   self.forward = {}
   for _, link in ipairs(self.input) do
      if link ~= self.input.arp then
         table.insert(self.forward, link)
      end
   end
end

function NextHop4:push ()
   local output = self.output.output

   if self.connected then
      -- Forward packets to next hop
      for _, input in ipairs(self.forward) do
         while not link.empty(input) do
            local p = link.receive(input)
            link.transmit(output, self:encapsulate(p, 0x0800))
         end
      end

   elseif self.connect_interval() then
      -- Send periodic ARP requests if not connected
      link.transmit(output, self:arp_request(self.nexthop_ip4))
      counter.add(self.shm.arp_requests)
   end

   -- Handle incoming ARP requests and replies
   local arp_input = self.input.arp
   while not link.empty(arp_input) do
      local p = link.receive(arp_input)
      local reply = self:handle_arp(p)
      if reply then
         counter.add(self.shm.arp_replies)
         link.transmit(output, reply)
      else
         packet.free(p)
      end
   end

   -- Synchronize next hop
   if self.synchronize and self.sync_interval() then
      self:sync_nexthop()
   end
end

function NextHop4:encapsulate (p, type)
   self.eth:type(type)
   return packet.prepend(p, self.eth:header_ptr(), ethernet:sizeof())
end

function NextHop4:arp_request (ip)
   self.request.arp_ipv4:tpa(ip)
   return packet.clone(self.request.p)
end

local function ip4eq (x, y)
   return ffi.cast("uint32_t *", x)[0] == ffi.cast("uint32_t *", y)[0]
end

function NextHop4:handle_arp (p)
   local arp_hdr, arp_ipv4 = self.arp, self.arp_ipv4
   -- ?Do I have the hardware type in ar$hrd?
   -- Yes: (almost definitely)
   --    [optionally check the hardware length ar$hln]
   --    ?Do I speak the protocol in ar$pro?
   if arp_hdr:new_from_mem(p.data, p.length)
      and arp_hdr:hrd() == arp.ETHERNET
      and arp_hdr:pro() == arp_ipv4.PROTOCOL
      and arp_ipv4:new_from_mem(p.data + arp:sizeof(), p.length - arp:sizeof())
   then
      -- Yes:
      --    [optionally check the protocol length ar$pln]
      --    Merge_flag := false
      --    (self.connected in our case)
      --    If the pair <protocol type, sender protocol address> is
      --        already in my translation table, update the sender
      --        hardware address field of the entry with the new
      --        information in the packet and set Merge_flag to true.
      if ip4eq(arp_ipv4:spa(), self.nexthop_ip4) and self.connected then
         self.eth:dst(arp_ipv4:sha())
         if self.synchronize then self:share_nexthop() end
         counter.add(self.shm.addresses_updated)
         self.connected = true
      end
      --    ?Am I the target protocol address?
      if ip4eq(arp_ipv4:tpa(), self.node_ip4) then
         -- Yes:
         --    If Merge_flag is false, add the triplet <protocol type,
         --        sender protocol address, sender hardware address> to
         --        the translation table.
         if not self.connected then
            self.eth:dst(arp_ipv4:sha())
            if self.synchronize then self:share_nexthop() end
            counter.add(self.shm.addresses_added)
            self.connected = true
         end
         --    ?Is the opcode ares_op$REQUEST?  (NOW look at the opcode!!)
         if arp_hdr:op() == 'request' then
            -- Yes:
            --    Swap hardware and protocol fields, putting the local
            --        hardware and protocol addresses in the sender fields.
            arp_ipv4:tha(arp_ipv4:sha())
            arp_ipv4:sha(self.node_mac)
            arp_ipv4:tpa(arp_ipv4:spa())
            arp_ipv4:spa(self.node_ip4)
            --    Set the ar$op field to ares_op$REPLY
            arp_hdr:op('reply')
            --    Send the packet to the (new) target hardware address on
            --        the same hardware on which the request was received.
            return self:encapsulate(p, arp.ETHERTYPE)
         end
      end
   else
      counter.add(self.shm.arp_errors)
   end
end

function NextHop4:shared_nexthop_path ()
   -- We share the resolved next hop with siblings of the same name.
   return "group/"..self.name.."/"..self.appname
end

function NextHop4:share_nexthop ()
   if not self.nexthop then
      self.nexthop = shm.create(self:shared_nexthop_path(), "uint8_t[6]")
   end
   ffi.copy(self.nexthop, self.eth:dst(), ffi.sizeof(self.nexthop))
end

function NextHop4:sync_nexthop ()
   if not self.nexthop then
      local ok, nh = pcall(shm.open, self:shared_nexthop_path(), "uint8_t[6]")
      self.connected, self.nexthop = ok or self.connected, ok and nh
   end
   if self.connected and self.nexthop then
      self.eth:dst(self.nexthop)
   end
end


local ipv6 = require("lib.protocol.ipv6")
local icmp = require("lib.protocol.icmp.header")
local ns = require("lib.protocol.icmp.nd.ns")
local na = require("lib.protocol.icmp.nd.na")
local tlv = require("lib.protocol.icmp.nd.options.tlv")

-- NextHop6 forwards IPv6 packets to the next hop and resolves Ethernet
-- addresses via a subset of IPv6 Neighbor Discovery, see
-- https://tools.ietf.org/html/rfc4861

NextHop6 = {
   name = "NextHop6",
   config = {
      node_mac = {required=true},
      node_ip6 = {required=true},
      nexthop_ip6 = {required=true},
      nexthop_mac = {},
      synchronize = {default=false}
   },
   shm = {
      ns_requests = {counter},
      na_replies = {counter},
      nd_errors = {counter},
      addresses_added = {counter},
      addresses_updated = {counter}
   }
}

function NextHop6:new (conf)
   local o = {}
   o.node_mac = ethernet:pton(conf.node_mac)
   o.node_ip6 = ipv6:pton(conf.node_ip6)
   o.nexthop_ip6 = ipv6:pton(conf.nexthop_ip6)

   -- Ethernet frame header (node → nexthop)
   o.eth = ethernet:new{
      src = o.node_mac
   }

   -- Neighbor solicitation message to emit
   o.ns_request = {
      p = packet.allocate()
   }
   local d = datagram:new(o.ns_request.p)
   local source_lladdr = tlv:new(1, o.node_mac):tlv()
   d:payload(source_lladdr, ffi.sizeof(source_lladdr))
   d:push(ns:new(o.nexthop_ip6))
   local icmp = icmp:new(135, 0)
   local sol_node_mcast = ipv6:solicited_node_mcast(o.nexthop_ip6)
   local ip = ipv6:new{
      next_header = 58, -- ICMP6
      hop_limit = 255,
      src = o.node_ip6,
      dst = sol_node_mcast
   }
   local payload = d:packet()
   icmp:checksum(payload.data, payload.length, ip)
   d:push(icmp)
   ip:payload_length(d:packet().length)
   d:push(ip)
   d:push(ethernet:new{
             src = conf.local_mac,
             dst = ethernet:ipv6_mcast(sol_node_mcast),
             type = 0x86dd -- IPv6
   })
   o.ns_request.p = d:packet()

   -- Neighbor advertisement message template
   o.na_reply = {
      p = packet.allocate(),
      -- Leave IPv6 dst address unspecified. It will be set to the source of
      -- the incoming solicitation.
      ip = ipv6:new{
         next_header = 58, -- ICMP6
         hop_limit = 255,
         src = conf.node_ip6
      },
      -- Leave Ethernet dst address unspecified.
      eth = ethernet:new{
         src = conf.node_mac,
         type = 0x86dd -- IPv6
      }
   }
   local d = datagram:new(o.na_reply.p)
   local target_lladdr = tlv:new(2, o.node_mac):tlv()
   d:payload(target_lladdr, ffi.sizeof(target_lladdr))
   d:push(na:new(o.node_ip6, nil, 1, nil))
   local icmp = icmp:new(136, 0)
   local payload = d:packet()
   icmp:checksum(payload.data, payload.length, o.na_reply.ip)
   d:push(icmp)
   o.na_reply.ip:payload_length(d:packet().length)
   d:push(o.na_reply.ip)
   d:push(o.na_reply.eth)
   o.na_reply.p = d:packet()
   o.na_reply.ip:new_from_mem(d:packet().data+ethernet:sizeof(), ipv6:sizeof())
   o.na_reply.eth:new_from_mem(d:packet().data, ethernet:sizeof())

   -- Headers to parse
   o.eth_in = ethernet:new{}
   o.ip_in = ipv6:new{}
   o.icmp_in = icmp:new()
   o.ns_in = ns:new()
   o.na_in = na:new()

   -- Initially, we don’t know the hardware address of our next hop
   o.connected = false
   o.connect_interval = lib.throttle(5)

   -- ...unless its supplied
   if conf.nexthop_mac then
      o.eth:dst(ethernet:pton(conf.nexthop_mac))
      o.connected = true
   end

   -- We can get our next hop by synchronizing with other NextHop6 instances
   o.synchronize = conf.synchronize
   o.sync_interval = lib.throttle(1)

   return setmetatable(o, {__index = NextHop6})
end

function NextHop6:stop ()
   packet.free(self.ns_request.p)
   packet.free(self.na_reply.p)
end

function NextHop6:link ()
   -- We receive `nd' messages on the `nd' port, and traffic to be forwarded
   -- on all other input ports.
   self.forward = {}
   for _, link in ipairs(self.input) do
      if link ~= self.input.nd then
         table.insert(self.forward, link)
      end
   end
end

function NextHop6:push ()
   local output = self.output.output

   if self.connected then
      -- Forward packets to next hop
      for _, input in ipairs(self.forward) do
         while not link.empty(input) do
            local p = link.receive(input)
            link.transmit(output, self:encapsulate(p, 0x86dd))
         end
      end

   elseif self.connect_interval() then
      -- Send periodic neighbot solicitation requests if not connected
      link.transmit(output, self.ns_request.p)
      counter.add(self.shm.ns_requests)
   end

   -- Handle incoming ND solicitations and advertisements
   local nd_input = self.input.nd
   while not link.empty(nd_input) do
      local p = link.receive(nd_input)
      local reply = self:handle_nd(p)
      if reply then
         link.transmit(output, reply)
         counter.add(self.shm.na_replies)
      else
         packet.free(p)
      end
   end

   -- Synchronize next hop
   if self.synchronize and self.sync_interval() then
      self:sync_nexthop()
   end
end

NextHop6.encapsulate = NextHop4.encapsulate

-- Send periodic unsolicited NA? Only connect to
-- solicited NA? Update via NA/NS once we got a solicited NA? Send unsolicited
-- NA on start?
function NextHop6:handle_nd (p)
   local data, length = p.data, p.length

   local eth = assert(self.eth_in:new_from_mem(data, length))
   data, length = data + eth:sizeof(), length - eth:sizeof()

   local ip = assert(self.ip_in:new_from_mem(data, length))
   data, length = data + ip:sizeof(), length - ip:sizeof()

   if ip:hop_limit() ~= 255 then
      -- Mitigate off-link spoofing as per RFC4861
      counter.add(self.shm.nd_errors)
      return
   end

   local icmp = assert(self.icmp_in:new_from_mem(data, length))
   data, length = data + icmp:sizeof(), length - icmp:sizeof()

   if not icmp:checksum_check(data, length, ip) then
      counter.add(self.shm.nd_errors)
      return
   end
   if icmp:code() ~= 0 then
      counter.add(self.shm.nd_errors)
      return
   end

   local function add_or_update_nexthop (lladdr)
      self.eth:dst(lladdr)
      if self.synchronize then self:share_nexthop() end
      if self.connected then counter.add(self.shm.addresses_updated)
      else counter.add(self.shm.addresses_added) end
      self.connected = true
   end

   -- Incoming neighbor solicitation
   if icmp:type() == 135 then
      local ns = self.ns_in:new_from_mem(data, length)
      if not ns then
         counter.add(self.shm.nd_errors)
         return
      end
      -- If the sender is our target nexthop, try to add or update its address
      -- using the “Source Link-Layer Address” option, if present.
      if ip:src_eq(self.nexthop_ip6) then
         data, length = data + ns:sizeof(), length - ns:sizeof()
         for _, tlv in ipairs(ns:options(data, length)) do
            if tlv:type() == 1 then -- Source Link-Layer Address
               add_or_update_nexthop(tlv:option():addr())
               break
            end
         end
      end
      -- If we are the target of the solicitation, reply with an advertisement.
      if ns:target_eq(self.node_ip6) then
         self.na_reply.eth:dst(eth:src())
         self.na_reply.ip:dst(ip:src())
         return packet.clone(self.na_reply.p)
      end

   -- Incoming neighbor advertisement
   elseif icmp:type() == 136 then
      local na = self.na_in:new_from_mem(data, length)
      if not na then         
         counter.add(self.shm.nd_errors)
         return
      end
      -- If the advertisement’s target our nexthop, try to add or update its
      -- address using the “Target Link-Layer Address” option, if present.
      if na:target_eq(self.nexthop_ip6) then
         data, length = data + na:sizeof(), length - na:sizeof()
         for _, tlv in ipairs(na:options(data, length)) do
            if tlv:type() == 2 then -- Target Link-Layer Address
               add_or_update_nexthop(tlv:option():addr())
               break
            end
         end
      end

   else
      counter.add(self.shm.nd_errors)
   end
end

NextHop6.shared_nexthop_path = NextHop4.shared_nexthop_path
NextHop6.share_nexthop = NextHop4.share_nexthop
NextHop6.sync_nexthop = NextHop4.sync_nexthop
