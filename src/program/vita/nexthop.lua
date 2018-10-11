-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

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
      nexthop_mac = {}
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
      print("forced")
      o.eth:dst(ethernet:pton(conf.nexthop_mac))
      o.connected = true
   end

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
