-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(..., package.seeall)

local ethernet= require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local datagram = require("lib.protocol.datagram")
local lib = require("core.lib")

-- Test case generation for Vita via synthetic traffic and configurations.
-- Exposes configuration knobs like “number of routes” and “packet size”.
--
-- Produces a set of test packets and a matching vita-esp-gateway configuration
-- in loopback mode by default. I.e., potentially many routes to a single
-- destination.

defaults = {
   private_interface = {},
   public_interface = {},
   route_prefix = {default="172.16"},
   nroutes = {default=1},
   packet_size = {default="IMIX"}
}
private_interface_defaults = {
   pci = {default="00:00.0"},
   mac = {default="02:00:00:00:00:01"}, -- needed because used in sim. packets
   ip4 = {default="172.16.1.10"},
   nexthop_ip4 = {default="172.16.1.1"},
   nexthop_mac = {}
}
public_interface_defaults = {
   pci = {default="00:00.0"},
   mac = {},
   ip4 = {default="172.16.1.10"},
   nexthop_ip4 = {default="172.16.1.10"},
   nexthop_mac = {}
}

traffic_templates = {
   -- Internet Mix, see https://en.wikipedia.org/wiki/Internet_Mix
   IMIX = { 54, 54, 54, 54, 54, 54, 54, 590, 590, 590, 590, 1514 }
}

function gen_packet (conf, route, size)
   local payload_size = size - ethernet:sizeof() - ipv4:sizeof()
   assert(payload_size >= 0, "Negative payload_size :-(")
   local d = datagram:new(packet.resize(packet.allocate(), payload_size))
   d:push(ipv4:new{ src = ipv4:pton(conf.private_interface.nexthop_ip4),
                    dst = ipv4:pton(conf.route_prefix.."."..route..".1"),
                    total_length = ipv4:sizeof() + payload_size,
                    ttl = 64 })
   d:push(ethernet:new{ dst = ethernet:pton(conf.private_interface.mac),
                        type = 0x0800 })
   local p = d:packet()
   -- Pad to minimum Ethernet frame size (excluding four octet CRC)
   return packet.resize(p, math.max(60, p.length))
end

function gen_packets (conf)
   local sim_packets = {}
   local sizes = traffic_templates[conf.packet_size]
              or {tonumber(conf.packet_size)}
   for _, size in ipairs(sizes) do
      for route = 1, conf.nroutes do
         table.insert(sim_packets, gen_packet(conf, route, size))
      end
   end
   return sim_packets
end

function gen_cfg (conf)
   local cfg = {
      private_interface = conf.private_interface,
      public_interface = conf.public_interface,
      route = {},
      negotiation_ttl = conf.nroutes
   }
   for route = 1, conf.nroutes do
      cfg.route["test"..route] = {
         net_cidr4 = conf.route_prefix.."."..route..".0/24",
         gw_ip4 = conf.public_interface.nexthop_ip4,
         preshared_key = string.rep("00", 32),
         spi = 1000+route
      }
   end
   return cfg
end

-- Return test configuration and simulation packets according to conf
function gen_testcase (conf)
   conf = lib.parse(conf, defaults)
   conf.private_interface = lib.parse(conf.private_interface,
                                      private_interface_defaults)
   conf.public_interface = lib.parse(conf.public_interface,
                                     public_interface_defaults)
   assert(conf.nroutes >= 0 and conf.nroutes <= 255,
          "Invalid number of routes: "..conf.nroutes)
   return gen_cfg(conf), gen_packets(conf)
end
