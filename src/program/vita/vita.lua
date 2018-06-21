-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

local lib = require("core.lib")
local shm = require("core.shm")
local worker = require("core.worker")
local dispatch = require("program.vita.dispatch")
local ttl = require("program.vita.ttl")
local route = require("program.vita.route")
local tunnel = require("program.vita.tunnel")
local nexthop = require("program.vita.nexthop")
local exchange = require("program.vita.exchange")
local icmp = require("program.vita.icmp")
      schemata = require("program.vita.schemata")
local interlink = require("lib.interlink")
local Receiver = require("apps.interlink.receiver")
local Transmitter = require("apps.interlink.transmitter")
local intel_mp = require("apps.intel_mp.intel_mp")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local numa = require("lib.numa")
local yang = require("lib.yang.yang")
local pci = require("lib.hardware.pci")
local S = require("syscall")
local ffi = require("ffi")
local usage = require("program.vita.README_inc")
local confighelp = require("program.vita.README_config_inc")

local confspec = {
   private_interface = {required=true},
   public_interface = {required=true},
   mtu = {default=8937},
   route = {required=true},
   negotiation_ttl = {},
   sa_ttl = {}
}

local ifspec = {
   pci = {required=true},
   ip4 = {required=true},
   nexthop_ip4 = {required=true},
   mac = {},
   nexthop_mac = {}
}

local function derive_local_unicast_mac (prefix, ip4)
   local mac = ffi.new("uint8_t[?]", 6)
   mac[0] = prefix[1]
   mac[1] = prefix[2]
   ffi.copy(mac+2, ipv4:pton(ip4), 4)
   -- First bit = 0 indicates unicast, second bit = 1 means locally
   -- administered.
   assert(bit.band(bit.bor(prefix[1], 0x02), 0xFE) == prefix[1],
          "Non-unicast or non-local MAC address: "..ethernet:ntop(mac))
   return ethernet:ntop(mac)
end

local function parse_ifconf (conf, mac_prefix)
   conf = lib.parse(conf, ifspec)
   conf.mac = conf.mac or derive_local_unicast_mac(mac_prefix, conf.ip4)
   return conf
end

local function parse_conf (conf)
   conf = lib.parse(conf, confspec)
   conf.private_interface = parse_ifconf(conf.private_interface, {0x2a, 0xbb})
   conf.public_interface = parse_ifconf(conf.public_interface, {0x3a, 0xbb})
   return conf
end

local esp_keyfile = "group/esp_ephemeral_keys"
local dsp_keyfile = "group/dsp_ephemeral_keys"

function run (args)
   io.stdout:setvbuf("line")
   io.stderr:setvbuf("line")

   local long_opt = {
      help = "h",
      ["config-help"] = "H",
      ["config-test"] = "t",
      cpu = "c"
   }

   local opt = {}
   local conftest = false
   local cpus = {}

   local function exit_usage (status) print(usage) main.exit(status) end

   function opt.h () exit_usage(0) end

   function opt.H () print(confighelp) main.exit(0) end

   function opt.t () conftest = true end

   function opt.c (arg) cpus = cpuset(arg) end

   args = lib.dogetopt(args, opt, "hHtc:m:", long_opt)

   if #args ~= 1 then exit_usage(1) end
   local confpath = args[1]

   if conftest then
      local success, error = pcall(
         load_config, schemata['esp-gateway'], confpath
      )
      if success then main.exit(0)
      else print(error) main.exit(1) end
   end

   -- “link” with worker processes
   worker.set_exit_on_worker_death(true)

   -- start private and public router processes
   worker.start(
      "PrivatePort",
      ([[require("program.vita.vita").private_port_worker(%q, %s)]])
         :format(confpath, cpus[2])
   )
   worker.start(
      "PublicPort",
      ([[require("program.vita.vita").public_port_worker(%q, %s)]])
         :format(confpath, cpus[3])
   )

   -- start crypto processes
   worker.start("ESP", ([[require("program.vita.vita").esp_worker(%s)]])
                   :format(cpus[4]))
   worker.start("DSP", ([[require("program.vita.vita").dsp_worker(%s)]])
                   :format(cpus[5]))

   -- become key exchange protocol handler process
   exchange_worker(confpath, cpus[1])
end

function configure_private_router (conf, append)
   conf = parse_conf(conf)
   local c = append or config.new()

   config.app(c, "PrivateDispatch", dispatch.PrivateDispatch, {
                 node_ip4 = conf.private_interface.ip4
   })
   config.app(c, "OutboundTTL", ttl.DecrementTTL)
   config.app(c, "PrivateRouter", route.PrivateRouter, {
                 routes = conf.route,
                 mtu = conf.mtu
   })
   config.app(c, "PrivateICMP4", icmp.ICMP4, {
                 node_ip4 = conf.private_interface.ip4,
                 nexthop_mtu = conf.mtu
   })
   config.app(c, "InboundDispatch", dispatch.InboundDispatch, {
                 node_ip4 = conf.private_interface.ip4
   })
   config.app(c, "InboundTTL", ttl.DecrementTTL)
   config.app(c, "InboundICMP4", icmp.ICMP4, {
                 node_ip4 = conf.private_interface.ip4
   })
   config.app(c, "PrivateNextHop", nexthop.NextHop4, {
                 node_mac = conf.private_interface.mac,
                 node_ip4 = conf.private_interface.ip4,
                 nexthop_ip4 = conf.private_interface.nexthop_ip4,
                 nexthop_mac = conf.private_interface.nexthop_mac
   })
   config.link(c, "PrivateDispatch.forward4 -> OutboundTTL.input")
   config.link(c, "PrivateDispatch.icmp4 -> PrivateICMP4.input")
   config.link(c, "PrivateDispatch.arp -> PrivateNextHop.arp")
   config.link(c, "PrivateDispatch.protocol4_unreachable -> PrivateICMP4.protocol_unreachable")
   config.link(c, "OutboundTTL.output -> PrivateRouter.input")
   config.link(c, "OutboundTTL.time_exceeded -> PrivateICMP4.transit_ttl_exceeded")
   config.link(c, "PrivateRouter.fragmentation_needed -> PrivateICMP4.fragmentation_needed")
   config.link(c, "PrivateICMP4.output -> PrivateNextHop.icmp4")
   config.link(c, "InboundDispatch.forward4 -> InboundTTL.input")
   config.link(c, "InboundDispatch.icmp4 -> InboundICMP4.input")
   config.link(c, "InboundDispatch.protocol4_unreachable -> InboundICMP4.protocol_unreachable")
   config.link(c, "InboundTTL.output -> PrivateNextHop.forward")
   config.link(c, "InboundTTL.time_exceeded -> InboundICMP4.transit_ttl_exceeded")
   config.link(c, "InboundICMP4.output -> PrivateRouter.control")

   for id, route in pairs(conf.route) do
      local private_in = "PrivateRouter."..id
      local ESP_in = "ESP_"..id.."_in"
      config.app(c, ESP_in, Transmitter)
      config.link(c, private_in.." -> "..ESP_in..".input")

      local private_out = "InboundDispatch."..id
      local DSP_out = "DSP_"..id.."_out"
      config.app(c, DSP_out, Receiver)
      config.link(c, DSP_out..".output -> "..private_out)
   end

   local private_links = {
      input = "PrivateDispatch.input",
      output = "PrivateNextHop.output"
   }
   return c, private_links
end

function configure_public_router (conf, append)
   conf = parse_conf(conf)
   local c = append or config.new()

   config.app(c, "PublicDispatch", dispatch.PublicDispatch, {
                 node_ip4 = conf.public_interface.ip4
   })
   config.app(c, "PublicRouter", route.PublicRouter, {
                 routes = conf.route
   })
   config.app(c, "PublicICMP4", icmp.ICMP4, {
                 node_ip4 = conf.public_interface.ip4
   })
   config.app(c, "PublicNextHop", nexthop.NextHop4, {
                 node_mac = conf.public_interface.mac,
                 node_ip4 = conf.public_interface.ip4,
                 nexthop_ip4 = conf.public_interface.nexthop_ip4,
                 nexthop_mac = conf.public_interface.nexthop_mac
   })
   config.link(c, "PublicDispatch.forward4 -> PublicRouter.input")
   config.link(c, "PublicDispatch.icmp4 -> PublicICMP4.input")
   config.link(c, "PublicDispatch.arp -> PublicNextHop.arp")
   config.link(c, "PublicDispatch.protocol4_unreachable -> PublicICMP4.protocol_unreachable")
   config.link(c, "PublicICMP4.output -> PublicNextHop.icmp4")

   config.app(c, "Protocol_in", Transmitter)
   config.app(c, "Protocol_out", Receiver)
   config.link(c, "PublicDispatch.protocol -> Protocol_in.input")
   config.link(c, "Protocol_out.output -> PublicNextHop.protocol")

   for id, route in pairs(conf.route) do
      local public_in = "PublicRouter."..id
      local DSP_in = "DSP_"..id.."_in"
      config.app(c, DSP_in, Transmitter)
      config.link(c, public_in.." -> "..DSP_in..".input")

      local public_out = "PublicNextHop."..id
      local ESP_out = "ESP_"..id.."_out"
      local Tunnel = "Tunnel_"..id
      config.app(c, ESP_out, Receiver)
      config.app(c, Tunnel, tunnel.Tunnel4,
                 {src=conf.public_interface.ip4, dst=route.gw_ip4})
      config.link(c, ESP_out..".output -> "..Tunnel..".input")
      config.link(c, Tunnel..".output -> "..public_out)
   end

   local public_links = {
      input = "PublicDispatch.input",
      output = "PublicNextHop.output"
   }

   return c, public_links
end

local function nic_config (conf, interface)
   numa.check_affinity_for_pci_addresses({conf[interface].pci})
   local needs_vmdq = pci.canonical(conf.private_interface.pci)
                   == pci.canonical(conf.public_interface.pci)
   return {
      pciaddr = conf[interface].pci,
      vmdq = needs_vmdq,
      macaddr = needs_vmdq and conf[interface].mac
   }
end

function configure_private_router_with_nic (conf, append)
   conf = parse_conf(conf)

   local c, private =
      configure_private_router(conf, append or config.new())

   config.app(c, "PrivateNIC", intel_mp.Intel,
              nic_config(conf, 'private_interface'))
   config.link(c, "PrivateNIC.output -> "..private.input)
   config.link(c, private.output.." -> PrivateNIC.input")

   return c
end

function configure_public_router_with_nic (conf, append)
   conf = parse_conf(conf)

   local c, public =
      configure_public_router(conf, append or config.new())

   config.app(c, "PublicNIC", intel_mp.Intel,
              nic_config(conf, 'public_interface'))
   config.link(c, "PublicNIC.output -> "..public.input)
   config.link(c, public.output.." -> PublicNIC.input")

   return c
end

function private_port_worker (confpath, cpu)
   numa.bind_to_cpu(cpu)
   engine.log = true
   listen_confpath(
      schemata['esp-gateway'],
      confpath,
      configure_private_router_with_nic
   )
end

function public_port_worker (confpath, cpu)
   numa.bind_to_cpu(cpu)
   engine.log = true
   listen_confpath(
      schemata['esp-gateway'],
      confpath,
      configure_public_router_with_nic
   )
end

function public_router_loopback_worker (confpath, cpu)
   local function configure_public_router_loopback (conf)
      local c, public = configure_public_router(conf)
      config.link(c, public.output.." -> "..public.input)
      return c
   end
   numa.bind_to_cpu(cpu)
   engine.log = true
   listen_confpath(
      schemata['esp-gateway'],
      confpath,
      configure_public_router_loopback
   )
end

function configure_exchange (conf, append)
   conf = parse_conf(conf)
   local c = append or config.new()

   config.app(c, "KeyExchange", exchange.KeyManager, {
                 node_ip4 = conf.public_interface.ip4,
                 routes = conf.route,
                 esp_keyfile = esp_keyfile,
                 dsp_keyfile = dsp_keyfile,
                 negotiation_ttl = conf.negotiation_ttl,
                 sa_ttl = conf.sa_ttl
   })
   config.app(c, "Protocol_in", Receiver)
   config.app(c, "Protocol_out", Transmitter)
   config.link(c, "Protocol_in.output -> KeyExchange.input")
   config.link(c, "KeyExchange.output -> Protocol_out.input")

   return c
end

function exchange_worker (confpath, cpu)
   numa.bind_to_cpu(cpu)
   engine.log = true
   listen_confpath(schemata['esp-gateway'], confpath, configure_exchange)
end


-- ephemeral_keys := { <id>=(SA), ... }                        (see exchange)

function configure_esp (ephemeral_keys, append)
   local c = append or config.new()

   for id, sa in pairs(ephemeral_keys.sa) do
      -- Configure interlink receiver/transmitter for inbound SA
      local ESP_in = "ESP_"..id.."_in"
      local ESP_out = "ESP_"..id.."_out"
      config.app(c, ESP_in, Receiver)
      config.app(c, ESP_out, Transmitter)
      -- Configure inbound SA
      local ESP = "ESP_"..id
      config.app(c, ESP, tunnel.Encapsulate, sa)
      config.link(c, ESP_in..".output -> "..ESP..".input4")
      config.link(c, ESP..".output -> "..ESP_out..".input")
   end

   return c
end

function configure_dsp (ephemeral_keys, append)
   local c = append or config.new()

   for id, sa in pairs(ephemeral_keys.sa) do
      -- Configure interlink receiver/transmitter for outbound SA
      local DSP_in = "DSP_"..id.."_in"
      local DSP_out = "DSP_"..id.."_out"
      config.app(c, DSP_in, Receiver)
      config.app(c, DSP_out, Transmitter)
      -- Configure outbound SA
      local DSP = "DSP_"..id
      config.app(c, DSP, tunnel.Decapsulate, sa)
      config.link(c, DSP_in..".output -> "..DSP..".input")
      config.link(c, DSP..".output4 -> "..DSP_out..".input")
   end

   return c
end

function esp_worker (cpu)
   numa.bind_to_cpu(cpu)
   engine.log = true
   listen_confpath(
      schemata['ephemeral-keys'],
      shm.root.."/"..shm.resolve(esp_keyfile),
      configure_esp
   )
end

function dsp_worker (cpu)
   numa.bind_to_cpu(cpu)
   engine.log = true
   listen_confpath(
      schemata['ephemeral-keys'],
      shm.root.."/"..shm.resolve(dsp_keyfile),
      configure_dsp
   )
end

function load_config (schema, confpath)
   return yang.load_config_for_schema(
      schema, lib.readfile(confpath, "a*"), confpath
   )
end

function save_config (schema, confpath, conf)
   local f = assert(io.open(confpath, "w"), "Unable to open file: "..confpath)
   yang.print_config_for_schema(schema, conf, f)
   f:close()
end

function listen_confpath (schema, confpath, loader, interval)
   interval = interval or 1e9

   local notify_fd = assert(S.inotify_init("cloexec, nonblock"))
   local conf_fd
   local needs_reconfigure = true
   local function check_reconfigure ()
      if not conf_fd then
         conf_fd = notify_fd:inotify_add_watch(confpath, "close_write")
         needs_reconfigure = needs_reconfigure or conf_fd
      else
         local events, err = notify_fd:inotify_read()
         needs_reconfigure = not (err and assert(err.again)) and #events >= 1
      end
   end
   timer.activate(timer.new("check-for-reconfigure",
                            check_reconfigure,
                            interval,
                            "repeating"))

   local function run_loader ()
      return loader(load_config(schema, confpath))
   end

   while true do
      needs_reconfigure = false
      local success, c = pcall(run_loader)
      if success then
         print("Reconfigure: loaded "..confpath)
         engine.configure(c)
      else
         print("Reconfigure: error: "..c)
      end
      engine.main({
         done = function() return needs_reconfigure end,
         no_report = true
      })
   end
end

-- Parse CPU set from string.
function cpuset (s)
   local cpus = {}
   for cpu in s:gmatch('%s*([0-9]+),*') do
      table.insert(cpus, assert(tonumber(cpu), "Not a valid CPU id: " .. cpu))
   end
   return cpus
end
