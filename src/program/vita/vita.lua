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
local basic_apps = require("apps.basic.basic_apps")
local intel_mp = require("apps.intel_mp.intel_mp")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local numa = require("lib.numa")
local yang = require("lib.yang.yang")
local ptree = require("lib.ptree.ptree")
local CPUSet = require("lib.cpuset")
local pci = require("lib.hardware.pci")
local S = require("syscall")
local ffi = require("ffi")
local usage = require("program.vita.README_inc")
local confighelp = require("program.vita.README_config_inc")

local confspec = {
   private_interface = {},
   public_interface = {default={}},
   mtu = {default=8937},
   route = {default={}},
   negotiation_ttl = {},
   sa_ttl = {},
   data_plane = {},
   sa_database = {default={}}
}

local ifspec = {
   pci = {required=true},
   ip4 = {required=true},
   nexthop_ip4 = {required=true},
   mac = {},
   nexthop_mac = {},
   queue = {}
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
   if not conf then return end
   conf = lib.parse(conf, ifspec)
   conf.mac = conf.mac or derive_local_unicast_mac(mac_prefix, conf.ip4)
   return conf
end

-- This takes a Vita configuration (potentially defining multiple queues) and a
-- queue id and returns the configuration for a single given queue by mutating
-- a copy of the configuration.
local function parse_conf (conf, queue)
   conf = lib.parse(lib.deepcopy(conf), confspec)
   conf.queue = queue
   -- all queues share a single private interface
   conf.private_interface = parse_ifconf(conf.private_interface, {0x2a, 0xbb})
   -- select the public interface for the queue from the public interface list
   -- (it is possible that no such interface is configured)
   local public_interfaces = conf.public_interface
   conf.public_interface = nil
   for ip4, interface in pairs(public_interfaces) do
      interface.ip4 = ip4
      local interface = parse_ifconf(interface, {0x3a, 0xbb})
      if interface.queue == conf.queue then
         conf.public_interface = interface
         break
      end
   end
   -- for each route, select a single gateway ip to use for this queue
   for id, route in pairs(conf.route) do
      local gateways = route.gateway
      route.gateway = nil
      for ip4, gateway in pairs(gateways) do
         if gateway.queue == 1 then -- default to the first defined gateway
            route.gw_ip4 = ip4
         end
         if gateway.queue == conf.queue then
            route.gw_ip4 = ip4
            break
         end
      end
   end
   -- select the SAs configured for this queue, default to empty SA lists
   conf.outbound_sa = {}
   conf.inbound_sa = {}
   local sa_database = conf.sa_database
   conf.sa_database = nil
   for queue, sa_db in pairs(sa_database) do
      if queue == conf.queue then
         conf.outbound_sa = sa_db.outbound_sa
         conf.inbound_sa = sa_db.inbound_sa
         break
      end
   end
   return conf
end

local sa_db_path = "group/sa_db"

function init_sa_db ()
   shm.mkdir(shm.resolve(sa_db_path))
end

-- Vita command-line interface (CLI)
function run (args)
   local long_opt = {
      help = "h",
      ["config-help"] = "H",
      name = "n",
      cpu = "c",
      busywait = "b",
      realtime = "r",
   }

   local opt = {}

   local function exit_usage (status) print(usage) main.exit(status) end

   function opt.h () exit_usage(0) end

   function opt.H () print(confighelp) main.exit(0) end

   local cpuset
   function opt.c (arg) cpuset = CPUSet:new():add_from_string(arg) end

   local name
   function opt.n (arg) name = arg end

   local busywait, realtime
   function opt.b () busywait = true end
   function opt.r () realtime = true end

   args = lib.dogetopt(args, opt, "hHn:c:br", long_opt)

   if #args > 0 then exit_usage(1) end
   run_vita{name=name, cpuset=cpuset, busywait=busywait, realtime=realtime}
end

-- Vita runs as a process tree that reconfigures itself at runtime based on key
-- exchange and expiration. The key manager maintains a current SA database in
-- sa_db_path (relative to the process group) which is polled and applied by
-- the supervisor. NB: naturally, the SA database must not affect key manager
-- configuration.
-- This function does not halt except for fatal error situations.
function run_vita (opt)
   init_sa_db()

   -- Schema support: because Vita configurations are generally shallow we
   -- choose to reliably delegate all configuration transitions to core.app by
   -- making sure that setup_fn receives a fresh configuration every time it is
   -- called.
   local schema_support = {
      compute_config_actions = function(old_graph, new_graph)
         local actions = engine.compute_config_actions(old_graph, new_graph)
         table.insert(actions, {'commit', {}})
         return actions
      end,
      update_mutable_objects_embedded_in_app_initargs = function () end,
      compute_apps_to_restart_after_configuration_update = function () end,
      compute_state_reader = schemata.support.compute_state_reader,
      configuration_for_worker = schemata.support.configuration_for_worker,
      process_states = schemata.support.process_states,
      translators = {}
   }
   local function purify (setup_fn)
      return function (new_conf)
         return setup_fn(lib.deepcopy(new_conf))
      end
   end

   -- Setup supervisor
   local supervisor = ptree.new_manager{
      name = opt.name,
      schema_name = 'vita-esp-gateway',
      schema_support = schema_support,
      initial_configuration = opt.initial_configuration or {},
      setup_fn = purify(opt.setup_fn or vita_workers),
      cpuset = opt.cpuset,
      worker_default_scheduling = {busywait=opt.busywait or false,
                                   real_time=opt.realtime or false},
      worker_jit_flush = false
   }

   local function absolute_sa_db_path (queue)
      return shm.root.."/"..shm.resolve(sa_db_path)
   end

   -- Listen for SA database changes.
   local sa_db_last_modified = {}
   local function sa_db_needs_reload ()
      local modified = false
      for _, queue in ipairs(shm.children(sa_db_path)) do
         queue = tonumber(queue)
         if queue then -- ignore temp files
            local stat = S.stat(absolute_sa_db_path().."/"..queue)
            if stat and stat.st_mtime ~= sa_db_last_modified[queue] then
               sa_db_last_modified[queue] = stat.st_mtime
               modified = true
            end
         end
      end
      return modified
   end

   -- Load current SA database.
   local function load_sa_db ()
      local sa_db = {}
      for _, queue in ipairs(shm.children(sa_db_path)) do
         queue = tonumber(queue)
         if queue then -- ignore temp files
            sa_db[queue] = yang.load_configuration(
               absolute_sa_db_path().."/"..queue,
               {schema_name='vita-ephemeral-keys'}
            )
         end
      end
      return sa_db
   end

   -- This is how we imperatively incorporate the SA database into the
   -- configuration proper. NB: see schema_support and the use of purify above.
   local function merge_sa_db (sa_db)
      return function (current_config)
         current_config.sa_database = sa_db
         return current_config
      end
   end

   -- Ensure I/O is line-buffered.
   io.stdout:setvbuf("line")
   io.stderr:setvbuf("line")

   -- Ensure exit on worker failure (while we lack proper process supervision.)
   worker.set_exit_on_worker_death(true)

   -- Run the supervisor while keeping up to date with SA database changes.
   while true do
      supervisor:main(1)
      if sa_db_needs_reload() then
         supervisor:info("Reloading SA database: %s", sa_db_path)
         supervisor:update_configuration(merge_sa_db(load_sa_db()), 'set', '/')
      end
   end
end

function vita_workers (conf)
   local workers = {}
   -- Provision a dedicated process/queue for each address of the public
   -- interface.
   for _, interface in pairs(conf.public_interface or {}) do
      local name = "queue"..interface.queue
      workers[name] = configure_vita_queue(conf, interface.queue)
   end
   return workers
end

function configure_vita_queue (conf, queue)
   conf = parse_conf(conf, queue)

   local c = config.new()
   local _, key_manager = configure_exchange(conf, c)
   local _, private_router = configure_private_router(conf, c)
   local _, public_router = configure_public_router(conf, c)
   local _, outbound_sa = configure_outbound_sa(conf, c)
   local _, inbound_sa = configure_inbound_sa(conf, c)
   local _, interfaces = configure_interfaces(conf, c)

   local function link (from, to) config.link(c, from.." -> "..to) end

   if conf.data_plane then
      config.app(c, "Null", basic_apps.Sink)
      link(public_router.protocol_input, "Null.input")
   else
      link(public_router.protocol_input, key_manager.input)
      link(key_manager.output, public_router.protocol_output)
   end

   if interfaces.private then
      link(interfaces.private.rx, private_router.input)
      link(private_router.output, interfaces.private.tx)
   end
   if interfaces.public then
      link(interfaces.public.rx, public_router.input)
      link(public_router.output, interfaces.public.tx)
   end

   for _, sa in pairs(conf.outbound_sa) do
      link(private_router.outbound[sa.route], outbound_sa.input[sa.route])
      link(outbound_sa.output[sa.route], public_router.outbound[sa.route])
   end
   for spi, sa in pairs(conf.inbound_sa) do
      local id = sa.route.."_"..spi
      link(public_router.inbound[id], inbound_sa.input[id])
      link(inbound_sa.output[id], private_router.inbound[id])
   end

   return c, private_router, public_router
end

function configure_interfaces (conf, append)
   local c = append or config.new()

   local ports = {
      private = nil, -- private interface receive/transmit
      public = nil -- punlic interface receive/transmit
   }

   if conf.private_interface and conf.private_interface.pci ~= "00:00.0" then
      config.app(c, "PrivateNIC", intel_mp.Intel, {
                    pciaddr = conf.private_interface.pci,
                    rxq = conf.queue - 1,
                    txq = conf.queue - 1
      })
      ports.private = {
         rx = "PrivateNIC.output",
         tx = "PrivateNIC.input"
      }
   end

   if conf.public_interface and conf.public_interface.pci ~= "00:00.0" then
      config.app(c, "PublicNIC", intel_mp.Intel, {
                    pciaddr = conf.public_interface.pci,
                    macaddr = conf.public_interface.mac,
                    vmdq = true
      })
      ports.public = {
         rx = "PublicNIC.output",
         tx = "PublicNIC.input"
      }
   end

   return c, ports
end

function configure_private_router (conf, append)
   local c = append or config.new()

   local ports = {
      input = nil, -- private input
      output = nil, -- private output
      outbound = {}, -- outbound SA queues (to encapsulate)
      inbound = {} -- inbound SA queues (decapsulated)
   }

   if not conf.private_interface then return c, ports end

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
                 nexthop_mac = conf.private_interface.nexthop_mac,
                 synchronize = true
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

   ports.input = "PrivateDispatch.input"
   ports.output = "PrivateNextHop.output"

   for id, route in pairs(conf.route) do
      ports.outbound[id] = "PrivateRouter."..id
   end

   for spi, sa in pairs(conf.inbound_sa) do
      local id = sa.route.."_"..spi
      ports.inbound[id] = "InboundDispatch."..id
   end

   return c, ports
end

function configure_public_router (conf, append)
   local c = append or config.new()

   local ports = {
      input = nil, -- public router input
      output = nil, -- public router output
      protocol_input = nil, -- incoming key exchange messages
      protocol_output = nil, -- outgoing key exchange messages
      inbound = {}, -- inbound SA queues (to be decapsulated)
      outbound = {} -- outbound SA queues (encapsulated)
   }

   if not conf.public_interface then return c, ports end

   config.app(c, "PublicDispatch", dispatch.PublicDispatch, {
                 node_ip4 = conf.public_interface.ip4
   })
   config.app(c, "PublicRouter", route.PublicRouter, {
                 sa = conf.inbound_sa
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

   ports.input = "PublicDispatch.input"
   ports.output = "PublicNextHop.output"

   ports.protocol_input = "PublicDispatch.protocol"
   ports.protocol_output = "PublicNextHop.protocol"

   for id, route in pairs(conf.route) do
      local Tunnel = "Tunnel_"..id
      config.app(c, Tunnel, tunnel.Tunnel4, {
                    src = conf.public_interface.ip4,
                    dst = route.gw_ip4
      })
      config.link(c, Tunnel..".output -> PublicNextHop."..id)
      ports.outbound[id] = Tunnel..".input"
   end

   for spi, sa in pairs(conf.inbound_sa) do
      local id = sa.route.."_"..spi
      ports.inbound[id] = "PublicRouter."..id
   end

   return c, ports
end

function configure_exchange (conf, append)
   local c = append or config.new()

   local ports = {
      input = nil, -- key exchange input
      output = nil, -- key exchange output
   }

   if conf.data_plane or not conf.public_interface then return c, ports end

   config.app(c, "KeyManager", exchange.KeyManager, {
                 node_ip4 = conf.public_interface.ip4,
                 routes = conf.route,
                 sa_db_path = sa_db_path.."/"..conf.queue,
                 negotiation_ttl = conf.negotiation_ttl,
                 sa_ttl = conf.sa_ttl
   })

   ports.input = "KeyManager.input"
   ports.output = "KeyManager.output"

   return c, ports
end

-- sa_db := { outbound_sa={<spi>=(SA), ...}, inbound_sa={<spi>=(SA), ...} }
-- (see exchange)

function configure_outbound_sa (sa_db, append)
   local c = append or config.new()

   local ports = { input={}, output={} } -- SA input/output pairs

   for spi, sa in pairs(sa_db.outbound_sa) do
      local OutboundSA = "OutboundSA_"..sa.route
      config.app(c, OutboundSA, tunnel.Encapsulate, {
                    spi = spi,
                    aead = sa.aead,
                    key = sa.key,
                    salt = sa.salt
      })
      ports.input[sa.route] = OutboundSA..".input4"
      ports.output[sa.route] = OutboundSA..".output"
   end

   return c, ports
end

function configure_inbound_sa (sa_db, append)
   local c = append or config.new()

   local ports = { input={}, output={} } -- SA input/output pairs

   for spi, sa in pairs(sa_db.inbound_sa) do
      local id = sa.route.."_"..spi
      -- Configure inbound SA
      local InboundSA = "InboundSA_"..id
      config.app(c, InboundSA, tunnel.Decapsulate, {
                    spi = spi,
                    aead = sa.aead,
                    key = sa.key,
                    salt = sa.salt,
                    auditing = true
      })
      ports.input[id] = InboundSA..".input"
      ports.output[id] = InboundSA..".output4"
   end

   return c, ports
end
