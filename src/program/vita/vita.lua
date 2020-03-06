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
local crypto = require("program.vita.crypto")
local pci = require("lib.hardware.pci")
local ethernet = require("lib.protocol.ethernet")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")
local murmur = require("lib.hash.murmur")
local yang = require("lib.yang.yang")
local data = require("lib.yang.data")
local cltable = require("lib.cltable")
local ptree = require("lib.ptree.ptree")
local CPUSet = require("lib.cpuset")
local mem_stream = require("lib.stream.mem")
local S = require("syscall")
local ffi = require("ffi")
local usage = require("program.vita.README_inc")
local confighelp = require("program.vita.README_config_inc")

local default_config = yang.load_config_for_schema_by_name(
   'vita-esp-gateway', mem_stream.open_input_string ''
)

local confspec = {
   is_first_queue = {},
   private_interface4 = {},
   private_interface6 = {},
   public_interface4 = {default={}},
   public_interface6 = {default={}},
   mtu = {default=default_config.mtu},
   tfc = {},
   route4 = {default={}},
   route6 = {default={}},
   protocol_port = {default=default_config.protocol_port},
   negotiation_ttl = {default=default_config.negotation_ttl},
   sa_ttl = {default=default_config.sa_ttl},
   data_plane = {},
   outbound_sa = {default=default_config.outbound_sa},
   inbound_sa = {default=default_config.inbound_sa}
}

local ifspec = {
   pci = {},
   ifname = {},
   ip = {},
   nexthop_ip = {},
   mac = {},
   nexthop_mac = {},
   queue = {}
}

local function derive_local_unicast_mac (prefix, ip)
   local mac = ffi.new("uint8_t[?]", 6)
   mac[0] = prefix[1]
   mac[1] = prefix[2]
   local ip4 = ipv4:pton(ip)
   if ip4 then
      ffi.copy(mac+2, ip4, 4)
   else
      local ip6 = ipv6:pton(ip)
      -- hash IPv6 address to obtain hopefully unique MAC suffix...
      local murmur32 = murmur.MurmurHash3_x86_32:new()
      ffi.copy(mac+2, murmur32:hash(ip6, ffi.sizeof(ip6)), 4)
   end
   -- First bit = 0 indicates unicast, second bit = 1 means locally
   -- administered.
   assert(bit.band(bit.bor(mac[0], 0x02), 0xFE) == mac[0],
          "Non-unicast or non-local MAC address: "..ethernet:ntop(mac))
   return ethernet:ntop(mac)
end

local function parse_ifconf (conf, mac_prefix)
   conf = lib.parse(conf, ifspec)
   conf.mac = conf.mac or derive_local_unicast_mac(mac_prefix, conf.ip)
   return conf
end

-- This takes a Vita configuration (potentially defining multiple queues) and a
-- queue id and returns the configuration for a single given queue by mutating
-- a copy of the configuration.
local function parse_queue_conf (conf, queue)
   conf = lib.parse(lib.deepcopy(conf), confspec)
   conf.queue = queue
   -- all queues share a single private interface
   if conf.private_interface4 then
      conf.private_interface4 = parse_ifconf(conf.private_interface4, {0x2a,0xbb})
   elseif conf.private_interface6 then
      conf.private_interface6 = parse_ifconf(conf.private_interface6, {0x2a,0xbb})
   end
   -- select the public interface for the queue from the public interface list
   -- (it is possible that no such interface is configured)
   local function select_public_interface (interfaces)
      for ip, interface in pairs(interfaces) do
         interface.ip = ip
         local interface = parse_ifconf(interface, {0x3a, 0xbb})
         if interface.queue == conf.queue then return interface end
      end
   end
   conf.public_interface4 = select_public_interface(conf.public_interface4)
   conf.public_interface6 = select_public_interface(conf.public_interface6)
   -- for each route, select a single gateway ip to use for this queue
   local function select_gateway (gateways)
      local default
      for ip, gateway in pairs(gateways) do
         if gateway.queue == conf.queue then return ip end
         -- default to the first defined gateway
         if not default or gateway.queue < gateways[default].queue then
            default = ip
         end
      end
      return default
   end
   for id, route in pairs(conf.route4) do
      route.gateway = select_gateway(route.gateway)
   end
   for id, route in pairs(conf.route6) do
      route.gateway = select_gateway(route.gateway)
   end
   -- select the SAs configured for this queue, default to empty SA lists
   local function select_sa (sa)
      local selected = {}
      for key, sa in cltable.pairs(sa) do
         if key.queue == conf.queue then
            selected[key.spi] = sa
            sa.queue = key.queue
         end
      end
      return selected
   end
   conf.outbound_sa = select_sa(conf.outbound_sa)
   conf.inbound_sa = select_sa(conf.inbound_sa)
   return conf
end

-- The SA database is maintained as one file per work queue, named after the
-- queue identifier. Each work queue maintains its own respective SPI space,
-- and atomically updates its SA database as a configuration in the format
-- described by the vita-ephemeral-keys YANG schema (see
-- vita-ephemeral-keys.yang).
--
-- The Vita supervisor periodically merges these SA database “shards” into the
-- vita-esp-gateway schema, quere each SA is keyed by SPI and queue identifier.

local sa_db_path = "group/sa_db"

function init_sa_db ()
   shm.mkdir(shm.resolve(sa_db_path))
end

function queue_sa_db (queue)
   return ("%s/queue%d"):format(sa_db_path, queue)
end

function iterate_sa_db ()
   local files = shm.children(sa_db_path)
   local sa_db = {}
   for _, name in ipairs(files) do
      local queue = name:match("^queue(%d+)$")
      if queue then sa_db[tonumber(queue)] = sa_db_path.."/"..name end
   end
   return pairs(sa_db)
end

-- Global XDP mode flag
local xdp_mode = false

-- Vita command-line interface (CLI)
function run (args)
   local long_opt = {
      help = "h",
      ["config-help"] = "H",
      name = "n",
      cpu = "c",
      busywait = "b",
      realtime = "r",
      keygen = "K",
      xdp = "X"
   }

   local opt = {}

   local function exit_usage (status) print(usage) main.exit(status) end

   function opt.h () exit_usage(0) end

   function opt.H () print(confighelp) main.exit(0) end

   local function keygen ()
      local len = 32
      local key = ffi.new("uint8_t[?]", len)
      crypto.random_bytes(key, len)
      return lib.hexdump(ffi.string(key, len))
   end

   function opt.K () print(keygen()) main.exit(0) end

   local cpuset
   function opt.c (arg) cpuset = CPUSet:new():add_from_string(arg) end

   local name
   function opt.n (arg) name = arg end

   local busywait, realtime
   function opt.b () busywait = true end
   function opt.r () realtime = true end

   function opt.X () xdp_mode = true end

   args = lib.dogetopt(args, opt, "hHn:c:brKX", long_opt)

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
   local supervisor -- forward declaration

   init_sa_db()

   -- Listen for SA database changes.
   local sa_db_last_modified = {}
   local function sa_db_needs_reload ()
      local modified = false
      for queue, db in iterate_sa_db() do
         local stat = S.stat(shm.path(db))
         if stat and stat.st_mtime ~= sa_db_last_modified[queue] then
            sa_db_last_modified[queue] = stat.st_mtime
            modified = true
         end
      end
      return modified
   end

   -- Load current SA database.
   local function load_sa_db ()
      local data_gmr =
         data.data_grammar_from_schema(schemata['esp-gateway'], true)
      local outbound_key =
         data.typeof(data_gmr.members['outbound-sa'].key_ctype)
      local inbound_key =
         data.typeof(data_gmr.members['inbound-sa'].key_ctype)
      local outbound_sa = cltable.new{key_type=outbound_key}
      local inbound_sa = cltable.new{key_type=inbound_key}
      for queue, db in iterate_sa_db() do
         local success, db = pcall(yang.load_configuration,
            shm.path(db), {schema_name='vita-ephemeral-keys'}
         )
         if success then
            for spi, sa in pairs(db.outbound_sa) do
               outbound_sa[outbound_key{spi=spi, queue=queue}] = sa
            end
            for spi, sa in pairs(db.inbound_sa) do
               inbound_sa[inbound_key{spi=spi, queue=queue}] = sa
            end
         else
            supervisor:warn("Failed to read SA DB for queue %d", queue)
         end
      end
      return {outbound_sa=outbound_sa, inbound_sa=inbound_sa}
   end

   -- This is how we imperatively incorporate the SA database into the
   -- configuration proper. NB: see schema_support and the use of purify below.
   local function merge_sa_db (sa_db)
      return function (current_config)
         current_config.outbound_sa = sa_db.outbound_sa
         current_config.inbound_sa = sa_db.inbound_sa
         return current_config
      end
   end

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
   supervisor = ptree.new_manager{
      name = opt.name,
      schema_name = 'vita-esp-gateway',
      schema_support = schema_support,
      initial_configuration = opt.initial_configuration or default_config,
      setup_fn = purify(opt.setup_fn or vita_workers),
      cpuset = opt.cpuset,
      worker_default_scheduling = {busywait=opt.busywait or false,
                                   real_time=opt.realtime or false,
                                   enable_xdp=xdp_mode and {}},
      worker_jit_flush = false
   }

   -- Patch supervisor:update_configuration to handle managed SA database case.
   supervisor.update_configuration_raw = supervisor.update_configuration
   function supervisor:update_configuration (update_fn, verb, path, ...)
      local function update (current_config, ...)
         if path == '/' then
            -- Attempt to set whole config.
            local new_config = update_fn(current_config, ...)
            if new_config.data_plane then
               -- SA database is unmanaged, accept updates to it as they are.
               return new_config
            else
               -- SA database is managed, ignore updates to it.
               supervisor:warn("Rejected changes to auto-managed SA database"..
                                  " (data-plane option is not set).")
               return merge_sa_db(current_config)(new_config)
            end
         elseif path:match("^/outbound%-sa") or
                path:match("^/inbound%-sa")
         then
            -- Attempt to update SA database.
            if current_config.data_plane then
               -- SA database is unmanaged, accept updates as they are.
               return update_fn(current_config, ...)
            else
               -- SA database is managed, reject updates.
               error("SA database is auto-managed"..
                        " (data-plane option is not set).")
            end
         else
            return update_fn(current_config, ...)
         end
      end
      supervisor:update_configuration_raw(update, verb, path, ...)
   end

   -- Ensure I/O is line-buffered.
   io.stdout:setvbuf("line")
   io.stderr:setvbuf("line")

   -- Run the supervisor while keeping up to date with SA database changes.
   while true do
      supervisor:main(1)
      -- Exit if a worker failed unexpectedly.
      local status = worker.status()
      for id, worker in pairs(supervisor.workers) do
         if not worker.shutting_down and not status[id].alive then
            supervisor:warn("Worker exited unexpectedly: %s", id)
            main.exit(status[id].status)
         end
      end
      -- React to SA database changes.
      if not supervisor.current_configuration.data_plane and
         sa_db_needs_reload()
      then
         supervisor:info("Reloading SA database: %s", sa_db_path)
         supervisor:update_configuration_raw(merge_sa_db(load_sa_db()), 'set', '/')
         -- (bypass patched supervisor:update_configuration)
      end
   end
end

function vita_workers (conf)
   local workers = {}
   -- Provision a dedicated process/queue for each address of the public
   -- interface.
   local public_interfaces = conf.public_interface4 or
                             conf.public_interface6 or
                             {}
   local first_queue
   for _, interface in pairs(public_interfaces) do
      first_queue = math.min(interface.queue, first_queue or interface.queue)
   end
   for _, interface in pairs(public_interfaces) do
      local name = "queue"..interface.queue
      conf.is_first_queue = (interface.queue == first_queue)
      workers[name] = configure_vita_queue(conf, interface.queue)
   end
   return workers
end

function configure_vita_queue (conf, queue, free_links)
   conf = parse_queue_conf(conf, queue)

   local c = config.new()
   local _, key_manager = configure_exchange(conf, c)
   local _, private_router = configure_private_router(conf, c)
   local _, public_router = configure_public_router(conf, c)
   local _, outbound_sa = configure_outbound_sa(conf, c)
   local _, inbound_sa = configure_inbound_sa(conf, c)
   local _, interfaces = configure_interfaces(conf, c)

   local function link (from, to) config.link(c, from.." -> "..to) end

   if not conf.data_plane then
      link(public_router.protocol_input, key_manager.input)
      link(key_manager.output, public_router.protocol_output)
   end

   if interfaces.private then
      link(interfaces.private.rx, private_router.input)
      link(private_router.output, interfaces.private.tx)
   elseif not free_links then
      config.app(c, "PrivateSink", basic_apps.Sink)
      link("PrivateSink.rx", private_router.input)
      link(private_router.output, "PrivateSink.tx")
   end
   if interfaces.public then
      link(interfaces.public.rx, public_router.input)
      link(public_router.output, interfaces.public.tx)
   elseif not free_links then
      config.app(c, "PublicSink", basic_apps.Sink)
      link("PublicSink.rx", public_router.input)
      link(public_router.output, "PublicSink.tx")
   end

   for route, port in pairs(private_router.outbound) do
      if outbound_sa.input[route] then
         link(port, outbound_sa.input[route])
      end
   end
   for route, port in pairs(public_router.outbound) do
      if outbound_sa.output[route] then
         link(outbound_sa.output[route], port)
      end
   end
   for spi, sa in pairs(conf.inbound_sa) do
      local id = sa.route.."_"..sa.queue.."_"..spi
      if public_router.inbound[id] and inbound_sa.input[id] then
         link(public_router.inbound[id], inbound_sa.input[id])
      end
      if inbound_sa.output[id] and private_router.inbound[id] then
         link(inbound_sa.output[id], private_router.inbound[id])
      end
   end

   return c, free_links and private_router, free_links and public_router
end

local function io_driver (spec)
   local info
   if spec.pci then
      info = pci.device_info(spec.pci)
   elseif spec.ifname then
      info = {driver='apps.xdp.xdp'}
   else
      info = {model='unknown'}
   end
   local driver = info.driver and require(info.driver)
   local conf = {}
   if info.driver == 'apps.intel_mp.intel_mp' then
      assert(not xdp_mode, "Can not use native driver in XDP mode. (--xdp)")
      if spec.mac then
         conf.pciaddr = spec.pci
         conf.macaddr = spec.mac
         conf.vmdq = true
      else
         local max_q = driver.byPciID[tonumber(info.device)].max_q
         assert(spec.queue <= max_q,
                info.model.." only supports up to "..max_q.." queues.")
         conf.pciaddr = spec.pci
         conf.txq = spec.queue - 1
         conf.rxq = spec.queue - 1
      end
   elseif info.driver == 'apps.intel_avf.intel_avf' then
      assert(not xdp_mode, "Can not use native driver in XDP mode. (--xdp)")
      assert(spec.mac or spec.queue <= 1,
             info.model.." only supports a single queue.")
      conf.pciaddr = spec.pci
   elseif info.driver == 'apps.xdp.xdp' then
      assert(xdp_mode, "Need to run vita with --xdp to enable XDP mode.")
      conf.ifname = spec.ifname
      conf.queue = spec.queue - 1
      -- XXX: we should test this configuration before shipping it to the
      -- data-plane.
   else
      error("Unsupported device: "..info.model)
   end
   return driver.driver, conf
end

function configure_interfaces (conf, append)
   local c = append or config.new()

   local ports = {
      private = nil, -- private interface receive/transmit
      public = nil -- public interface receive/transmit
   }

   local private_interface = conf.private_interface4 or conf.private_interface6
   if private_interface and private_interface.pci ~= "00:00.0" then
      config.app(c, "PrivateNIC", io_driver{ pci = private_interface.pci,
                                             ifname = private_interface.ifname,
                                             queue = conf.queue })
      ports.private = {
         rx = "PrivateNIC.output",
         tx = "PrivateNIC.input"
      }
   end

   local public_interface = conf.public_interface4 or conf.public_interface6
   if public_interface and public_interface.pci ~= "00:00.0" then
      config.app(c, "PublicNIC", io_driver{ pci = public_interface.pci,
                                            ifname = public_interface.ifname,
                                            queue = conf.queue })
      ports.public = {
         rx = "PublicNIC.output",
         tx = "PublicNIC.input"
      }
   end

   assert(private_interface.pci == "00:00.0" or
             public_interface.pci == "00:00.0" or
             not (private_interface.pci or public_interface.pci) or
             private_interface.pci ~= public_interface.pci,
          "Using the same PCI device for both interfaces is not supported.")

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

   local routes

   if conf.private_interface4 then
      routes = conf.route4
      config.app(c, "PrivateDispatch", dispatch.PrivateDispatch, {
                    node_ip4 = conf.private_interface4.ip
      })
      config.app(c, "OutboundTTL", ttl.DecrementTTL)
      config.app(c, "PrivateRouter", route.PrivateRouter, {
                    route4 = routes,
                    mtu = conf.mtu
      })
      config.app(c, "PrivateICMP4", icmp.ICMP4, {
                    node_ip4 = conf.private_interface4.ip,
                    nexthop_mtu = conf.mtu
      })
      config.app(c, "InboundDispatch", dispatch.InboundDispatch, {
                    node_ip4 = conf.private_interface4.ip
      })
      config.app(c, "InboundTTL", ttl.DecrementTTL)
      config.app(c, "InboundICMP4", icmp.ICMP4, {
                    node_ip4 = conf.private_interface4.ip
      })
      config.app(c, "PrivateNextHop", nexthop.NextHop4, {
                    node_mac = conf.private_interface4.mac,
                    node_ip4 = conf.private_interface4.ip,
                    nexthop_ip4 = conf.private_interface4.nexthop_ip,
                    nexthop_mac = conf.private_interface4.nexthop_mac,
                    synchronize = true,
                    passive = not conf.is_first_queue
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

   elseif conf.private_interface6 then
      routes = conf.route6
      config.app(c, "PrivateDispatch", dispatch.PrivateDispatch, {
                    node_ip6 = conf.private_interface6.ip
      })
      config.app(c, "OutboundHopLimit", ttl.DecrementHopLimit)
      config.app(c, "PrivateRouter", route.PrivateRouter, {
                    route6 = routes,
                    mtu = conf.mtu
      })
      config.app(c, "PrivateICMP6", icmp.ICMP6, {
                    node_ip6 = conf.private_interface6.ip,
                    nexthop_mtu = conf.mtu
      })
      config.app(c, "InboundDispatch", dispatch.InboundDispatch, {
                    node_ip6 = conf.private_interface6.ip
      })
      config.app(c, "InboundHopLimit", ttl.DecrementHopLimit)
      config.app(c, "InboundICMP6", icmp.ICMP6, {
                    node_ip6 = conf.private_interface6.ip
      })
      config.app(c, "PrivateNextHop", nexthop.NextHop6, {
                    node_mac = conf.private_interface6.mac,
                    node_ip6 = conf.private_interface6.ip,
                    nexthop_ip6 = conf.private_interface6.nexthop_ip,
                    nexthop_mac = conf.private_interface6.nexthop_mac,
                    synchronize = true,
                    passive = not conf.is_first_queue
      })
      config.link(c, "PrivateDispatch.forward6 -> OutboundHopLimit.input")
      config.link(c, "PrivateDispatch.icmp6 -> PrivateICMP6.input")
      config.link(c, "PrivateDispatch.nd -> PrivateNextHop.nd")
      config.link(c, "PrivateDispatch.protocol6_unreachable -> PrivateICMP6.protocol_unreachable")
      config.link(c, "OutboundHopLimit.output -> PrivateRouter.input")
      config.link(c, "OutboundHopLimit.hop_limit_exceeded -> PrivateICMP6.transit_ttl_exceeded")
      config.link(c, "PrivateRouter.fragmentation_needed -> PrivateICMP6.fragmentation_needed")
      config.link(c, "PrivateICMP6.output -> PrivateNextHop.icmp6")
      config.link(c, "InboundDispatch.forward6 -> InboundHopLimit.input")
      config.link(c, "InboundDispatch.icmp6 -> InboundICMP6.input")
      config.link(c, "InboundDispatch.protocol6_unreachable -> InboundICMP6.protocol_unreachable")
      config.link(c, "InboundHopLimit.output -> PrivateNextHop.forward")
      config.link(c, "InboundHopLimit.hop_limit_exceeded -> InboundICMP6.transit_ttl_exceeded")
      config.link(c, "InboundICMP6.output -> PrivateRouter.control")

   -- No interface configured, can not configure private router.
   else return c, ports end

   ports.input = "PrivateDispatch.input"
   ports.output = "PrivateNextHop.output"

   for id, route in pairs(routes) do
      ports.outbound[id] = "PrivateRouter."..id
   end

   for spi, sa in pairs(conf.inbound_sa) do
      local id = sa.route.."_"..sa.queue.."_"..spi
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

   local routes

   if conf.public_interface4 then
      routes = conf.route4
      config.app(c, "PublicDispatch", dispatch.PublicDispatch, {
                    node_ip4 = conf.public_interface4.ip,
                    protocol_port = conf.protocol_port
      })
      config.app(c, "PublicICMP4", icmp.ICMP4, {
                    node_ip4 = conf.public_interface4.ip
      })
      config.app(c, "PublicNextHop", nexthop.NextHop4, {
                    node_mac = conf.public_interface4.mac,
                    node_ip4 = conf.public_interface4.ip,
                    nexthop_ip4 = conf.public_interface4.nexthop_ip,
                    nexthop_mac = conf.public_interface4.nexthop_mac
      })
      config.link(c, "PublicDispatch.forward4 -> PublicRouter.input")
      config.link(c, "PublicDispatch.icmp4 -> PublicICMP4.input")
      config.link(c, "PublicDispatch.arp -> PublicNextHop.arp")
      config.link(c, "PublicDispatch.protocol4_unreachable -> PublicICMP4.protocol_unreachable")
      config.link(c, "PublicICMP4.output -> PublicNextHop.icmp4")

   elseif conf.public_interface6 then
      routes = conf.route6
      config.app(c, "PublicDispatch", dispatch.PublicDispatch, {
                    node_ip6 = conf.public_interface6.ip,
                    protocol_port = conf.protocol_port
      })
      config.app(c, "PublicICMP6", icmp.ICMP6, {
                    node_ip6 = conf.public_interface6.ip
      })
      config.app(c, "PublicNextHop", nexthop.NextHop6, {
                    node_mac = conf.public_interface6.mac,
                    node_ip6 = conf.public_interface6.ip,
                    nexthop_ip6 = conf.public_interface6.nexthop_ip,
                    nexthop_mac = conf.public_interface6.nexthop_mac
      })
      config.link(c, "PublicDispatch.forward6 -> PublicRouter.input")
      config.link(c, "PublicDispatch.icmp6 -> PublicICMP6.input")
      config.link(c, "PublicDispatch.nd -> PublicNextHop.nd")
      config.link(c, "PublicDispatch.protocol6_unreachable -> PublicICMP6.protocol_unreachable")
      config.link(c, "PublicICMP6.output -> PublicNextHop.icmp6")

   -- No interface configured, can not configure public router.
   else return c, ports end

   ports.input = "PublicDispatch.input"
   ports.output = "PublicNextHop.output"

   config.app(c, "PublicRouter", route.PublicRouter, {
                 sa = conf.inbound_sa
   })

   ports.protocol_input = "PublicDispatch.protocol"
   ports.protocol_output = "PublicNextHop.protocol"

   for id, route in pairs(routes) do
      local Tunnel = "Tunnel_"..id
      if conf.public_interface4 then
         config.app(c, Tunnel, tunnel.Tunnel4,
                    {src=conf.public_interface4.ip, dst=route.gateway})
      elseif conf.public_interface6 then
         config.app(c, Tunnel, tunnel.Tunnel6,
                    {src=conf.public_interface6.ip, dst=route.gateway})
      end
      config.link(c, Tunnel..".output -> PublicNextHop."..id)
      ports.outbound[id] = Tunnel..".input"
   end

   for spi, sa in pairs(conf.inbound_sa) do
      local id = sa.route.."_"..sa.queue.."_"..spi
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

   if conf.data_plane or
   not (conf.public_interface4 or conf.public_interface6) then
      return c, ports
   end

   config.app(c, "KeyManager", exchange.KeyManager, {
                 node_ip4 = conf.public_interface4 and conf.public_interface4.ip,
                 node_ip6 = conf.public_interface6 and conf.public_interface6.ip,
                 routes = (conf.public_interface4 and conf.route4) or
                          (conf.public_interface6 and conf.route6),
                 sa_db_path = queue_sa_db(conf.queue),
                 negotiation_ttl = conf.negotiation_ttl,
                 sa_ttl = conf.sa_ttl,
                 udp_port = conf.protocol_port
   })

   ports.input = "KeyManager.input"
   ports.output = "KeyManager.output"

   return c, ports
end

-- sa_db := { outbound_sa={<spi>=(SA), ...}, inbound_sa={<spi>=(SA), ...} }
-- (see exchange)

function configure_outbound_sa (conf, append)
   local c = append or config.new()

   local ports = { input={}, output={} } -- SA input/output pairs

   for spi, sa in pairs(conf.outbound_sa) do
      local OutboundSA = "OutboundSA_"..sa.route
      config.app(c, OutboundSA, tunnel.Encapsulate, {
                    spi = spi,
                    aead = sa.aead,
                    key = sa.key,
                    salt = sa.salt,
                    tfc_mtu = conf.tfc and conf.mtu
      })
      if conf.route4[sa.route] then
         ports.input[sa.route] = OutboundSA..".input4"
      elseif conf.route6[sa.route] then
         ports.input[sa.route] = OutboundSA..".input6"
      end
      ports.output[sa.route] = OutboundSA..".output"
   end

   return c, ports
end

function configure_inbound_sa (conf, append)
   local c = append or config.new()

   local ports = { input={}, output={} } -- SA input/output pairs

   for spi, sa in pairs(conf.inbound_sa) do
      local id = sa.route.."_"..sa.queue.."_"..spi
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
      if conf.route4[sa.route] then
         ports.output[id] = InboundSA..".output4"
      elseif conf.route6[sa.route] then
         ports.output[id] = InboundSA..".output6"
      end
   end

   return c, ports
end
