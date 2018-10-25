-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

local shm = require("core.shm")
local counter = require("core.counter")
local data = require("lib.yang.data")
local state = require('lib.yang.state')
local yang = require("lib.yang.yang")


-- Load Vita’s native schemata

yang.add_schema(require("program.vita.vita_esp_gateway_yang",
                        "program/vita/vita-esp-gateway.yang"))
yang.add_schema(require("program.vita.vita_ephemeral_keys_yang",
                        "program/vita/vita-ephemeral-keys.yang"))


-- State reader support

local function open_counters (path)
   local counters = {}
   for _, file in ipairs(shm.children(path)) do
      local name, type = file:match("(.*)[.](.*)$")
      local canonical_name = name:gsub('[^%w-]', '-')
      if type == 'counter' then
         counters[canonical_name] = counter.open(path..'/'..file)
      end
   end
   return counters
end

function configuration_for_worker (worker, _)
   return worker.graph
end

function compute_state_reader (schema_name)
   assert(schema_name == 'vita-esp-gateway')
   local schema = yang.load_schema_by_name(schema_name)
   local grammar = data.data_grammar_from_schema(schema, false)

   local gateway_state_gmr =
      grammar.members["gateway-state"]
   local sa_state_gmr =
      gateway_state_gmr.members["inbound-sa"].values["sa-state"]

   return function (pid, graph)
      local gateway_state = {}

      local interface_state = {
         PrivateNIC = "private-interface",
         PublicNIC = "public-interface"
      }
      for app, member in pairs(interface_state) do
         local id = data.normalize_id(member)
         local grammar = gateway_state_gmr.members[member]
         local counters = {}
         if graph.apps[app] then
            local pciaddr = graph.apps[app].arg.pciaddr
            counters = open_counters("/"..pid.."/pci/"..pciaddr)
         end
         gateway_state[id] = state.state_reader_from_grammar(grammar)(counters)
      end

      local app_state = {
         PrivateNextHop = "private-next-hop",
         PublicNextHop = "public-next-hop",
         PrivateDispatch = "private-dispatch",
         PublicDispatch = "public-dispatch",
         InboundDispatch = "inbound-dispatch",
         OutboundTTL = "outbound-ttl",
         InboundTTL = "inbound-ttl",
         PrivateRouter = "private-router",
         PublicRouter = "public-router",
         PrivateICMP4 = "private-icmp4",
         PublicICMP4 = "public-icmp4",
         InboundICMP4 = "inbound-icmp4",
         KeyManager = "key-manager"
      }
      for app, member in pairs(app_state) do
         local id = data.normalize_id(member)
         local grammar = gateway_state_gmr.members[member]
         local counters = {}
         if graph.apps[app] then
            counters = open_counters("/"..pid.."/apps/"..app)
         end
         gateway_state[id] = state.state_reader_from_grammar(grammar)(counters)
      end

      gateway_state.inbound_sa = {}
      for app, _ in pairs(graph.apps) do
         local sa = app:match("^DSP_%w+_(%d+)$")
         if sa then
            local spi = tonumber(sa)
            local counters = open_counters("/"..pid.."/apps/"..app)
            local reader = state.state_reader_from_grammar(sa_state_gmr)
            gateway_state.inbound_sa[spi] =
               {spi=spi, sa_state=reader(counters)}
         end
      end

      return gateway_state
   end
end

function process_states (states)
   local gateway_state = {}

   local containers =
      {"private_interface", "public_interface",
       "private_next_hop", "public_next_hop",
       "private_dispatch", "public_dispatch", "inbound_dispatch",
       "outbound_ttl", "inbound_ttl", "private_router", "public_router",
       "private_icmp4", "public_icmp4", "inbound_icmp4", "key_manager"}
   for _, container in ipairs(containers) do
      local acc = {}
      for _, state in ipairs(states) do
         for member, value in pairs(state[container]) do
            acc[member] = (acc[member] or 0) + value
         end
      end
      gateway_state[container] = acc
   end

   local lists =
      {"inbound_sa"}
   for _, list in ipairs(lists) do
      local acc = {}
      for _, state in ipairs(states) do
         for key, value in pairs(state[list]) do
            acc[key] = value
         end
      end
      gateway_state[list] = acc
   end

   return {gateway_state = gateway_state}
end


-- Module exports

return {
   -- Schemata
   ['esp-gateway'] = yang.load_schema_by_name('vita-esp-gateway'),
   ['ephemeral-keys'] = yang.load_schema_by_name('vita-ephemeral-keys'),
   -- State reader support
   support = {
      configuration_for_worker = configuration_for_worker,
      compute_state_reader = compute_state_reader,
      process_states = process_states
   }
   
}
