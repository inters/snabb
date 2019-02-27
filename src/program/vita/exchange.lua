-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

-- This module handles AUTHENTICATED KEY EXCHANGE with peers and
-- SECURITY ASSOCIATION (SA) CONFIGURATION, which includes dynamically reacting
-- to changes to the routes defined in Vita’s root configuration. For each
-- route defined in the gateway’s configuration pairs of SAs (inbound and
-- outbound) are negotiated and maintained. On change, the set of SAs is
-- written to the Security Association Database (SAD) which is used to
-- configure the data plane.
--
--                         (AKE protocol)
--                               ||
--                               ||
--               <config> --> KeyManager --> <SAD>
--
-- All things considered, this is the hairy part of Vita, as it covers touchy
-- things such as key generation and expiration, and ultimately presents Vita’s
-- main exploitation surface. On the upside, this module’s data plane doesn’t
-- need to worry as much about soft real-time requirements as others, as its
-- generally low-throughput. It can (and should) primarily focus on safety,
-- and can afford more costly dynamic high-level language features to do so.
-- At least to the extent where to doesn’t enable low-bandwidth DoS, that is.
--
-- In order to insulate failure, this module is composed of three subsystems:
--
--  1. The KeyManager app handles AKE control plane traffic (key negotiation
--     requests and responses) and configuration plane changes (react to
--     configuration changes and update the SAD.)
--
--     It tries its best to avoid clobbering valid SA configurations, too. I.e.
--     SAs whose routes are not changed in a configuration transition are
--     unaffected by the ensuing re-configuration, allowing for seamless
--     addition of new routes and network address renumbering.
--
--     Whenever SAs are invalidated, i.e. because the route’s pre-shared key or
--     SPI is changed, or because a route is removed entirely, or because the
--     lifetime of a SA pair has expired (sa_ttl), it is destroyed, and
--     eventually re-negotiated if applicable.
--
--     Active SAs are maintained in three lists, inbound_sa, outbound_sa, and
--     outbound_sa_queue, which behave as FIFO queues. Inbound_sa and
--     outbound_sa reflect the active set of SAs as committed to the SAD. Newly
--     established inbound SAs are inserted to the front of inbound_sa,
--     displacing SAs at its end according to max_inbound_sa. Newly established
--     outbound SAs are inserted at the end of outbound_sa_queue. Outbound SAs
--     are removed from the front of outbound_sa_queue and inserted to the
--     front of outbound_sa once their activation_delay has elapsed. If there
--     are less than num_outbound_sa SAs in the outbound_sa list, outbound SAs
--     are removed from the front of outbound_sa_queue and inserted to the
--     front of outbound_sa. SAs inserted into outbound_sa displace SAs at the
--     end of outbound_sa according to num_outbound_sa. SAs that have expired
--     (sa_ttl) are removed from the inbound_sa and outbound_sa lists.
--
--     Note that the KeyManager app will attempt to re-negotiate SAs long
--     before they expire (approximately once half of sa_ttl has passed, see
--     rekey_timeout), in order to avoid loss of tunnel connectivity during
--     re-negotiation.
--
--     Negotiation requests are fed from the input port to the individual
--     Protocol finite-state machines (described below in 2.) of a route, and
--     associated to routes via the Transport wrapper (described below in 3.).
--     Replies and outgoing requests (also obtained by mediating with the
--     Protocol fsm) are sent via the output port.
--
--     Any meaningful events regarding SA negotiation and expiry are logged and
--     registered in the following counters:
--
--        rxerrors                count of all erroneous incoming requests
--                                (includes all others counters)
--
--        route_errors            count of requests that couldn’t be associated
--                                to any configured route
--
--        protocol_errors         count of requests that violated the protocol
--                                (order of messages and message format)
--
--        authentication_errors   count of requests that were detected to be
--                                unauthentic (had an erroneous MAC, this
--                                includes packets corrupted during transit)
--
--        public_key_errors       count of public keys that were rejected
--                                because they were considered unsafe
--
--        negotiations_initiated  count of negotiations initiated by us
--
--        negotiations_expired    count of negotiations expired
--                                (negotiation_ttl)
--
--        challenges_offered      count of challenges that were offered
--                                (responder) 
--
--        challenges_accepted     count of challenges that were accepted
--                                (initiator) 
--
--        keypairs_offered        count of ephemeral key pairs that were
--                                offered (responder)
--
--        keypairs_negotiated     count of ephemeral key pairs that were
--                                negotiated (initiator)
--
--        inbound_sa_expired      count of inbound SAs that have expired
--                                (sa_ttl)
--
--        outbound_sa_expired     count of outbound SAs that have expired
--                                (sa_ttl)
--
--        outbound_sa_updated     count of outbound SAs that were updated
--
--  2. The Protocol subsystem implements vita-ske2 (the cryptographic key
--     exchange protocol defined in README.exchange) as two finite-state
--     machines (responder and initiator).
--
--     For a state transition diagram see: fsm-protocol.png
--
--     The Protocol fsm requires its user (the KeyManager app) to “know” about
--     the state transitions of the exchange protocol, but it is written in a
--     way that intends to make fatal misuse impossible, given that one sticks
--     to its public API methods. I.e. it is driven by calling the methods
--
--        initiate_exchange
--        receive_nonce
--        offer_challenge
--        receive_challenge
--        offer_key
--        receive_key
--        offer_nonce_key
--        receive_nonce_key
--        reset_if_expired
--
--     which uphold invariants that should ensure any resulting key material is
--     trustworthy, signal any error conditions to the caller, and maintain
--     general consistency of the protocol so that it doesn’t get stuck.
--     Hopefully, the worst consequence of misusing the Protocol fsm is failure
--     to negotiate a key pair.
--
--  3. The Transport header is a super-light transport header that encodes the
--     target SPI and message type of the protocol requests it precedes. It is
--     used by the KeyManager app to parse requests and associate them to the
--     correct route and fsm by SPI and message type respectively. It uses the
--     IP protocol type 99 for “any private encryption scheme”. (Eventually, it
--     needs to be wrapped in UDP.)
--
--     It exists explicitly separate from the KeyManager app and Protocol fsm,
--     to clarify that it is interchangable, and logically unrelated to either
--     components.

local S = require("syscall")
local ffi = require("ffi")
local shm = require("core.shm")
local counter = require("core.counter")
local header = require("lib.protocol.header")
local lib = require("core.lib")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")
local yang = require("lib.yang.yang")
local schemata = require("program.vita.schemata")
require("program.vita.sodium_h")
local C = ffi.C

PROTOCOL = 99 -- “Any private encryption scheme”

KeyManager = {
   name = "KeyManager",
   config = {
      node_ip4 = {},
      node_ip6 = {},
      routes = {required=true},
      sa_db_path = {required=true},
      num_outbound_sa = {default=1},
      max_inbound_sa = {default=4},
      negotiation_ttl = {default=5}, -- default:  5 seconds
      sa_ttl = {default=(10 * 60)}   -- default: 10 minutes
   },
   shm = {
      rxerrors = {counter},
      route_errors = {counter},
      protocol_errors = {counter},
      authentication_errors = {counter},
      public_key_errors = {counter},
      negotiations_initiated = {counter},
      negotiations_expired = {counter},
      challenges_offered = {counter},
      challenges_accepted = {counter},
      keypairs_offered = {counter},
      keypairs_negotiated = {counter},
      inbound_sa_expired  = {counter},
      outbound_sa_expired = {counter},
      outbound_sa_updated = {counter}
   },
   max_pps = 100
}

function KeyManager:new (conf)
   local o = {
      routes = {},
      ip4 = ipv4:new({}),
      ip6 = ipv6:new({}),
      transport = Transport.header:new({}),
      nonce_message = Protocol.nonce_message:new({}),
      key_message = Protocol.key_message:new({}),
      challenge_message = Protocol.challenge_message:new({}),
      nonce_key_message = Protocol.nonce_key_message:new({}),
      sa_db_updated = false,
      sa_db_commit_throttle = lib.throttle(1),
      rate_bucket = KeyManager.max_pps,
      rate_throttle = lib.throttle(1)
   }
   local self = setmetatable(o, { __index = KeyManager })
   self:reconfig(conf)
   assert(C.sodium_init() >= 0, "Failed to initialize libsodium.")
   return self
end

function KeyManager:reconfig (conf)
   self.audit = lib.logger_new({
         rate = 32,
         module = ("KeyManager(%s)"):format(conf.node_ip4 or conf.node_ip6)
   })

   local function find_route (id)
      for _, route in ipairs(self.routes) do
         if route.id == id then return route end
      end
   end
   local function route_match (route, preshared_key, spi)
      return lib.equal(route.preshared_key, preshared_key)
         and route.spi == spi
   end
   local function free_route (route)
      for _, sa in ipairs(route.inbound_sa) do
         self.audit:log(("Expiring inbound SA %d for '%s' (reconfig)")
               :format(sa.spi, route.id))
         self.sa_db_updated = true
      end
      for _, sa in ipairs(route.outbound_sa) do
         self.audit:log(("Expiring outbound SA %d for '%s' (reconfig)")
               :format(sa.spi, route.id))
         self.sa_db_updated = true
      end
   end

   -- compute new set of routes
   local new_routes = {}
   for id, route in pairs(conf.routes) do
      local new_key = lib.hexundump(route.preshared_key,
                                    Protocol.preshared_key_bytes)
      local old_route = find_route(id)
      if old_route and route_match(old_route, new_key, route.spi) then
         -- keep old route
         table.insert(new_routes, old_route)
         -- if negotation_ttl has changed, swap out old protocol fsm for a new
         -- one with the adjusted timeout, effectively resetting the fsm
         if conf.negotiation_ttl ~= self.negotiation_ttl then
            self.audit:log("Protocol reset for '"..id.."' (reconfig)")
            old_route.initiator = Protocol:new('initiator',
                                               old_route.spi,
                                               old_route.preshared_key,
                                               conf.negotiation_ttl)
            old_route.responder = Protocol:new('responder',
                                               old_route.spi,
                                               old_route.preshared_key,
                                               conf.negotiation_ttl)
         end
      else
         -- insert new new route
         assert(route.gw_ip4 or route.gw_ip6, "Need either gw_ip4 or gw_ip6")
         local new_route = {
            id = id,
            gw_ip4n = route.gw_ip4 and ipv4:pton(route.gw_ip4),
            gw_ip6n = route.gw_ip6 and ipv6:pton(route.gw_ip6),
            preshared_key = new_key,
            spi = route.spi,
            inbound_sa = {}, outbound_sa = {}, outbound_sa_queue = {},
            responder = Protocol:new('responder',
                                     route.spi,
                                     new_key,
                                     conf.negotiation_ttl),
            initiator = Protocol:new('initiator',
                                     route.spi,
                                     new_key,
                                     conf.negotiation_ttl)
         }
         table.insert(new_routes, new_route)
         -- clean up after the old route if necessary
         if old_route then free_route(old_route) end
      end
   end

   -- clean up after removed routes
   for _, route in ipairs(self.routes) do
      if not conf.routes[route.id] then free_route(route) end
   end

   -- switch to new configuration
   assert(conf.node_ip4 or conf.node_ip6, "Need either node_ip4 or node_ip6")
   self.node_ip4n = conf.node_ip4 and ipv4:pton(conf.node_ip4)
   self.node_ip6n = conf.node_ip6 and ipv6:pton(conf.node_ip6)
   self.routes = new_routes
   self.sa_db_file = shm.root.."/"..shm.resolve(conf.sa_db_path)
   self.num_outbound_sa = conf.num_outbound_sa
   self.max_inbound_sa = conf.max_inbound_sa
   self.negotiation_ttl = conf.negotiation_ttl
   self.sa_ttl = conf.sa_ttl
end

function KeyManager:stop ()
   -- make sure to remove SA database when app is stopped
   S.unlink(self.sa_db_file)
end

function KeyManager:push ()
   -- handle negotiation protocol requests
   local input = self.input.input
   while not link.empty(input) and self:rate_limit() do
      local request = link.receive(input)
      self:handle_negotiation(request)
      packet.free(request)
   end

   for _, route in ipairs(self.routes) do
      -- process protocol timeouts
      if route.initiator:reset_if_expired() == Protocol.code.expired then
         counter.add(self.shm.negotiations_expired)
         self.audit:log(("Negotiation expired for '%s' (negotiation_ttl)")
               :format(route.id))
      end
      for index, sa in ipairs(route.inbound_sa) do
         if sa.ttl() then
            table.remove(route.inbound_sa, index)
            self.sa_db_updated = true
            counter.add(self.shm.inbound_sa_expired)
            self.audit:log(("Inbound SA %d expired for '%s' (sa_ttl)")
                  :format(sa.spi, route.id))
         end
      end
      for index, sa in ipairs(route.outbound_sa) do
         if sa.ttl() then
            table.remove(route.outbound_sa, index)
            self.sa_db_updated = true
            counter.add(self.shm.outbound_sa_expired)
            self.audit:log(("Outbound SA %d expired for '%s' (sa_ttl)")
                  :format(sa.spi, route.id))
         end
      end

      -- activate new outbound SAs
      for index, sa in ipairs(route.outbound_sa_queue) do
         if sa.activation_delay()
         or #route.outbound_sa < self.num_outbound_sa then
            self.audit:log(("Activating outbound SA %d for '%s'")
                  :format(sa.spi, route.id))
            -- insert in front of SA list
            table.insert(route.outbound_sa, 1, sa)
            table.remove(route.outbound_sa_queue, index)
            self.sa_db_updated = true
         end
      end
      -- remove superfluous outbound SAs from the end of the list
      while #route.outbound_sa > self.num_outbound_sa do
         table.remove(route.outbound_sa)
         self.sa_db_updated = true
      end

      -- initiate (re-)negotiation of SAs
      local num_sa = #route.outbound_sa_queue
      for _, sa in ipairs(route.outbound_sa) do
         if not sa.rekey_timeout() then num_sa = num_sa + 1 end
      end
      if num_sa < self.num_outbound_sa then
         self:negotiate(route)
      end
   end

   -- commit SA database if necessary
   if self.sa_db_updated and self.sa_db_commit_throttle() then
      self:commit_sa_db()
      self.sa_db_updated = false
   end
end

function KeyManager:rate_limit ()
   if self.rate_throttle() then
      self.rate_bucket = self.max_pps
   end
   if self.rate_bucket > 0 then
      self.rate_bucket = self.rate_bucket - 1
      return true
   end
end

function KeyManager:negotiate (route)
   -- Inititate AKE if the protocol fsm permits (i.e., is in the initiator
   -- state.)
   local ecode, nonce_message =
      route.initiator:initiate_exchange(self.nonce_message)
   if not ecode then
      counter.add(self.shm.negotiations_initiated)
      self.audit:log("Initiating negotiation for '"..route.id.."'")
      link.transmit(self.output.output, self:request(route, nonce_message))
   else assert(ecode == Protocol.code.protocol) end
end

function KeyManager:handle_negotiation (request)
   local route, message = self:parse_request(request)

   if not (self:handle_nonce_request(route, message)
           or self:handle_key_request(route, message)
           or self:handle_challenge_request(route, message)
           or self:handle_nonce_key_request(route, message)) then
      counter.add(self.shm.rxerrors)
      self.audit:log(("Rejected invalid negotiation request for '%s'")
            :format(route or "<unknown>"))
   end
end

function KeyManager:handle_nonce_request (route, message)
   if not route or message ~= self.nonce_message then return end

   -- Receive nonce message if the protocol fsm permits
   -- (responder -> offer_challenge), otherwise reject the message and return.
   local ecode = route.responder:receive_nonce(message)
   if ecode == Protocol.code.protocol then
      counter.add(self.shm.protocol_errors)
      return false
   else assert(not ecode) end

   -- If we got here we should respond with a challenge message
   -- (offer_challenge -> responder).
   local response = self.challenge_message
   local ecode, response = route.responder:offer_challenge(response)
   assert(not ecode)
   link.transmit(self.output.output, self:request(route, response))

   counter.add(self.shm.challenges_offered)
   self.audit:log("Offered challenge for '"..route.id.."'")

   return true
end

function KeyManager:handle_challenge_request (route, message)
   if not route or message ~= self.challenge_message then return end

   -- Receive challenge message if the protocol fsm permits
   -- (accept_challenge -> offer_nonce_key), reject the message and return
   -- otherwise or if...
   local ecode = route.initiator:receive_challenge(message)
   if ecode == Protocol.code.protocol then
      counter.add(self.shm.protocol_errors)
      return false
   elseif ecode == Protocol.code.authentication then
      -- ...the message failed to authenticate.
      counter.add(self.shm.authentication_errors)
      return false
   else assert(not ecode) end

   counter.add(self.shm.challenges_accepted)
   self.audit:log("Accepted challenge for '"..route.id.."'")

   -- If we got here we should offer our nonce and public key
   -- (offer_nonce_key -> accept_key).
   local response = self.nonce_key_message
   local ecode, response = route.initiator:offer_nonce_key(response)
   assert(not ecode)

   self.audit:log("Proposing key exchange for '"..route.id.."'")
   link.transmit(self.output.output, self:request(route, response))

   return true
end

function KeyManager:handle_nonce_key_request (route, message)
   if not route or message ~= self.nonce_key_message then return end

   -- Receive an authenticated, combined nonce and key message if the protocol
   -- fsm permits (responder -> offer_key), reject the message and return
   -- otherwise or if...
   local ecode, inbound_sa, outbound_sa =
      route.responder:receive_nonce_key(message)
   if ecode == Protocol.code.protocol then
      counter.add(self.shm.protocol_errors)
      return false
   elseif ecode == Protocol.code.authentication then
      -- ...the message failed to authenticate.
      counter.add(self.shm.authentication_errors)
      return false
   elseif ecode == Protocol.code.parameter then
      -- ...the message offered a bad public key.
      counter.add(self.shm.public_key_errors)
      return false
   else assert(not ecode) end

   -- If we got here we should respond with our own public key
   -- (offer_key -> responder).
   local ecode, response = route.responder:offer_key(self.key_message)
   assert(not ecode)

   link.transmit(self.output.output, self:request(route, response))

   -- This is an optimization for loopback testing: if we are negotiating with
   -- ourselves, configure an inbound SA only (outbound SA will be configured
   -- by the initiator.)
   local is_loopback = (route.gw_ip4n and self.ip4:src_eq(route.gw_ip4n)) or
                       (route.gw_ip6n and self.ip6:src_eq(route.gw_ip6n))

   counter.add(self.shm.keypairs_offered)
   self.audit:log(("Offered key pair for '%s' (inbound SA %d, outbound SA %s)"):
         format(route.id,
                inbound_sa.spi,
                (is_loopback and "-") or outbound_sa.spi))

   self:insert_inbound_sa(route, inbound_sa)
   if not is_loopback then self:upsert_outbound_sa(route, outbound_sa) end

   return true
end

function KeyManager:handle_key_request (route, message)
   if not route or message ~= self.key_message then return end

   -- Receive an authenticated key message if the protocol fsm permits
   -- (accept_key -> initiator), reject the message and return otherwise or
   -- if...
   local ecode, inbound_sa, outbound_sa = route.initiator:receive_key(message)
   if ecode == Protocol.code.protocol then
      counter.add(self.shm.protocol_errors)
      return false
   elseif ecode == Protocol.code.authentication then
      -- ...the message failed to authenticate.
      counter.add(self.shm.authentication_errors)
      return false
   elseif ecode == Protocol.code.parameter then
      -- ...the message offered a bad public key.
      counter.add(self.shm.public_key_errors)
      return false
   else assert(not ecode) end

   -- This is an optimization for loopback testing: if we are negotiating with
   -- ourselves, configure an outbound SA only (inbound SA has been configured
   -- by the responder.)
   local is_loopback = (route.gw_ip4n and self.ip4:src_eq(route.gw_ip4n)) or
                       (route.gw_ip6n and self.ip6:src_eq(route.gw_ip6n))

   counter.add(self.shm.keypairs_negotiated)
   self.audit:log(("Completed AKE for '%s' (inbound SA %s, outbound SA %d)"):
         format(route.id,
                (is_loopback and "-") or inbound_sa.spi,
                outbound_sa.spi))

   if not is_loopback then self:insert_inbound_sa(route, inbound_sa) end
   self:upsert_outbound_sa(route, outbound_sa)

   return true
end

function KeyManager:insert_inbound_sa (route, sa)
   -- invariant: inbound SA spi is unique
   for _, route in ipairs(self.routes) do
      for _, inbound in ipairs(route.inbound_sa) do
         assert(inbound.spi ~= sa.spi, "PANIC: SPI collision detected.")
      end
   end
   -- insert in front of SA list
   table.insert(route.inbound_sa, 1, {
      spi = sa.spi,
      aead = "aes-gcm-16-icv",
      key = lib.hexdump(sa.key),
      salt = lib.hexdump(sa.salt),
      ttl = lib.timeout(self.sa_ttl)
   })
   -- remove superfluous SAs from the end of the list
   while #route.inbound_sa > self.max_inbound_sa do
      table.remove(route.inbound_sa)
   end
   self.sa_db_updated = true
end

function KeyManager:upsert_outbound_sa (route, sa)
   -- possibly replace existing or queued outbound SA
   local function remove_existing_sa_for_update ()
      for index, outbound in ipairs(route.outbound_sa_queue) do
         if outbound.spi == sa.spi then
            return table.remove(route.outbound_sa_queue, index)
         end
      end
      for index, outbound in ipairs(route.outbound_sa) do
         if outbound.spi == sa.spi then
            return table.remove(route.outbound_sa, index)
         end
      end
   end
   if remove_existing_sa_for_update() then
      counter.add(self.shm.outbound_sa_updated)
      self.audit:log("Updating outbound SA "..sa.spi.." for '"..route.id.."'")
   end
   -- enqueue new outbound SA at the end of the queue
   table.insert(route.outbound_sa_queue, {
      spi = sa.spi,
      aead = "aes-gcm-16-icv",
      key = lib.hexdump(sa.key),
      salt = lib.hexdump(sa.salt),
      ttl = lib.timeout(self.sa_ttl),
      -- Rekey outbound SAs after approximately half of sa_ttl, with a second
      -- of jitter to reduce the probability of two peers initating the key
      -- exchange concurrently.
      rekey_timeout = lib.timeout(self.sa_ttl/2 + math.random(1000)/1000),
      -- Delay before activating redundant, newly established outbound SAs to
      -- give the receiving end time to set up. Choosen so that when a
      -- negotiation times out due to packet loss, the initiator can update
      -- unrequited outbound SAs before they get activated.
      activation_delay = lib.timeout(self.negotiation_ttl*1.5)
   })
end

function KeyManager:request (route, message)
   local request = packet.allocate()

   if self.node_ip4n then
      self.ip4:new({
            total_length = ipv4:sizeof()
               + Transport.header:sizeof()
               + message:sizeof(),
            ttl = 64,
            protocol = PROTOCOL,
            src = self.node_ip4n,
            dst = route.gw_ip4n
      })
      packet.append(request, self.ip4:header(), ipv4:sizeof())
   elseif self.node_ip6n then
      self.ip6:new({
            payload_length = Transport.header:sizeof() + message:sizeof(),
            hop_limit = 64,
            next_header = PROTOCOL,
            src = self.node_ip6n,
            dst = route.gw_ip6n
      })
      packet.append(request, self.ip6:header(), ipv6:sizeof())
   else error("BUG") end

   self.transport:new({
         spi = route.spi,
         message_type = (message == self.nonce_message
                            and Transport.message_type.nonce)
                     or (message == self.key_message
                            and Transport.message_type.key)
                     or (message == self.challenge_message
                            and Transport.message_type.challenge)
                     or (message == self.nonce_key_message
                            and Transport.message_type.nonce_key)
   })

   packet.append(request, self.transport:header(), Transport.header:sizeof())

   packet.append(request, message:header(), message:sizeof())

   return request
end

function KeyManager:parse_request (request)
   local transport = self.transport:new_from_mem(request.data, request.length)
   if not transport then
      counter.add(self.shm.protocol_errors)
      return
   end

   local route = nil
   for _, r in ipairs(self.routes) do
      if transport:spi() == r.spi then
         route = r
         break
      end
   end
   if not route then
      counter.add(self.shm.route_errors)
      return
   end

   local data = request.data + Transport.header:sizeof()
   local length = request.length - Transport.header:sizeof()
   local message =
         (transport:message_type() == Transport.message_type.nonce
             and self.nonce_message:new_from_mem(data, length))
      or (transport:message_type() == Transport.message_type.key
             and self.key_message:new_from_mem(data, length))
      or (transport:message_type() == Transport.message_type.challenge
             and self.challenge_message:new_from_mem(data, length))
      or (transport:message_type() == Transport.message_type.nonce_key
             and self.nonce_key_message:new_from_mem(data, length))
   if not message then
      counter.add(self.shm.protocol_errors)
      return
   end

   return route, message
end

-- sa_db := { outbound_sa={<spi>=(SA), ...}, inbound_sa={<spi>=(SA), ...} }

function KeyManager:commit_sa_db ()
   -- Collect currently active SAs
   local esp_keys, dsp_keys = {}, {}
   for _, route in ipairs(self.routes) do
      for _, sa in ipairs(route.outbound_sa) do
         esp_keys[sa.spi] = {
            route=route.id, spi=sa.spi, aead=sa.aead, key=sa.key, salt=sa.salt
         }
      end
      for _, sa in ipairs(route.inbound_sa) do
         dsp_keys[sa.spi] = {
            route=route.id, spi=sa.spi, aead=sa.aead, key=sa.key, salt=sa.salt
         }
      end
   end
   -- Commit active SAs to SA database
   yang.compile_config_for_schema(
      schemata['ephemeral-keys'],
      {outbound_sa=esp_keys, inbound_sa=dsp_keys},
      self.sa_db_file
   )
end

-- Vita: simple key exchange (vita-ske, version 2a). See README.exchange

Message = subClass(header)
function Message:new_from_mem (mem, size)
   if size == self:sizeof() then
      return Message:superClass().new_from_mem(self, mem, size)
   end
end

Protocol = {
   status = { responder = 0, initiator = 1,
              offer_challenge = 2, accept_challenge = 3,
              offer_key = 4, offer_nonce_key = 5, accept_key = 7 },
   code = { protocol = 0, authentication = 1, parameter = 2, expired = 3},
   spi_counter = 0,
   preshared_key_bytes = C.crypto_auth_hmacsha512256_KEYBYTES,
   public_key_bytes = C.crypto_scalarmult_curve25519_BYTES,
   secret_key_bytes = C.crypto_scalarmult_curve25519_SCALARBYTES,
   auth_code_bytes = C.crypto_auth_hmacsha512256_BYTES,
   nonce_bytes = 32,
   spi_t = ffi.typeof("union { uint32_t u32; uint8_t bytes[4]; }"),
   buffer_t = ffi.typeof("uint8_t[?]"),
   key_t = ffi.typeof[[
      union {
         uint8_t bytes[20];
         struct {
            uint8_t key[16];
            uint8_t salt[4];
         } __attribute__((packed)) slot;
      }
   ]],
   nonce_message = subClass(Message),
   challenge_message = subClass(Message),
   key_message = subClass(Message),
   nonce_key_message = subClass(Message)
}

Protocol.nonce_message:init({
      [1] = ffi.typeof([[
            struct {
               uint8_t nonce[]]..Protocol.nonce_bytes..[[];
            } __attribute__((packed))
      ]])
})

Protocol.challenge_message:init({
      [1] = ffi.typeof([[
            struct {
               uint8_t nonce[]]..Protocol.nonce_bytes..[[];
               uint8_t auth_code[]]..Protocol.auth_code_bytes..[[];
            } __attribute__((packed))
      ]])
})

Protocol.key_message:init({
      [1] = ffi.typeof([[
            struct {
               uint8_t spi[]]..ffi.sizeof(Protocol.spi_t)..[[];
               uint8_t public_key[]]..Protocol.public_key_bytes..[[];
               uint8_t auth_code[]]..Protocol.auth_code_bytes..[[];
            } __attribute__((packed))
      ]])
})

Protocol.nonce_key_message:init({
      [1] = ffi.typeof([[
            struct {
               uint8_t nonce[]]..Protocol.nonce_bytes..[[];
               uint8_t spi[]]..ffi.sizeof(Protocol.spi_t)..[[];
               uint8_t public_key[]]..Protocol.public_key_bytes..[[];
               uint8_t auth_code[]]..Protocol.auth_code_bytes..[[];
            } __attribute__((packed))
      ]])
})

-- Public API

function Protocol.nonce_message:new (config)
   local o = Protocol.nonce_message:superClass().new(self)
   o:nonce(config.nonce)
   return o
end

function Protocol.nonce_message:nonce (nonce)
   local h = self:header()
   if nonce ~= nil then
      ffi.copy(h.nonce, nonce, ffi.sizeof(h.nonce))
   end
   return h.nonce
end

function Protocol.challenge_message:new (config)
   local o = Protocol.challenge_message:superClass().new(self)
   o:nonce(config.nonce)
   o:auth_code(config.auth_code)
   return o
end

Protocol.challenge_message.nonce = Protocol.nonce_message.nonce

function Protocol.challenge_message:auth_code (auth_code)
   local h = self:header()
   if auth_code ~= nil then
      ffi.copy(h.auth_code, auth_code, ffi.sizeof(h.auth_code))
   end
   return h.auth_code
end

function Protocol.key_message:new (config)
   local o = Protocol.key_message:superClass().new(self)
   o:spi(config.spi)
   o:public_key(config.public_key)
   o:auth_code(config.auth_code)
   return o
end

function Protocol.key_message:spi (spi)
   local h = self:header()
   if spi ~= nil then
      ffi.copy(h.spi, spi, ffi.sizeof(h.spi))
   end
   return h.spi
end

function Protocol.key_message:public_key (public_key)
   local h = self:header()
   if public_key ~= nil then
      ffi.copy(h.public_key, public_key, ffi.sizeof(h.public_key))
   end
   return h.public_key
end

Protocol.key_message.auth_code = Protocol.challenge_message.auth_code

function Protocol.nonce_key_message:new (config)
   local o = Protocol.nonce_key_message:superClass().new(self)
   o:nonce(config.nonce)
   o:spi(config.spi)
   o:public_key(config.public_key)
   o:auth_code(config.auth_code)
   return o
end

Protocol.nonce_key_message.nonce = Protocol.nonce_message.nonce
Protocol.nonce_key_message.spi = Protocol.key_message.spi
Protocol.nonce_key_message.public_key = Protocol.key_message.public_key
Protocol.nonce_key_message.auth_code = Protocol.challenge_message.auth_code

function Protocol:new (initial_status, r, key, timeout)
   local o = {
      status = assert(Protocol.status[initial_status]),
      timeout = timeout,
      deadline = false,
      k = ffi.new(Protocol.buffer_t, Protocol.preshared_key_bytes),
      r = ffi.new(Protocol.spi_t),
      n1 = ffi.new(Protocol.buffer_t, Protocol.nonce_bytes),
      n2 = ffi.new(Protocol.buffer_t, Protocol.nonce_bytes),
      spi1 = ffi.new(Protocol.spi_t),
      spi2 = ffi.new(Protocol.spi_t),
      s1 = ffi.new(Protocol.buffer_t, Protocol.secret_key_bytes),
      p1 = ffi.new(Protocol.buffer_t, Protocol.public_key_bytes),
      p2 = ffi.new(Protocol.buffer_t, Protocol.public_key_bytes),
      h  = ffi.new(Protocol.buffer_t, Protocol.auth_code_bytes),
      q  = ffi.new(Protocol.buffer_t, Protocol.secret_key_bytes),
      e  = ffi.new(Protocol.key_t),
      hmac_state = ffi.new("struct crypto_auth_hmacsha512256_state"),
      hash_state = ffi.new("struct crypto_generichash_blake2b_state")
   }
   ffi.copy(o.k, key, ffi.sizeof(o.k))
   o.r.u32 = lib.htonl(r)
   return setmetatable(o, {__index=Protocol}):reset()
end

function Protocol:initiate_exchange (nonce_message)
   assert(nonce_message:class() == Protocol.nonce_message)
   if self.status == Protocol.status.initiator then
      -- initiator -> accept_challenge
      self:set_deadline()
      self.status = Protocol.status.accept_challenge
      return nil, self:send_nonce(nonce_message)
   else return Protocol.code.protocol end
end

function Protocol:receive_nonce (nonce_message)
   assert(nonce_message:class() == Protocol.nonce_message)
   if self.status == Protocol.status.responder then
      -- responder -> offer_challenge
      self:intern_nonce(nonce_message)
      self.status = Protocol.status.offer_challenge
   else return Protocol.code.protocol end
end

function Protocol:offer_challenge (challenge_message)
   assert(challenge_message:class() == Protocol.challenge_message)
   if self.status == Protocol.status.offer_challenge then
      -- offer_challenge -> responder
      self.status = Protocol.status.responder
      return nil, self:send_challenge(challenge_message)
   else return Protocol.code.protocol end
end

function Protocol:receive_challenge (challenge_message)
   assert(challenge_message:class() == Protocol.challenge_message)
   if self.status == Protocol.status.accept_challenge then
      -- accept_challenge -> offer_nonce_key
      if self:intern_challenge_nonce(challenge_message) then
         self.status = Protocol.status.offer_nonce_key
      else return Protocol.code.authentication end
   else return Protocol.code.protocol end
end

function Protocol:offer_key (key_message)
   assert(key_message:class() == Protocol.key_message)
   if self.status == Protocol.status.offer_key then
      -- offer_key -> responder
      local response = self:send_key(key_message)
      self:reset()
      self.status = Protocol.status.responder
      return nil, response
   else return Protocol.code.protocol end
end

function Protocol:receive_key (key_message)
   assert(key_message:class() == Protocol.key_message)
   if self.status == Protocol.status.accept_key then
      -- accept_key -> initiator
      if self:intern_key(key_message) then
         local ok, inbound_sa, outbound_sa = self:derive_ephemeral_keys()
         if ok then
            self:reset()
            self.status = Protocol.status.initiator
            return nil, inbound_sa, outbound_sa
         else return Protocol.code.parameter end
      else return Protocol.code.authentication end
   else return Protocol.code.protocol end
end

function Protocol:offer_nonce_key (nonce_key_message)
   assert(nonce_key_message:class() == Protocol.nonce_key_message)
   if self.status == Protocol.status.offer_nonce_key then
      -- offer_nonce_key -> accept_key
      self.status = Protocol.status.accept_key
      self:set_deadline()
      return nil, self:send_key(self:send_nonce(nonce_key_message))
   else return Protocol.code.protocol end
end

function Protocol:receive_nonce_key (nonce_key_message)
   assert(nonce_key_message:class() == Protocol.nonce_key_message)
   if self.status == Protocol.status.responder then
      -- responder -> offer_key
      self:intern_nonce(nonce_key_message)
      if self:intern_key(nonce_key_message) then
         local ok, inbound_sa, outbound_sa = self:derive_ephemeral_keys()
         if ok then
            self.status = Protocol.status.offer_key
            return nil, inbound_sa, outbound_sa
         else return Protocol.code.parameter end
      else return Protocol.code.authentication end
   else return Protocol.code.protocol end
end

function Protocol:reset_if_expired ()
   if self.status == Protocol.status.accept_challenge
   or self.status == Protocol.status.accept_key then
      if self.deadline and self.deadline() then
         -- accept_challenge, accept_key -> initiator
         self:reset('reuse_spi') -- renegotiate this SA and possibly update it
         self.status = Protocol.status.initiator
         return Protocol.code.expired
      end
   else return Protocol.code.protocol end
end

-- Internal methods

function Protocol:send_nonce (nonce_message)
   nonce_message:nonce(self.n1)
   return nonce_message
end

function Protocol:intern_nonce (nonce_message)
   ffi.copy(self.n2, nonce_message:nonce(), ffi.sizeof(self.n2))
end

function Protocol:send_key (key_message)
   local r, k, n1, n2, spi1, p1 =
      self.r, self.k, self.n1, self.n2, self.spi1, self.p1
   local state, h1 = self.hmac_state, self.h
   C.crypto_auth_hmacsha512256_init(state, k, ffi.sizeof(k))
   C.crypto_auth_hmacsha512256_update(state, r.bytes, ffi.sizeof(r))
   C.crypto_auth_hmacsha512256_update(state, n1, ffi.sizeof(n1))
   C.crypto_auth_hmacsha512256_update(state, n2, ffi.sizeof(n2))
   C.crypto_auth_hmacsha512256_update(state, spi1.bytes, ffi.sizeof(spi1))
   C.crypto_auth_hmacsha512256_update(state, p1, ffi.sizeof(p1))
   C.crypto_auth_hmacsha512256_final(state, h1)
   key_message:spi(spi1.bytes)
   key_message:public_key(p1)
   key_message:auth_code(h1)
   return key_message
end

function Protocol:intern_key (m)
   local r, k, n1, n2, spi2, p2 =
      self.r, self.k, self.n1, self.n2, self.spi2, self.p2
   local state, h2 = self.hmac_state, self.h
   C.crypto_auth_hmacsha512256_init(state, k, ffi.sizeof(k))
   C.crypto_auth_hmacsha512256_update(state, r.bytes, ffi.sizeof(r))
   C.crypto_auth_hmacsha512256_update(state, n2, ffi.sizeof(n2))
   C.crypto_auth_hmacsha512256_update(state, n1, ffi.sizeof(n1))
   C.crypto_auth_hmacsha512256_update(state, m:spi(), ffi.sizeof(spi2))
   C.crypto_auth_hmacsha512256_update(state, m:public_key(), ffi.sizeof(p2))
   C.crypto_auth_hmacsha512256_final(state, h2)
   if C.sodium_memcmp(h2, m:auth_code(), ffi.sizeof(h2)) == 0 then
      ffi.copy(spi2.bytes, m:spi(), ffi.sizeof(spi2))
      ffi.copy(p2, m:public_key(), ffi.sizeof(p2))
      return true
   end
end

function Protocol:intern_challenge_nonce (m)
   local r, k, n1 = self.r, self.k, self.n1
   local state, c = self.hmac_state, self.h
   C.crypto_auth_hmacsha512256_init(state, k, ffi.sizeof(k))
   C.crypto_auth_hmacsha512256_update(state, r.bytes, ffi.sizeof(r))
   C.crypto_auth_hmacsha512256_update(state, m:nonce(), ffi.sizeof(m:nonce()))
   C.crypto_auth_hmacsha512256_update(state, n1, ffi.sizeof(n1))
   C.crypto_auth_hmacsha512256_final(state, c)
   if C.sodium_memcmp(c, m:auth_code(), ffi.sizeof(c)) == 0 then
      self:intern_nonce(m)
      return true
   end
end

function Protocol:send_challenge (challenge_message)
   local r, k, n1, n2 = self.r, self.k, self.n1, self.n2
   local state, c = self.hmac_state, self.h
   C.crypto_auth_hmacsha512256_init(state, k, ffi.sizeof(k))
   C.crypto_auth_hmacsha512256_update(state, r.bytes, ffi.sizeof(r))
   C.crypto_auth_hmacsha512256_update(state, n1, ffi.sizeof(n1))
   C.crypto_auth_hmacsha512256_update(state, n2, ffi.sizeof(n2))
   C.crypto_auth_hmacsha512256_final(state, c)
   challenge_message:auth_code(c)
   return self:send_nonce(challenge_message)
end

function Protocol:derive_ephemeral_keys ()
   if self:derive_shared_secret() then
      local inbound = self:derive_key_material(self.spi1, self.p1, self.p2)
      local outbound = self:derive_key_material(self.spi2, self.p2, self.p1)
      return true, inbound, outbound
   end
end

function Protocol:derive_shared_secret ()
   return C.crypto_scalarmult_curve25519(self.q, self.s1, self.p2) == 0
end

function Protocol:derive_key_material (spi, salt_a, salt_b)
   local q, e, state = self.q, self.e, self.hash_state
   C.crypto_generichash_blake2b_init(state, nil, 0, ffi.sizeof(e))
   C.crypto_generichash_blake2b_update(state, q, ffi.sizeof(q))
   C.crypto_generichash_blake2b_update(state, salt_a, ffi.sizeof(salt_a))
   C.crypto_generichash_blake2b_update(state, salt_b, ffi.sizeof(salt_b))
   C.crypto_generichash_blake2b_final(state, e.bytes, ffi.sizeof(e.bytes))
   return { spi = lib.ntohl(spi.u32),
            key = ffi.string(e.slot.key, ffi.sizeof(e.slot.key)),
            salt = ffi.string(e.slot.salt, ffi.sizeof(e.slot.salt)) }
end

function Protocol:set_deadline (deadline)
   if deadline == nil then self.deadline = lib.timeout(self.timeout)
   else                    self.deadline = deadline end
end

function Protocol:reset (reuse_spi)
   self:set_deadline(false)
   if not reuse_spi then self:next_spi() end
   self:next_nonce()
   self:next_dh_key()
   self:clear_external_inputs()
   return self
end

function Protocol:next_spi ()
   self.spi1.u32 = lib.htonl(Protocol.spi_counter + 256)
   Protocol.spi_counter = (Protocol.spi_counter + 1) % (2^32 - 1 - 256)
end

function Protocol:next_nonce ()
   C.randombytes_buf(self.n1, ffi.sizeof(self.n1))
end

function Protocol:next_dh_key ()
   C.randombytes_buf(self.s1, ffi.sizeof(self.s1))
   C.crypto_scalarmult_curve25519_base(self.p1, self.s1)
end

function Protocol:clear_external_inputs ()
   ffi.fill(self.n2, ffi.sizeof(self.n2))
   ffi.fill(self.p2, ffi.sizeof(self.p2))
   ffi.fill(self.e.bytes, ffi.sizeof(self.e.bytes))
end

-- Assertions about the world                                              (-:

assert(Protocol.preshared_key_bytes == 32)
assert(Protocol.public_key_bytes == 32)
assert(Protocol.auth_code_bytes == 32)
assert(ffi.sizeof(Protocol.key_t) >= C.crypto_generichash_blake2b_BYTES_MIN)
assert(ffi.sizeof(Protocol.key_t) <= C.crypto_generichash_blake2b_BYTES_MAX)

-- Transport wrapper for vita-ske that encompasses an SPI to map requests to
-- routes, and a message type to facilitate parsing.
--
-- NB: might have to replace this with a UDP based header to get key exchange
-- requests through protocol filters.

Transport = {
   message_type = { nonce = 4, challenge = 5, key = 6, nonce_key = 7 },
   header = subClass(header)
}
Transport.header:init({
      [1] = ffi.typeof[[
            struct {
               uint32_t spi;
               uint8_t message_type;
               uint8_t reserved[3];
            } __attribute__((packed))
      ]]
})

-- Public API

function Transport.header:new (config)
   local o = Transport.header:superClass().new(self)
   o:spi(config.spi)
   o:message_type(config.message_type)
   return o
end

function Transport.header:spi (spi)
   local h = self:header()
   if spi ~= nil then
      h.spi = lib.htonl(spi)
   end
   return lib.ntohl(h.spi)
end

function Transport.header:message_type (message_type)
   local h = self:header()
   if message_type ~= nil then
      h.message_type = message_type
   end
   return h.message_type
end

-- Test Protocol FSM
function selftest ()
   local old_now = engine.now
   local now
   engine.now = function () return now end

   local function can_not_except (p, ops)
      if not ops.initiate_exchange then
         local e, m = p:initiate_exchange(Protocol.nonce_message:new{})
         assert(e == Protocol.code.protocol and not m)
      end
      if not ops.receive_nonce then
         local e = p:receive_nonce(Protocol.nonce_message:new{})
         assert(e == Protocol.code.protocol)
      end
      if not ops.offer_challenge then
         local e, m = p:offer_challenge(Protocol.challenge_message:new{})
         assert(e == Protocol.code.protocol and not m)
      end
      if not ops.receive_challenge then
         local e = p:receive_challenge(Protocol.challenge_message:new{})
         assert(e == Protocol.code.protocol)
      end
      if not ops.offer_key then
         local e, m = p:offer_key(Protocol.key_message:new{})
         assert(e == Protocol.code.protocol and not m)
      end
      if not ops.receive_key then
         local e, rx, tx = p:receive_key(Protocol.key_message:new{})
         assert(e == Protocol.code.protocol and not (rx or tx))
      end
      if not ops.offer_nonce_key then
         local e, m = p:offer_nonce_key(Protocol.nonce_key_message:new{})
         assert(e == Protocol.code.protocol and not m)
      end
      if not ops.receive_nonce_key then
         local e, rx, tx = p:receive_nonce_key(Protocol.nonce_key_message:new{})
         assert(e == Protocol.code.protocol and not (rx or tx))
      end
      if not ops.reset_if_expired then
         local e = p:reset_if_expired()
         assert(e == Protocol.code.protocol)
      end
   end

   local key = ffi.new("uint8_t[20]");
   local A = Protocol:new('initiator', 1234, key, 2)
   local B = Protocol:new('responder', 1234, key, 2)

   now = 0

   can_not_except(A, {initiate_exchange=true})

   can_not_except(B, {receive_nonce=true, receive_nonce_key=true})
   local e, rx, tx = B:receive_nonce_key(Protocol.nonce_key_message:new{})
   assert(e == Protocol.code.authentication and not (rx or tx))
   local C = Protocol:new('offer_nonce_key', 1234, key, 2)
   ffi.copy(C.n2, B.n1, ffi.sizeof(C.n2))
   ffi.fill(C.p1, ffi.sizeof(C.p1))
   local _, nonce_key_c = C:offer_nonce_key(Protocol.nonce_key_message:new{})
   local e, rx, tx = B:receive_nonce_key(nonce_key_c)
   assert(e == Protocol.code.parameter and not (rx or tx))

   -- A: initiator -> accept_challenge
   local e, nonce_a = A:initiate_exchange(Protocol.nonce_message:new{})
   assert(not e and nonce_a)

   can_not_except(A, {receive_challenge=true, reset_if_expired=true})

   -- B: responder -> offer_challenge
   local e = B:receive_nonce(nonce_a)
   assert(not e)

   can_not_except(B, {offer_challenge=true})

   -- B: offer_challenge -> responder
   local e, challenge_b = B:offer_challenge(Protocol.challenge_message:new{})
   assert(not e and challenge_b)

   -- A: accept_challenge -> offer_nonce_key
   local e = A:receive_challenge(challenge_b)
   assert(not e)

   can_not_except(A, {offer_nonce_key=true})

   -- A: offer_nonce_key -> accept_key
   local e, nonce_key_a = A:offer_nonce_key(Protocol.nonce_key_message:new{})
   assert(not e and nonce_key_a)

   can_not_except(A, {receive_key=true, reset_if_expired=true})
   local e, rx, tx = A:receive_key(Protocol.key_message:new{})
   assert(e == Protocol.code.authentication and not (rx or tx))
   local C = Protocol:new('offer_key', 1234, key, 2)
   ffi.copy(C.n1, B.n1, ffi.sizeof(C.n1))
   ffi.copy(C.n2, A.n1, ffi.sizeof(C.n2))
   ffi.fill(C.p1, ffi.sizeof(C.p1))
   ffi.copy(C.p2, A.p1, ffi.sizeof(C.p2))
   local _, key_c = C:offer_key(Protocol.key_message:new{})
   local e, rx, tx = A:receive_key(key_c)
   assert(e == Protocol.code.parameter and not (rx or tx))

   -- B: responder -> offer_key
   local e, B_rx, B_tx = B:receive_nonce_key(nonce_key_a)
   assert(not e and B_rx and B_tx)

   can_not_except(B, {offer_key=true})

   -- B: offer_key -> responder
   local e, key_b = B:offer_key(Protocol.key_message:new{})
   assert(not e and key_b)

   -- A: accept_key -> initator
   local e, A_rx, A_tx = A:receive_key(key_b)
   assert(not e and A_rx and A_tx)

   -- Ephemeral keys should match
   assert(A_rx.key == B_tx.key)
   assert(A_rx.salt == B_tx.salt)
   assert(A_tx.key == B_rx.key)
   assert(A_tx.salt == B_rx.salt)

   -- Test negotiation expiry
   now = 10

   -- A: initiator -> accept_challenge
   A:initiate_exchange(Protocol.nonce_message:new{})
   assert(not A:reset_if_expired())

   -- accept_challenge -> initiator
   now = 12.0123
   assert(A:reset_if_expired() == Protocol.code.expired)

   --  A: accept_challenge -> offer_nonce_key -> accept_key
   local _, nonce_a = A:initiate_exchange(Protocol.nonce_message:new{})
   B:receive_nonce(nonce_a)
   local _, challenge_b = B:offer_challenge(Protocol.challenge_message:new{})
   A:receive_challenge(challenge_b)
   now = 20
   A:offer_nonce_key(Protocol.nonce_key_message:new{})

   assert(not A:reset_if_expired())

   -- A: accept_key -> initiator
   now = 30
   assert(A:reset_if_expired() == Protocol.code.expired)

   engine.now = old_now
end
