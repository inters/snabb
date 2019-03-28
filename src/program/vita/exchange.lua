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
--        version_errors          count of challenge requests with incompatible
--                                protocol versions (initiator)
--
--        aead_errors             count of challenge requests with incompatible
--                                AEAD proposals.
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
--  2. The Protocol subsystem implements vita-ske 4 (the cryptographic key
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
--        receive_knock
--        offer_challenge
--        receive_challenge
--        offer_proposal
--        receive_proposal
--        offer_agreement
--        receive_agreement
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
local crypto = require("program.vita.crypto")
local noise_NNpsk0 = require("program.vita.noise_NNpsk0")

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
      version_errors = {counter},
      parameter_errors = {counter},
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
      transport_in = Transport.header:new({}),
      knock_message = Protocol.knock_message:new({}),
      knock_message_in = Protocol.knock_message:new({}),
      challenge_message = Protocol.challenge_message:new({}),
      challenge_message_in = Protocol.challenge_message:new({}),
      proposal_message = Protocol.proposal_message:new({}),
      proposal_message_in = Protocol.proposal_message:new({}),
      agreement_message = Protocol.agreement_message:new({}),
      agreement_message_in = Protocol.agreement_message:new({}),
      sa_db_updated = false,
      sa_db_commit_throttle = lib.throttle(1),
      rate_bucket = KeyManager.max_pps,
      rate_throttle = lib.throttle(1)
   }
   local self = setmetatable(o, { __index = KeyManager })
   self:reconfig(conf)
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
   local ecode, knock_message =
      route.initiator:initiate_exchange(self.knock_message)
   if not ecode then
      counter.add(self.shm.negotiations_initiated)
      self.audit:log("Initiating negotiation for '"..route.id.."'")
      link.transmit(self.output.output, self:request(route, knock_message))
   else assert(ecode == Protocol.code.protocol) end
end

function KeyManager:handle_negotiation (request)
   local route, message = self:parse_request(request)

   if not (self:handle_knock_request(route, message)
           or self:handle_challenge_request(route, message)
           or self:handle_proposal_request(route, message)
           or self:handle_agreement_request(route, message)) then
      counter.add(self.shm.rxerrors)
      self.audit:log(("Rejected invalid negotiation request for '%s'")
            :format(route or "<unknown>"))
   end
end

function KeyManager:handle_knock_request (route, message)
   if not route or message ~= self.knock_message_in then return end

   -- Receive challenge request message if the protocol fsm permits
   -- (responder -> offer_challenge), otherwise reject the message and return.
   local ecode = route.responder:receive_knock(message)
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
   if not route or message ~= self.challenge_message_in then return end

   -- Receive challenge message if the protocol fsm permits
   -- (accept_challenge -> offer_proposal), reject the message and return
   -- otherwise or if...
   local ecode = route.initiator:receive_challenge(message)
   if ecode == Protocol.code.protocol then
      counter.add(self.shm.protocol_errors)
      return false
   elseif ecode == Protocol.code.version then
      -- ...the protocol version is incompatible,
      counter.add(self.shm.version_errors)
      return false
   elseif ecode == Protocol.code.parameter then
      -- ...or the proposed parameters are incompatible.
      counter.add(self.shm.parameter_errors)
      return false
   else assert(not ecode) end

   counter.add(self.shm.challenges_accepted)
   self.audit:log("Received challenge for '"..route.id.."'")

   -- If we got here we should offer an authenticated key exchange proposal
   -- (offer_proposal -> accept_agreement).
   local response = self.proposal_message
   local ecode, response = route.initiator:offer_proposal(response)
   assert(not ecode)

   self.audit:log("Proposing key exchange for '"..route.id.."'")
   link.transmit(self.output.output, self:request(route, response))

   return true
end

function KeyManager:handle_proposal_request (route, message)
   if not route or message ~= self.proposal_message_in then return end

   -- Receive an authenticated key exchange proposal if the protocol fsm
   -- permits (responder -> offer_agreement), reject the message and return
   -- otherwise if...
   local ecode = route.responder:receive_proposal(message)
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

   -- If we got here we should respond with an agreement
   -- (offer_agreement -> responder).
   local ecode, response, inbound_sa, outbound_sa =
      route.responder:offer_agreement(self.agreement_message)
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

function KeyManager:handle_agreement_request (route, message)
   if not route or message ~= self.agreement_message_in then return end

   -- Receive an authenticated key exchange agreement if the protocol fsm
   -- permits (accept_agreement -> initiator), reject the message and return
   -- otherwise or if...
   local ecode, inbound_sa, outbound_sa =
      route.initiator:receive_agreement(message)
   if ecode == Protocol.code.protocol then
      counter.add(self.shm.protocol_errors)
      return false
   elseif ecode == Protocol.code.authentication then
      -- ...the message failed to authenticate.
      counter.add(self.shm.authentication_errors)
      return false
   elseif ecode == Protocol.code.parameter then
      -- ...or the proposed DH parameters are unsafe.
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
         message_type = (message == self.knock_message
                            and Transport.message_type.knock)
                     or (message == self.challenge_message
                            and Transport.message_type.challenge)
                     or (message == self.proposal_message
                            and Transport.message_type.proposal)
                     or (message == self.agreement_message
                            and Transport.message_type.agreement)
   })

   packet.append(request, self.transport:header(), Transport.header:sizeof())

   packet.append(request, message:header(), message:sizeof())

   return request
end

function KeyManager:parse_request (request)
   local transport =
      self.transport_in:new_from_mem(request.data, request.length)
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
         (transport:message_type() == Transport.message_type.knock
             and self.knock_message_in:new_from_mem(data, length))
      or (transport:message_type() == Transport.message_type.challenge
             and self.challenge_message_in:new_from_mem(data, length))
      or (transport:message_type() == Transport.message_type.proposal
             and self.proposal_message_in:new_from_mem(data, length))
      or (transport:message_type() == Transport.message_type.agreement
             and self.agreement_message_in:new_from_mem(data, length))
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

-- Vita: simple key exchange (vita-ske, version 4). See README.exchange

Message = subClass(header)
function Message:new_from_mem (mem, size)
   if size == self:sizeof() then
      return Message:superClass().new_from_mem(self, mem, size)
   end
end

Protocol = {
   version = 0x0004,
   -- protocol states: responder states are even and initiator states are odd
   -- (this is important!)
   status = { responder = 0, initiator = 1,
              offer_challenge = 2, accept_challenge = 3, offer_proposal = 5,
              offer_agreement = 6, accept_agreement = 7 },
   code = { protocol = 0, authentication = 1, parameter = 2, expired = 3,
            version = 4 },
   preshared_key_bytes = 32,
   spi_counter = 0,
   -- payload can be up to 32 bytes (see noise_NNpsk0.HanshakeState.message_t)
   payload_t = ffi.typeof[[
      struct {
         uint32_t spi;
      } __attribute__((packed))
   ]],
   key_t = ffi.typeof[[
      union {
         uint8_t bytes[20];
         struct {
            uint8_t key[16];
            uint8_t salt[4];
         } __attribute__((packed)) slot;
      }
   ]],
   prologue = subClass(header),
   knock_message = subClass(Message),
   challenge_message = subClass(Message),
   proposal_message = subClass(Message),
   agreement_message = subClass(Message)
}

Protocol.prologue:init({
      [1] = ffi.typeof[[
         struct {
            uint32_t version, route_spi;
            uint8_t aead[32], nonce[32];
         } __attribute__((packed))
      ]]
})

function Protocol.prologue:new (config)
   local o = Protocol.prologue:superClass().new(self)
   o:version(config.version or Protocol.version)
   o:route_spi(config.route_spi)
   o:aead(config.aead)
   o:nonce(config.nonce)
   return o
end

function Protocol.prologue:version (version)
   local h = self:header()
   if version ~= nil then
      h.version = lib.htonl(version)
   end
   return lib.ntohl(h.version)
end

function Protocol.prologue:route_spi (spi)
   local h = self:header()
   if spi ~= nil then
      h.route_spi = lib.htonl(spi)
   end
   return lib.ntohl(h.route_spi)
end

function Protocol.prologue:aead (aead)
   local h = self:header()
   if aead ~= nil then
      local len = (type(aead) == 'string' and #aead) or ffi.sizeof(aead)
      assert(len <= ffi.sizeof(h.aead), "AEAD identifier overflow")
      ffi.copy(h.aead, aead, len)
   end
   return h.aead
end

function Protocol.prologue:aead_eq (aead)
   assert(ffi.sizeof(aead) == ffi.sizeof(self:aead()))
   return crypto.bytes_equal(self:aead(), aead, ffi.sizeof(self:aead()))
end

function Protocol.prologue:nonce (nonce)
   local h = self:header()
   if nonce ~= nil then
      ffi.copy(h.nonce, nonce, ffi.sizeof(h.nonce))
   end
   return h.nonce
end

Protocol.knock_message:init({
      [1] = ffi.typeof([[
            struct {
               uint32_t version;
            } __attribute__((packed))
      ]])
})

Protocol.challenge_message:init({
      [1] = ffi.typeof([[
            struct {
               uint32_t version;
               uint8_t aead[32], nonce[32];
            } __attribute__((packed))
      ]])
})

Protocol.proposal_message:init({
      [1] = noise_NNpsk0.HandshakeState.message_t
})

Protocol.agreement_message:init({
      [1] = noise_NNpsk0.HandshakeState.message_t
})

-- Public API

function Protocol.knock_message:new ()
   local o = Protocol.knock_message:superClass().new(self)
   o:version(Protocol.version)
   return o
end

Protocol.knock_message.version = Protocol.prologue.version

function Protocol.challenge_message:new (config)
   local o = Protocol.challenge_message:superClass().new(self)
   o:version(config.version or Protocol.version)
   o:aead(config.aead)
   o:nonce(config.nonce)
   return o
end

Protocol.challenge_message.version = Protocol.prologue.version
Protocol.challenge_message.aead = Protocol.prologue.aead
Protocol.challenge_message.nonce = Protocol.prologue.nonce

function Protocol.proposal_message:new (config)
   local o = Protocol.proposal_message:superClass().new(self)
   o:spi(config.spi)
   return o
end

function Protocol.proposal_message:spi (spi)
   local h = self:header()
   local payload = ffi.cast(ffi.typeof("$ *", Protocol.payload_t), h.payload)
   if spi ~= nil then
      payload.spi = lib.htonl(spi)
   end
   return lib.ntohl(payload.spi)
end

function Protocol.agreement_message:new (config)
   local o = Protocol.agreement_message:superClass().new(self)
   o:spi(config.spi)
   return o
end

Protocol.agreement_message.spi = Protocol.proposal_message.spi

function Protocol:new (initial_status, route_spi, key, timeout)
   local status = assert(Protocol.status[initial_status],
                         "Invalid status: "..initial_status)
   local initiator = status % 2 ~= 0
   local psk = ffi.new("uint8_t[?]", Protocol.preshared_key_bytes)
   ffi.copy(psk, key, ffi.sizeof(psk))
   local o = {
      status = status,
      timeout = timeout,
      deadline = false,
      spi = 0,
      remote_spi = 0,
      prologue = Protocol.prologue:new{
         route_spi = route_spi,
         aead = "aes-gcm-16-icv",
      },
      handshake = noise_NNpsk0.HandshakeState:new(psk, initiator),
      rx = ffi.new(Protocol.key_t),
      tx = ffi.new(Protocol.key_t)
   }
   return setmetatable(o, {__index=Protocol}):reset()
end

function Protocol:initiate_exchange (knock_msg)
   assert(knock_msg:class() == Protocol.knock_message)
   if self.status == Protocol.status.initiator then
      -- initiator -> accept_challenge
      self:set_deadline()
      self.status = Protocol.status.accept_challenge
      return nil, knock_msg:new{}
   else return Protocol.code.protocol end
end

function Protocol:receive_knock (knock_msg)
   assert(knock_msg:class() == Protocol.knock_message)
   if self.status == Protocol.status.responder then
      -- responder -> offer_challenge
      self.status = Protocol.status.offer_challenge
   else return Protocol.code.protocol end
end

function Protocol:offer_challenge (challenge_msg)
   assert(challenge_msg:class() == Protocol.challenge_message)
   if self.status == Protocol.status.offer_challenge then
      -- offer_challenge -> responder
      self.status = Protocol.status.responder
      return nil, challenge_msg:new{
            aead = self.prologue:aead(),
            nonce = self.prologue:nonce()
      }
   else return Protocol.code.protocol end
end

function Protocol:receive_challenge (challenge_msg)
   assert(challenge_msg:class() == Protocol.challenge_message)
   if self.status == Protocol.status.accept_challenge then
      -- accept_challenge -> offer_proposal
      if challenge_msg:version() == self.prologue:version() then
         local aead = self.prologue:aead()
         if self.prologue:aead_eq(challenge_msg:aead()) then
            self.prologue:nonce(challenge_msg:nonce())
            self.handshake:init(self.prologue:header())
            self.status = Protocol.status.offer_proposal
         else return Protocol.code.parameter end
      else return Protocol.code.version end
   else return Protocol.code.protocol end
end

function Protocol:offer_proposal (proposal_msg)
   assert(proposal_msg:class() == Protocol.proposal_message)
   if self.status == Protocol.status.offer_proposal then
      -- offer_proposal -> accept_agreement
      proposal_msg:spi(self.spi)
      self.handshake:writeMessageA(proposal_msg:header())
      self.status = Protocol.status.accept_agreement
      self:set_deadline()
      return nil, proposal_msg
   else return Protocol.code.protocol end
end

function Protocol:receive_proposal (proposal_msg)
   assert(proposal_msg:class() == Protocol.proposal_message)
   if self.status == Protocol.status.responder then
      -- responder -> offer_agreement
      local valid, dh_ok = self.handshake:readMessageA(proposal_msg:header())
      if valid then
         if dh_ok then
            self.remote_spi = proposal_msg:spi()
            self.status = Protocol.status.offer_agreement
         else return Protocol.code.parameter end
      else return Protocol.code.authentication end
   else return Protocol.code.protocol end
end

function Protocol:offer_agreement (agreement_msg)
   assert(agreement_msg:class() == Protocol.agreement_message)
   if self.status == Protocol.status.offer_agreement then
      -- offer_agreement -> responder
      agreement_msg:spi(self.spi)
      self.handshake:writeMessageB(agreement_msg:header(), self.rx, self.tx)
      local inbound_sa, outbound_sa = self:derive_ephemeral_keys()
      self.status = Protocol.status.responder
      self:reset()
      return nil, agreement_msg, inbound_sa, outbound_sa
   else return Protocol.code.protocol end
end

function Protocol:receive_agreement (agreement_msg)
   assert(agreement_msg:class() == Protocol.agreement_message)
   if self.status == Protocol.status.accept_agreement then
      -- accept_agreement -> initiator
      local valid, dh_ok =
         self.handshake:readMessageB(agreement_msg:header(), self.rx, self.tx)
      if dh_ok then
         if valid then
            self.remote_spi = agreement_msg:spi()
            local inbound_sa, outbound_sa = self:derive_ephemeral_keys()
            self.status = Protocol.status.initiator
            self:reset()
            return nil, inbound_sa, outbound_sa
         else return Protocol.code.authentication end
      else return Protocol.code.parameter end
   else return Protocol.code.protocol end
end

function Protocol:reset_if_expired ()
   if self.status == Protocol.status.accept_challenge
   or self.status == Protocol.status.accept_agreement then
      if self.deadline and self.deadline() then
         -- accept_challenge, accept_agreement -> initiator
         self.status = Protocol.status.initiator
         self:reset('reuse_spi') -- renegotiate this SA and possibly update it
         return Protocol.code.expired
      end
   else return Protocol.code.protocol end
end

-- Internal methods

function Protocol:derive_ephemeral_keys ()
   local inbound = self:derive_key_material(self.spi, self.rx)
   local outbound = self:derive_key_material(self.remote_spi, self.tx)
   return inbound, outbound
end

function Protocol:derive_key_material (spi, keymat)
   return { spi = spi,
            key = ffi.string(keymat.slot.key, ffi.sizeof(keymat.slot.key)),
            salt = ffi.string(keymat.slot.salt, ffi.sizeof(keymat.slot.salt)) }
end

function Protocol:set_deadline (deadline)
   if deadline == nil then self.deadline = lib.timeout(self.timeout)
   else                    self.deadline = deadline end
end

function Protocol:reset (reuse_spi)
   self:set_deadline(false)
   self:clear_external_inputs()
   self.handshake:clear()
   if not reuse_spi then self:next_spi() end
   if self.status == Protocol.status.responder then
      self:next_nonce()
      self.handshake:init(self.prologue:header())
   end
   return self
end

function Protocol:next_spi ()
   self.spi = Protocol.spi_counter + 256
   Protocol.spi_counter = (Protocol.spi_counter + 1) % (2^16 - 1 - 256)
end

function Protocol:next_nonce ()
   local nonce = self.prologue:nonce()
   crypto.random_bytes(nonce, ffi.sizeof(nonce))
end

function Protocol:clear_external_inputs ()
   self.remote_spi = 0
   ffi.fill(self.prologue:nonce(), ffi.sizeof(self.prologue:nonce()))
   ffi.fill(self.rx, ffi.sizeof(self.rx))
   ffi.fill(self.tx, ffi.sizeof(self.tx))
end

-- Transport wrapper for vita-ske that encompasses an SPI to map requests to
-- routes, and a message type to facilitate parsing.
--
-- NB: might have to replace this with a UDP based header to get key exchange
-- requests through protocol filters.

Transport = {
   message_type = {knock = 11, challenge = 12, proposal = 13, agreement = 14},
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
         local e, m = p:initiate_exchange(Protocol.knock_message:new{})
         assert(e == Protocol.code.protocol and not m)
      end
      if not ops.receive_knock then
         local e = p:receive_knock(Protocol.knock_message:new{})
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
      if not ops.offer_proposal then
         local e, m = p:offer_proposal(Protocol.proposal_message:new{})
         assert(e == Protocol.code.protocol and not m)
      end
      if not ops.receive_proposal then
         local e = p:receive_proposal(Protocol.proposal_message:new{})
         assert(e == Protocol.code.protocol)
      end
      if not ops.offer_agreement then
         local e, m, rx, tx = p:offer_agreement(Protocol.agreement_message:new{})
         assert(e == Protocol.code.protocol and not m and not (rx or tx))
      end
      if not ops.receive_agreement then
         local e, rx, tx = p:receive_agreement(Protocol.agreement_message:new{})
         assert(e == Protocol.code.protocol and not (rx or tx))
      end
      if not ops.reset_if_expired then
         local e = p:reset_if_expired()
         assert(e == Protocol.code.protocol)
      end
   end

   local key = ffi.new("uint8_t[?]", Protocol.preshared_key_bytes);
   local A = Protocol:new('initiator', 1234, key, 2)
   local B = Protocol:new('responder', 1234, key, 2)
   local n1 = ffi.new("uint8_t[32]")
   ffi.copy(n1, B.prologue:nonce(), ffi.sizeof(n1))

   now = 0

   can_not_except(A, {initiate_exchange=true})

   can_not_except(B, {receive_knock=true, receive_proposal=true})
   local e = B:receive_proposal(Protocol.proposal_message:new{})
   assert(e == Protocol.code.authentication)
   local C = Protocol:new('offer_proposal', 1234, key, 2)
   C.prologue:nonce(B.prologue:nonce())
   C.handshake:init(C.prologue:header())
   ffi.fill(C.handshake.e.pk, ffi.sizeof(C.handshake.e.pk))
   local _, proposal_c = C:offer_proposal(Protocol.proposal_message:new{})
   local e = B:receive_proposal(proposal_c)
   assert(e == Protocol.code.parameter)

   -- A: initiator -> accept_challenge
   local e, knock_a = A:initiate_exchange(Protocol.knock_message:new{})
   assert(not e and knock_a)

   can_not_except(A, {receive_challenge=true, reset_if_expired=true})
   local e = A:receive_challenge(Protocol.challenge_message:new{
                                    version = 0, -- incompatible version
                                    aead = "aes-gcm-16-icv"
   })
   assert(e == Protocol.code.version)
   local e = A:receive_challenge(Protocol.challenge_message:new{
                                    version = Protocol.version,
                                    aead = "foobar" -- incompatible AEAD
   })
   assert(e == Protocol.code.parameter)

   -- B: responder -> offer_challenge
   local e = B:receive_knock(knock_a)
   assert(not e)

   can_not_except(B, {offer_challenge=true})

   -- B: offer_challenge -> responder
   local e, challenge_b = B:offer_challenge(Protocol.challenge_message:new{})
   assert(not e and challenge_b)

   -- A: accept_challenge -> offer_proposal
   local e = A:receive_challenge(challenge_b)
   assert(not e)

   can_not_except(A, {offer_proposal=true})

   -- A: offer_proposal -> accept_agreement
   local e, proposal_a = A:offer_proposal(Protocol.proposal_message:new{})
   assert(not e and proposal_a)

   can_not_except(A, {receive_agreement=true, reset_if_expired=true})
   local bogus_agreement = Protocol.agreement_message:new{}
   crypto.random_bytes(bogus_agreement:header().ne,
                       ffi.sizeof(bogus_agreement:header().ne))
   local e, rx, tx = A:receive_agreement(bogus_agreement)
   assert(e == Protocol.code.authentication and not (rx or tx))
   local e, rx, tx = A:receive_agreement(Protocol.agreement_message:new{})
   assert(e == Protocol.code.parameter and not (rx or tx))

   -- B: responder -> offer_agreement
   local e = B:receive_proposal(proposal_a)
   assert(not e)

   can_not_except(B, {offer_agreement=true})

   -- B: offer_agreement -> responder
   local e, agreement_b, B_rx, B_tx =
      B:offer_agreement(Protocol.agreement_message:new{})
   assert(not e and agreement_b and B_rx and B_tx)

   -- A: accept_agreement -> initator
   local e, A_rx, A_tx = A:receive_agreement(agreement_b)
   assert(not e and A_rx and A_tx)

   -- Ephemeral keys should match
   assert(A_rx.key == B_tx.key)
   assert(A_rx.salt == B_tx.salt)
   assert(A_tx.key == B_rx.key)
   assert(A_tx.salt == B_rx.salt)

   -- Ensure nonces cycle
   assert(not crypto.bytes_equal(n1, B.prologue:nonce(), ffi.sizeof(n1)))

   -- Test negotiation expiry
   now = 10

   -- A: initiator -> accept_challenge
   A:initiate_exchange(Protocol.knock_message:new{})
   assert(not A:reset_if_expired())

   -- accept_challenge -> initiator
   now = 12.0123
   assert(A:reset_if_expired() == Protocol.code.expired)

   --  A: accept_challenge -> offer_proposal -> accept_agreement
   local _, knock_a = A:initiate_exchange(Protocol.knock_message:new{})
   B:receive_knock(knock_a)
   local _, challenge_b = B:offer_challenge(Protocol.challenge_message:new{})
   A:receive_challenge(challenge_b)
   now = 20
   A:offer_proposal(Protocol.proposal_message:new{})

   assert(not A:reset_if_expired())

   -- A: accept_agreement -> initiator
   now = 30
   assert(A:reset_if_expired() == Protocol.code.expired)

   engine.now = old_now
end
