-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

local counter = require("core.counter")
local esp = require("lib.ipsec.esp")
local ipv4 = require("lib.protocol.ipv4")
local ipv6 = require("lib.protocol.ipv6")

-- sa := { spi=(SPI), aead=(STRING), key=(KEY), salt=(SALT),
--         [ window_size=(INT),
--           resync_threshold=(INT), resync_attempts=(INT),
--           auditing=(BOOL) ] }

-- https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
local NextHeaderIPv4 = 4
local NextHeaderIPv6 = 41

Encapsulate = {
   name = "Encapsulate",
   config = {
      spi = {required=true},
      aead = {required=true},
      key = {required=true},
      salt = {required=true},
      tfc_mtu = {}
   }
}

function Encapsulate:new (sa)
   return setmetatable({sa = esp.encrypt:new(sa), tfc_mtu = sa.tfc_mtu},
                       {__index = Encapsulate})
end

function Encapsulate:push ()
   local output, sa = self.output.output, self.sa
   local nh = (self.input.input4 and NextHeaderIPv4) or
              (self.input.input6 and NextHeaderIPv6)
   local input = self.input.input4 or self.input.input6
   while not link.empty(input) do
      local p = link.receive(input)
      if self.tfc_mtu then
         -- Pad to MTU for Traffic Flow Confidientiality (TFC)
         p = packet.resize(p, math.max(p.length, self.tfc_mtu))
      end
      link.transmit(output, sa:encapsulate_tunnel(p, nh))
   end
end


Decapsulate = {
   name = "Decapsulate",
   config = {
      spi = {required=true},
      aead = {required=true},
      key = {required=true},
      salt = {required=true},
      window_size = {},
      resync_threshold = {default=1/0}, -- disable resynchronization
      resync_attempts = {},
      auditing = {}
   },
   shm = {
      rxerrors = {counter},
      protocol_errors = {counter},
      decrypt_errors = {counter}
   }
}

function Decapsulate:new (sa)
   return setmetatable({sa = esp.decrypt:new(sa)}, {__index = Decapsulate})
end

function Decapsulate:push ()
   local input, sa = self.input.input, self.sa
   local output4, output6 = self.output.output4, self.output.output6
   while not link.empty(input) do
      local p_enc = link.receive(input)
      local p, next_header = sa:decapsulate_tunnel(p_enc)
      if p and next_header == NextHeaderIPv4 and output4 then
         link.transmit(output4, p)
      elseif p and next_header == NextHeaderIPv6 and output6 then
         link.transmit(output6, p)
      elseif p then
         counter.add(self.shm.rxerrors)
         counter.add(self.shm.protocol_errors)
         packet.free(p)
      else
         counter.add(self.shm.rxerrors)
         counter.add(self.shm.decrypt_errors)
         packet.free(p_enc)
      end
   end
end


Tunnel4 = {
   name = "Tunnel4",
   config = {
      src = {required=true},
      dst = {required=true}
   }
}

function Tunnel4:new (conf)
   local o = {
      ip_template = ipv4:new{
         src = ipv4:pton(conf.src),
         dst = ipv4:pton(conf.dst),
         protocol = esp.PROTOCOL,
         flags = 2, -- Don’t Fragment
         ttl = 64
      },
      ip = ipv4:new{}
   }
   return setmetatable(o, {__index = Tunnel4})
end

function Tunnel4:push ()
   local input, output = self.input.input, self.output.output
   while not link.empty(input) do
      link.transmit(output, self:encapsulate(link.receive(input)))
   end
end

function Tunnel4:encapsulate (p)
   p = packet.prepend(p, self.ip_template:header(), ipv4:sizeof())
   self.ip:new_from_mem(p.data, ipv4:sizeof())
   self.ip:total_length(p.length)
   self.ip:checksum()
   return p
end


Tunnel6 = {
   name = "Tunnel6",
   config = {
      src = {required=true},
      dst = {required=true}
   }
}

function Tunnel6:new (conf)
   local o = {
      ip_template = ipv6:new{
         src = ipv6:pton(conf.src),
         dst = ipv6:pton(conf.dst),
         next_header = esp.PROTOCOL,
         hop_limit = 64
      }
   }
   return setmetatable(o, {__index = Tunnel6})
end

function Tunnel6:push ()
   local input, output = self.input.input, self.output.output
   while not link.empty(input) do
      link.transmit(output, self:encapsulate(link.receive(input)))
   end
end

function Tunnel6:encapsulate (p)
   self.ip_template:payload_length(p.length)
   p = packet.prepend(p, self.ip_template:header(), ipv6:sizeof())
   return p
end
