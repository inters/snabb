-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

-- Noise instance XXpsk3 based on noise_XXpsk3.go, see
-- https://noiseexplorer.com/patterns/XXpsk3/

local crypto = require("program.vita.crypto")
local aes_gcm = require("lib.ipsec.aes_gcm_avx")
local lib = require("core.lib")
local ffi = require("ffi")

local new, sizeof, copy, fill, typeof, cast =
   ffi.new, ffi.sizeof, ffi.copy, ffi.fill, ffi.typeof, ffi.cast
local band, rshift = bit.band, bit.rshift
local htonl = lib.htonl

-- XXpsk3:
--    -> e
--    <- e, ee, s, es
--    -> s, se, psk
--    <-
--    ->

-- Kludge: our AES-GCM implementation only supports AAD between four and
-- sixteen bytes (multiples of four.) Hence, we include 16 zero bytes of AAD
-- when none is needed, and hash supplied AAD exceeding 16 bytes to 16 bytes
-- using blake2s.

local name = "Noise_XXpsk3_25519_AESGCM_BLAKE2s"
local empty_key = ffi.new("uint8_t[32]")

local CipherState = {}

function CipherState:new ()
   local o = {
      k = new("uint8_t[32]"),
      n = 0ULL,
      aes_gcm_state = ffi.new("gcm_data __attribute__((aligned(16)))"),
      aes_gcm_block = ffi.new("uint8_t[16]"),
      aes_gcm_nonce = ffi.new("struct { uint32_t pad, benh, benl; }"),
      hash_state = ffi.new(crypto.blake2s_state_t),
      ad_hash = ffi.new("uint8_t[16]")
   }
   return setmetatable(o, {__index=CipherState})
end

function CipherState:clear ()
   fill(self.k, sizeof(self.k))
   self.n = 0ULL
   fill(self.aes_gcm_state, sizeof(self.aes_gcm_state))
   fill(self.aes_gcm_block, sizeof(self.aes_gcm_block))
   fill(self.aes_gcm_nonce, sizeof(self.aes_gcm_nonce))
end

function CipherState:initializeKey (k)
   local aes_gcm_s, hash_subkey = self.aes_gcm_state, self.aes_gcm_block
   copy(self.k, k, sizeof(self.k))
   self.n = 0ULL
   -- Initialize AES-GCM state
   aes_gcm.aes_keyexp_256_enc_avx(self.k, aes_gcm_s)
   fill(hash_subkey, sizeof(hash_subkey))
   aes_gcm.aesni_encrypt_256_single_block(aes_gcm_s, hash_subkey)
   aes_gcm.aesni_gcm_precomp_avx_gen4(aes_gcm_s, hash_subkey)
end

function CipherState:hasKey ()
   return not crypto.bytes_equal(self.k, empty_key, sizeof(self.k))
end

function CipherState:nonce (n)
   local nonce = self.aes_gcm_nonce
   nonce.benl = htonl(band(n or self.n, 0x00000000ffffffff))
   nonce.benh = htonl(rshift(n or self.n, 32))
   if not n then self.n = self.n + 1 end
   return cast("uint8_t*", nonce)
end

function CipherState:encryptWithAd (out, plaintext, len, ad, tag)
   local ad, adlen = ad or empty_key, ad and sizeof(ad) or 16
   if adlen > 16 then
      local hash_s, h = self.hash_state, self.ad_hash
      crypto.blake2s_init(hash_s, sizeof(h))
      crypto.blake2s_update(hash_s, ad, adlen)
      crypto.blake2s_final(hash_s, h, sizeof(h))
      ad, adlen = h, sizeof(h)
   end
   local aes_gcm_s = self.aes_gcm_state
   assert(adlen>=4 and adlen%4==0)
   aes_gcm.aesni_gcm_enc_256_avx_gen4(
      aes_gcm_s, out, plaintext, len, self:nonce(), ad, adlen, tag, 16
   )
end

function CipherState:decryptWithAd (out, ciphertext, len, ad, tag)
   local ad, adlen = ad or empty_key, ad and sizeof(ad) or 16
   if adlen > 16 then
      local hash_s, h = self.hash_state, self.ad_hash
      crypto.blake2s_init(hash_s, 16)
      crypto.blake2s_update(hash_s, ad, adlen)
      crypto.blake2s_final(hash_s, h, 16)
      ad, adlen = h, 16
   end
   local aes_gcm_s, auth = self.aes_gcm_state, self.aes_gcm_block
   assert(adlen>=4 and adlen%4==0)
   aes_gcm.aesni_gcm_dec_256_avx_gen4(
      aes_gcm_s, out, ciphertext, len, self:nonce(), ad, adlen, auth, 16
   )
   return aes_gcm.auth16_equal(tag, auth) == 0
end

function CipherState:reKey ()
   local k, aes_gcm_s, tag = self.k, self.aes_gcm_state, self.aes_gcm_block
   self.n = 2^64-1ULL
   self:encryptWithAd(k, empty_key, sizeof(k), nil, tag)
   self:initializeKey(k)
end

local SymmetricState = {}

function SymmetricState:new ()
   local o = {
      h = new("uint8_t[32]"),
      ck = new("uint8_t[32]"),
      cs = CipherState:new(),
      hkdf_state = new(crypto.hkdf_blake2s_state_t),
      hash_state = new(crypto.blake2s_state_t),
      tmp = new("struct { uint8_t a[32], b[32], c[32]; }")
   }
   SymmetricState.init(o)
   return setmetatable(o, {__index=SymmetricState})
end

function SymmetricState:init ()
   local hash_s, h, ck = self.hash_state, self.h, self.ck
   if #name <= 32 then
      copy(h, name, #name)
   else
      crypto.blake2s_init(hash_s, sizeof(h))
      crypto.blake2s_update(hash_s, name, #name)
      crypto.blake2s_final(hash_s, h, sizeof(h))
   end
   copy(ck, h, sizeof(ck))
end

function SymmetricState:clear ()
   fill(self.h, sizeof(self.h))
   fill(self.ck, sizeof(self.ck))
   self.cs:clear()
   fill(self.hkdf_state, sizeof(self.hkdf_state))
   fill(self.hash_state, sizeof(self.hash_state))
   fill(self.tmp, sizeof(self.tmp))
   self:init()
end

function SymmetricState:mixKey (ikm)
   local hkdf_s, tmp, ck, cs = self.hkdf_state, self.tmp, self.ck, self.cs
   crypto.hkdf_blake2s(hkdf_s, cast("uint8_t*", tmp), sizeof(tmp), ikm, ck)
   copy(ck, tmp.a, sizeof(ck))
   cs:initializeKey(tmp.b)
end

function SymmetricState:mixHash (data, len)
   local hash_s, h = self.hash_state, self.h
   crypto.blake2s_init(hash_s, sizeof(h))
   crypto.blake2s_update(hash_s, h, sizeof(h))
   crypto.blake2s_update(hash_s, data, len or sizeof(data))
   crypto.blake2s_final(hash_s, h, sizeof(h))
end

function SymmetricState:mixKeyAndHash (ikm)
   local hkdf_s, tmp, ck, cs = self.hkdf_state, self.tmp, self.ck, self.cs
   crypto.hkdf_blake2s(hkdf_s, cast("uint8_t*", tmp), sizeof(tmp), ikm, ck)
   copy(ck, tmp.a, sizeof(ck))
   self:mixHash(tmp.b)
   cs:initializeKey(tmp.c)
end

function SymmetricState:encryptAndHash (out, plaintext, len)
   local cs, h = self.cs, self.h
   if cs:hasKey() then
      cs:encryptWithAd(out, plaintext, len, h, out+len)
   else
      ffi.copy(out, plaintext, len)
   end
   self:mixHash(out, len+16)
end

function SymmetricState:decryptAndHash (out, ciphertext, len)
   local cs, h, ad = self.cs, self.h, self.tmp.a
   assert(sizeof(ad) == sizeof(h))
   copy(ad, h, sizeof(ad))
   self:mixHash(ciphertext, len+16)
   local valid
   if cs:hasKey() then
      valid = cs:decryptWithAd(out, ciphertext, len, ad, out+len)
   else
      ffi.copy(out, plaintext, len)
      valid = true
   end
   return valid
end

function SymmetricState:split (cs1, cs2)
   local hkdf_s, tmp, ck = self.hkdf_state, self.tmp, self.ck
   crypto.hkdf_blake2s(hkdf_s, cast("uint8_t*", tmp), sizeof(tmp), ck, empty_key)
   copy(cs1.k, tmp.a, sizeof(cs1.k))
   cs1:initializeKey(cs1.k)
   copy(cs2.k, tmp.b, sizeof(cs2.k))
   cs2:initializeKey(cs2.k)
end

local HandshakeState = {
   message_t = ffi.typeof[[
      struct { uint8_t ne[32], ns[32], nstag[16], payload[32], tag[16]; }
   ]]
}

function HandshakeState:new (prologue, s, psk, initiator)
   local o = {
      prologue = prologue,
      ss = SymmetricState:new(),
      s = s,
      e = new("struct { uint8_t pk[32], sk[32]; }"),
      re = new("uint8_t[32]"),
      rs = new("uint8_t[32]"),
      q = new("uint8_t[32]"),
      psk = psk,
      initiator = initiator
   }
   HandshakeState.init(o)
   return setmetatable(o, {__index=HandshakeState})
end

function HandshakeState:init ()
   self.ss:mixHash(self.prologue)
end

function HandshakeState:clear ()
   self.ss:clear()
   fill(self.e, sizeof(self.e))
   fill(self.re, sizeof(self.re))
   fill(self.rs, sizeof(self.rs))
   fill(self.q, sizeof(self.q))
   self:init()
end

function HandshakeState:dh (s, p)
   crypto.curve25519_scalarmult(self.q, s, p)
   return self.q
end

function HandshakeState:writeMessageA (msg)
   local ss, s, e = self.ss, self.s, self.e
   crypto.random_bytes(e.sk, sizeof(e.sk))
   crypto.curve25519_scalarmult_base(e.pk, e.sk)
   ss:mixHash(e.pk)
   ss:mixKey(e.pk)
   copy(msg.ne, e.pk, sizeof(msg.ne))
   fill(msg.ns, sizeof(msg.ns))
   fill(msg.nstag, sizeof(msg.nstag))
   ss:encryptAndHash(msg.payload, msg.payload, sizeof(msg.payload))
end

function HandshakeState:readMessageA (msg)
   local ss, re = self.ss, self.re
   copy(re, msg.ne, sizeof(re))
   ss:mixHash(re)
   ss:mixKey(re)
   return ss:decryptAndHash(msg.payload, msg.payload, sizeof(msg.payload))
end

function HandshakeState:writeMessageB (msg)
   local ss, s, e, re = self.ss, self.s, self.e, self.re
   crypto.random_bytes(e.sk, sizeof(e.sk))
   crypto.curve25519_scalarmult_base(e.pk, e.sk)
   ss:mixHash(e.pk)
   ss:mixKey(e.pk)
   ss:mixKey(self:dh(e.sk, re))
   copy(msg.ne, e.pk, sizeof(msg.ne))
   ss:encryptAndHash(msg.ns, s.pk, sizeof(msg.ns))
   ss:mixKey(self:dh(s.sk, re))
   ss:encryptAndHash(msg.payload, msg.payload, sizeof(msg.payload))
end

function HandshakeState:readMessageB (msg)
   local ss, e, re, rs = self.ss, self.e, self.re, self.rs
   copy(re, msg.ne, sizeof(re))
   ss:mixHash(re)
   ss:mixKey(re)
   ss:mixKey(self:dh(e.sk, re))
   if not ss:decryptAndHash(msg.ns, msg.ns, sizeof(msg.ns)) then
      return false
   end
   copy(rs, msg.ns, sizeof(rs))
   ss:mixKey(self:dh(e.sk, rs))
   return ss:decryptAndHash(msg.payload, msg.payload, sizeof(msg.payload))
end

function HandshakeState:writeMessageC (msg, cs1, cs2)
   local ss, s, re, psk = self.ss, self.s, self.re, self.psk
   fill(msg.ne, sizeof(msg.ne))
   ss:encryptAndHash(msg.ns, s.pk, sizeof(msg.ns))
   ss:mixKey(self:dh(s.sk, re))
   ss:mixKeyAndHash(psk)
   ss:encryptAndHash(msg.payload, msg.payload, sizeof(msg.payload))
   ss:split(cs1, cs2)
end

function HandshakeState:readMessageC (msg, cs1, cs2)
   local ss, e, rs, psk = self.ss, self.e, self.rs, self.psk
   if not ss:decryptAndHash(msg.ns, msg.ns, sizeof(msg.ns)) then
      return false
   end
   copy(rs, msg.ns, sizeof(rs))
   ss:mixKey(self:dh(e.sk, rs))
   ss:mixKeyAndHash(psk)
   if not ss:decryptAndHash(msg.payload, msg.payload, sizeof(msg.payload)) then
      return false
   end
   ss:split(cs1, cs2)
   return true
end

function HandshakeState:writeMessageD (msg)
   local ss = self.ss
   fill(msg.ne, sizeof(msg.ne))
   fill(msg.ns, sizeof(msg.ns))
   fill(msg.nstag, sizeof(msg.nstag))
   ss.cs:encryptWithAd(
      msg.payload, msg.payload, sizeof(msg.payload), nil, msg.tag
   )
end

function HandshakeState:readMessageD (msg)
   local ss = self.ss
   return ss.cs:decryptWithAd(
      msg.payload, msg.payload, sizeof(msg.payload), nil, msg.tag
   )
end

Session = {
   message_t = HandshakeState.message_t
}

function Session:new (initiator, prologue, psk)
   local s = new("struct { uint8_t pk[32], sk[32]; }")
   crypto.random_bytes(s.sk, sizeof(s.sk))
   crypto.curve25519_scalarmult_base(s.pk, s.sk)
   local o = {
      hs = HandshakeState:new(prologue, s, psk, initiator),
      mc = 0,
      cs1 = CipherState:new(),
      cs2 = CipherState:new()
   }
   return setmetatable(o, {__index=Session})
end

function Session:reset ()
   self.hs:clear()
   self.mc = 0
   self.cs1:clear()
   self.cs2:clear()
end

function Session:SendMessage (msg)
   assert(typeof(msg) == HandshakeState.message_t)
   if self.mc == 0 then
      self.hs:writeMessageA(msg)
   end
   if self.mc == 1 then
      self.hs:writeMessageB(msg)
   end
   if self.mc == 2 then
      self.hs:writeMessageC(msg, self.cs1, self.cs2)
   end
   if self.mc > 2 then
      if self.hs.initiator then
         self.hs.ss.cs = self.cs1
      else
         self.hs.ss.cs = self.cs2
      end
      self.hs:writeMessageD(msg)
   end
   self.mc = self.mc + 1
   return self.mc > 3
end

function Session:RecvMessage (msg)
   assert(typeof(msg) == HandshakeState.message_t)
   local complete, valid = false, false
   if self.mc == 0 then
      valid = self.hs:readMessageA(msg)
   end
   if self.mc == 1 then
      valid = self.hs:readMessageB(msg)
   end
   if self.mc == 2 then
      valid = self.hs:readMessageC(msg, self.cs1, self.cs2)
   end
   if self.mc > 2 then
      if self.hs.initiator then
         self.hs.ss.cs = self.cs2
      else
         self.hs.ss.cs = self.cs1
      end
      valid = self.hs:readMessageD(msg)
      complete = valid and true
   end
   self.mc = self.mc + 1
   return complete, valid
end

function Session:extractKeys ()
   assert(self.mc > 3)
   local inbound, outbound
   if self.hs.initiator then
      inbound, outbound = self.cs1, self.cs2
   else
      inbound, outbound = self.cs2, self.cs1
   end
   inbound:reKey()
   outbound:reKey()
   return inbound.k, outbound.k
end

function selftest ()
   local msg = new(Session.message_t)
   local prologue = new("uint8_t[32]"); copy(prologue, "vita-noise-1")
   local psk = new("uint8_t[32]"); copy(psk, "test1234")
   local i = Session:new(true, prologue, psk)
   local r = Session:new(false, prologue, psk)
   -- A
   copy(msg.payload, "aes-gcm-16-icv")
   i:SendMessage(msg)
   local complete, valid = r:RecvMessage(msg)
   assert(not complete and valid and
             ffi.string(msg.payload, 14) == "aes-gcm-16-icv")
   -- B
   fill(msg.payload, sizeof(msg.payload))
   r:SendMessage(msg)
   local complete, valid = i:RecvMessage(msg)
   assert(not complete and valid)
   -- C
   cast("uint32_t*", msg.payload)[0] = 1234
   i:SendMessage(msg)
   local complete, valid = r:RecvMessage(msg)
   local initiator_spi = cast("uint32_t*", msg.payload)[0]
   assert(not complete and valid and initiator_spi == 1234)
   -- D
   cast("uint32_t*", msg.payload)[0] = 5678
   assert(r:SendMessage(msg))
   local complete, valid = i:RecvMessage(msg)
   local responder_spi = cast("uint32_t*", msg.payload)[0]
   assert(complete and valid and responder_spi == 5678)
   -- Complete
   local i_inbound, i_outbound = i:extractKeys()
   local r_inbound, r_outbound = r:extractKeys()
   print("initiator")
   print(" inbound", lib.hexdump(ffi.string(i_inbound, sizeof(i_inbound)), sizeof(i_inbound)))
   print("outbound", lib.hexdump(ffi.string(i_outbound, sizeof(i_outbound)), sizeof(i_outbound)))
   print("responder")
   print(" inbound", lib.hexdump(ffi.string(r_inbound, sizeof(r_inbound)), sizeof(r_inbound)))
   print("outbound", lib.hexdump(ffi.string(r_outbound, sizeof(r_outbound)), sizeof(r_outbound)))
   i:reset()
   r:reset()
end
