-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

-- Noise instance NNpsk0 based on noise_NNpsk0.go, see
-- https://noiseexplorer.com/patterns/NNpsk0/

local crypto = require("program.vita.crypto")
local aes_gcm = require("lib.ipsec.aes_gcm_avx")
local lib = require("core.lib")
local ffi = require("ffi")

local new, sizeof, copy, fill, typeof, cast =
   ffi.new, ffi.sizeof, ffi.copy, ffi.fill, ffi.typeof, ffi.cast
local band, rshift = bit.band, bit.rshift
local htonl = lib.htonl

-- NNpsk0:
--    -> e
--    <- e, ee

-- Kludge: our AES-GCM implementation only supports AAD between four and
-- sixteen bytes (multiples of four.) Hence, we include 16 zero bytes of AAD
-- when none is needed, and hash supplied AAD exceeding 16 bytes to 16 bytes
-- using blake2s.

local name = "Noise_NNpsk0_25519_AESGCM_BLAKE2s"
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

function CipherState:copy (cs)
   copy(cs.k, self.k, sizeof(cs.k))
   cs.n = self.n
   copy(cs.aes_gcm_state, self.aes_gcm_state, sizeof(cs.aes_gcm_state))
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

function SymmetricState:copy (ss)
   copy(ss.h, self.h, sizeof(ss.h))
   copy(ss.ck, self.ck, sizeof(ss.ck))
   self.cs:copy(ss.cs)
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

function SymmetricState:split (initiator, cs1, cs2)
   local hkdf_s, tmp, ck = self.hkdf_state, self.tmp, self.ck
   crypto.hkdf_blake2s(hkdf_s, cast("uint8_t*", tmp), sizeof(tmp), ck, empty_key)
   assert(sizeof(cs1) + sizeof(cs2) <= sizeof(tmp), "split underflow")
   if initiator then
      copy(cs1, tmp, sizeof(cs1))
      copy(cs2, cast("uint8_t*", tmp) + sizeof(cs1), sizeof(cs2))
   else
      copy(cs2, tmp, sizeof(cs2))
      copy(cs1, cast("uint8_t*", tmp) + sizeof(cs2), sizeof(cs1))
   end
   return true
end

HandshakeState = {
   message_t = ffi.typeof[[struct {
      uint8_t ne[32], payload[32], tag[16];
   } __attribute__((packed))]]
}

function HandshakeState:new (psk, initiator)
   local o = {
      ss = SymmetricState:new(),
      e = new("struct { uint8_t pk[32], sk[32]; }"),
      re = new("uint8_t[32]"),
      q = new("uint8_t[32]"),
      psk = psk,
      initiator = initiator,
      rollback_ss = SymmetricState:new()
   }
   return setmetatable(o, {__index=HandshakeState})
end

function HandshakeState:commit ()
   self.ss:copy(self.rollback_ss)
   return true
end

function HandshakeState:revert ()
   self.rollback_ss:copy(self.ss)
   return false
end

function HandshakeState:init (prologue, len)
   local ss = self.ss
   ss:mixHash(prologue, len)
   self:commit()
end

function HandshakeState:clear ()
   self.ss:clear()
   fill(self.e, sizeof(self.e))
   fill(self.re, sizeof(self.re))
   fill(self.q, sizeof(self.q))
end

function HandshakeState:generateKeypair ()
   local e = self.e
   crypto.random_bytes(e.sk, sizeof(e.sk))
   crypto.curve25519_scalarmult_base(e.pk, e.sk)
   return e
end

function HandshakeState:dh (s, p)
   crypto.curve25519_scalarmult(self.q, s, p)
   return self.q
end

function HandshakeState:writeMessageA (msg)
   local ss, e, psk = self.ss, self:generateKeypair(), self.psk
   ss:mixKeyAndHash(psk)
   ss:mixHash(e.pk)
   ss:mixKey(e.pk)
   copy(msg.ne, e.pk, sizeof(msg.ne))
   ss:encryptAndHash(msg.payload, msg.payload, sizeof(msg.payload))
   self:commit()
end

function HandshakeState:readMessageA (msg)
   local ss, re, psk = self.ss, self.re, self.psk
   ss:mixKeyAndHash(psk)
   copy(re, msg.ne, sizeof(re))
   ss:mixHash(re)
   ss:mixKey(re)
   return ss:decryptAndHash(msg.payload, msg.payload, sizeof(msg.payload))
       or self:revert()
end

function HandshakeState:writeMessageB (msg, cs1, cs2)
   local ss, e, re, psk = self.ss, self:generateKeypair(), self.re
   ss:mixHash(e.pk)
   ss:mixKey(e.pk)
   ss:mixKey(self:dh(e.sk, re))
   copy(msg.ne, e.pk, sizeof(msg.ne))
   ss:encryptAndHash(msg.payload, msg.payload, sizeof(msg.payload))
   self.ss:split(self.initiator, cs1, cs2)
end

function HandshakeState:readMessageB (msg, cs1, cs2)
   local ss, e, re = self.ss, self.e, self.re
   copy(re, msg.ne, sizeof(re))
   ss:mixHash(re)
   ss:mixKey(re)
   ss:mixKey(self:dh(e.sk, re))
   return ss:decryptAndHash(msg.payload, msg.payload, sizeof(msg.payload))
      and ss:split(self.initiator, cs1, cs2)
       or self:revert()
end

function selftest ()
   local msg = new(HandshakeState.message_t)
   local msg2 = new(HandshakeState.message_t)
   local msg_copy = new(HandshakeState.message_t)
   local psk = new("uint8_t[32]"); copy(psk, "test1234")
   local i = HandshakeState:new(psk, true)
   local r = HandshakeState:new(psk, false)
   local i2 = HandshakeState:new(psk, true)
   local r2 = HandshakeState:new(psk, false)

   local prologue = new([[struct {
      uint32_t version, r;
      uint8_t n[32], aead[32];
   } __attribute__((packed))]])
   prologue.version, prologue.r = 1, 42
   crypto.random_bytes(prologue.n, sizeof(prologue.n))
   copy(prologue.aead, "aes-gcm-16-icv")

   i:init(prologue)
   r:init(prologue)

   crypto.random_bytes(prologue.n, sizeof(prologue.n))

   i2:init(prologue)
   r2:init(prologue)

   local spi = ffi.cast("uint32_t *", msg.payload)

   -- A
   i2:writeMessageA(msg2)

   copy(msg_copy, msg2, sizeof(msg_copy))
   assert(not r:readMessageA(msg_copy))

   assert(r2:readMessageA(msg2))

   spi[0] = 1234
   i:writeMessageA(msg)

   assert(r:readMessageA(msg) and spi[0] == 1234)

   -- B
   local isa = { rx = ffi.new("uint8_t[20]"), tx = ffi.new("uint8_t[20]") }
   local rsa = { rx = ffi.new("uint8_t[20]"), tx = ffi.new("uint8_t[20]") }

   r2:writeMessageB(msg2, rsa.rx, rsa.tx)

   copy(msg_copy, msg2, sizeof(msg_copy))
   assert(not i:readMessageB(msg_copy, isa.rx, isa.tx))

   spi[0] = 5678
   r:writeMessageB(msg, rsa.rx, rsa.tx)

   copy(msg_copy, msg, sizeof(msg_copy))
   assert(not i2:readMessageB(msg_copy, isa.rx, isa.tx))

   assert(i:readMessageB(msg, isa.rx, isa.tx) and spi[0] == 5678)

   -- Complete
   assert(ffi.string(isa.rx, sizeof(isa.rx)) ==
             ffi.string(rsa.tx, sizeof(rsa.tx)))
   assert(ffi.string(isa.tx, sizeof(isa.tx)) ==
             ffi.string(rsa.rx, sizeof(rsa.rx)))

   i:clear()
   r:clear()
end
