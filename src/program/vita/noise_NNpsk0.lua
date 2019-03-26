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
-- sixteen bytes (multiples of four.) Hence, we use a 16 byte blake2s hash of
-- the AAD.

local name = "Noise_NNpsk0_25519_AESGCM_BLAKE2s"
local empty_key = ffi.new("uint8_t[32]")

local CipherState = {
   aes_gcm_nonce_t = ffi.typeof[[union {
      uint8_t bytes[16];
      struct { uint32_t pad, benh, benl; } slot;
   } __attribute__((packed, aligned(16)))]]
}

function CipherState:new ()
   local o = {
      k = new("uint8_t[32]"),
      n = 0ULL,
      aes_gcm_state = ffi.new("gcm_data __attribute__((aligned(16)))"),
      aes_gcm_block = ffi.new("uint8_t[16]"),
      aes_gcm_nonce = ffi.new(self.aes_gcm_nonce_t),
      aes_gcm_aad = ffi.new("uint8_t[16]"),
      mac_size = 16
   }
   return setmetatable(o, {__index=CipherState})
end

function CipherState:clear ()
   fill(self.k, sizeof(self.k))
   self.n = 0ULL
   fill(self.aes_gcm_state, sizeof(self.aes_gcm_state))
   fill(self.aes_gcm_block, sizeof(self.aes_gcm_block))
   fill(self.aes_gcm_nonce, sizeof(self.aes_gcm_nonce))
   fill(self.aes_gcm_aad, sizeof(self.aes_gcm_aad))
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

function CipherState:nonce ()
   local nonce = self.aes_gcm_nonce
   nonce.slot.benl = htonl(band(self.n, 0x00000000ffffffff))
   nonce.slot.benh = htonl(rshift(self.n, 32))
   self.n = self.n + 1
   return nonce.bytes
end

function CipherState:encryptWithAd (out, plaintext, len, ad)
   local aes_gcm_s, h = self.aes_gcm_state, self.aes_gcm_aad
   aes_gcm.aad_prehash(aes_gcm_s, h, ad, sizeof(ad))
   aes_gcm.aesni_gcm_enc_256_avx_gen4(aes_gcm_s,
                                      out, plaintext, len,
                                      self:nonce(),
                                      h, sizeof(ad),
                                      out+len, self.mac_size)
end

function CipherState:decryptWithAd (out, ciphertext, len, ad)
   local aes_gcm_s, h = self.aes_gcm_state, self.aes_gcm_aad
   aes_gcm.aad_prehash(aes_gcm_s, h, ad, sizeof(ad))
   local auth = self.aes_gcm_block
   aes_gcm.aesni_gcm_dec_256_avx_gen4(aes_gcm_s,
                                      out, ciphertext, len,
                                      self:nonce(),
                                      h, sizeof(ad),
                                      auth, sizeof(auth))
   return aes_gcm.auth16_equal(ciphertext+len, auth) == 0
end

local SymmetricState = {
   tmp_t = ffi.typeof[[union {
      uint8_t bytes[128];
      struct { uint8_t a[32], b[32], c[32]; } slot;
   } __attribute__((packed))]]
}

function SymmetricState:new ()
   local o = {
      h = new("uint8_t[32]"),
      ck = new("uint8_t[32]"),
      cs = CipherState:new(),
      ad = new("uint8_t[32]"),
      hkdf_state = new(crypto.hkdf_blake2s_state_t),
      hash_state = new(crypto.blake2s_state_t),
      tmp = new(self.tmp_t)
   }
   SymmetricState.init(o)
   return setmetatable(o, {__index=SymmetricState})
end

function SymmetricState:init ()
   local hash_s, h, ck = self.hash_state, self.h, self.ck
   if #name <= sizeof(h) then
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
   fill(self.ad, sizeof(self.ad))
   fill(self.hkdf_state, sizeof(self.hkdf_state))
   fill(self.hash_state, sizeof(self.hash_state))
   fill(self.tmp, sizeof(self.tmp))
   self:init()
end

function SymmetricState:mixKey (ikm)
   local hkdf_s, tmp, ck, cs = self.hkdf_state, self.tmp, self.ck, self.cs
   local a, b = tmp.slot.a, tmp.slot.b
   crypto.hkdf_blake2s(hkdf_s, tmp.bytes, sizeof(a)+sizeof(b), ikm, ck)
   copy(ck, a, sizeof(ck))
   cs:initializeKey(b)
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
   local a, b, c = tmp.slot.a, tmp.slot.b, tmp.slot.c
   crypto.hkdf_blake2s(hkdf_s, tmp.bytes, sizeof(a)+sizeof(b)+sizeof(c), ikm, ck)
   copy(ck, a, sizeof(ck))
   self:mixHash(b)
   cs:initializeKey(c)
end

function SymmetricState:encryptAndHash (out, plaintext, len)
   local cs, h = self.cs, self.h
   assert(cs:hasKey())
   cs:encryptWithAd(out, plaintext, len, h)
   self:mixHash(out, len + cs.mac_size)
end

function SymmetricState:decryptAndHash (out, ciphertext, len)
   local cs, h, ad = self.cs, self.h, self.ad
   assert(sizeof(ad) == sizeof(h))
   copy(ad, h, sizeof(ad))
   self:mixHash(ciphertext, len + cs.mac_size)
   assert(cs:hasKey())
   return cs:decryptWithAd(out, ciphertext, len, ad)
end

function SymmetricState:split (initiator, cs1, cs2)
   local hkdf_s, tmp, ck = self.hkdf_state, self.tmp, self.ck
   local len = sizeof(cs1) + sizeof(cs2)
   assert(len <= sizeof(tmp), "split underflow")
   crypto.hkdf_blake2s(hkdf_s, tmp.bytes, len, ck, empty_key)
   if initiator then
      copy(cs1, tmp.bytes, sizeof(cs1))
      copy(cs2, tmp.bytes + sizeof(cs1), sizeof(cs2))
   else
      copy(cs2, tmp.bytes, sizeof(cs2))
      copy(cs1, tmp.bytes + sizeof(cs2), sizeof(cs1))
   end
   fill(tmp, sizeof(tmp))
end

HandshakeState = {
   message_t = ffi.typeof[[struct {
      uint8_t ne[32], payload[32], tag[16];
   } __attribute__((packed))]]
}

function HandshakeState:new (psk, initiator)
   local o = {
      ss = SymmetricState:new(),
      e = { pk = new("uint8_t[32]"), sk = new("uint8_t[32]") },
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
end

function HandshakeState:revert ()
   self.rollback_ss:copy(self.ss)
end

function HandshakeState:init (prologue, len)
   local ss, e, psk = self.ss, self.e, self.psk
   ss:mixHash(prologue, len)
   ss:mixKeyAndHash(psk)
   self:commit()
   self:generateKeypair(e)
end

function HandshakeState:clear ()
   self.ss:clear()
   fill(self.e.sk, sizeof(self.e.sk))
   fill(self.e.pk, sizeof(self.e.pk))
   fill(self.re, sizeof(self.re))
   fill(self.q, sizeof(self.q))
end

function HandshakeState:generateKeypair (e)
   crypto.random_bytes(e.sk, sizeof(e.sk))
   crypto.curve25519_scalarmult_base(e.pk, e.sk)
end

function HandshakeState:dh (q, s, p)
   return crypto.curve25519_scalarmult(q, s, p)
end

function HandshakeState:writeMessageA (msg)
   local ss, e = self.ss, self.e
   ss:mixHash(e.pk)
   ss:mixKey(e.pk)
   copy(msg.ne, e.pk, sizeof(msg.ne))
   ss:encryptAndHash(msg.payload, msg.payload, sizeof(msg.payload))
   self:commit()
end

function HandshakeState:readMessageA (msg)
   local ss, e, re, q = self.ss, self.e, self.re, self.q
   copy(re, msg.ne, sizeof(re))
   ss:mixHash(re)
   ss:mixKey(re)
   local valid, dh_ok
   if ss:decryptAndHash(msg.payload, msg.payload, sizeof(msg.payload)) then
      valid = true
      if self:dh(q, e.sk, re) then
         dh_ok = true
         ss:mixHash(e.pk)
         ss:mixKey(e.pk)
         ss:mixKey(q)
         self:commit()
         return valid, dh_ok
      end
   end
   self:revert()
   return valid, dh_ok
end

function HandshakeState:writeMessageB (msg, cs1, cs2)
   local ss, e  = self.ss, self.e
   copy(msg.ne, e.pk, sizeof(msg.ne))
   ss:encryptAndHash(msg.payload, msg.payload, sizeof(msg.payload))
   self.ss:split(self.initiator, cs1, cs2)
end

function HandshakeState:readMessageB (msg, cs1, cs2)
   local ss, e, re, q = self.ss, self.e, self.re, self.q
   copy(re, msg.ne, sizeof(re))
   ss:mixHash(re)
   ss:mixKey(re)
   local valid, dh_ok
   if self:dh(q, e.sk, re) then
      dh_ok = true
      ss:mixKey(q)
      if ss:decryptAndHash(msg.payload, msg.payload, sizeof(msg.payload)) then
         valid = true
         ss:split(self.initiator, cs1, cs2)
         return valid, dh_ok
      end
   end
   self:revert()
   return valid, dh_ok
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

   local spi = cast("uint32_t *", msg.payload)

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
