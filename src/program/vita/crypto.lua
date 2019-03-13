-- Use of this source code is governed by the GNU AGPL license; see COPYING.

module(...,package.seeall)

local ffi = require("ffi")
local C = ffi.C
local S = require("syscall")

function random_bytes (out, n)
   S.getrandom(out, n)
end

function bytes_equal (x, y, n) -- Constant time memcmp
   x, y = ffi.cast("uint8_t*", x), ffi.cast("uint8_t*", y); assert(n > 0)
   local dif = 0
   for i = 0, n - 1 do
      dif = bit.bor(dif, bit.bxor(x[i], y[i]))
   end
   return dif == 0
end

-- blake2s FFI
ffi.cdef[[
  enum
  {
    BLAKE2S_BLOCKBYTES = 64U,
    BLAKE2S_OUTBYTES   = 32U
  };

  struct blake2s_state
  {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[BLAKE2S_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
  };

  int blake2s_init( struct blake2s_state *S, size_t outlen );
  int blake2s_update( struct blake2s_state *S, const void *in, size_t inlen );
  int blake2s_final( struct blake2s_state *S, void *out, size_t outlen );  
]]

blake2s_OUTBYTES = C.BLAKE2S_OUTBYTES
blake2s_BLOCKBYTES = C.BLAKE2S_BLOCKBYTES
blake2s_state_t = ffi.typeof("struct blake2s_state")
function blake2s_init (...) assert(C.blake2s_init(...) == 0) end
function blake2s_update (...) assert(C.blake2s_update(...) == 0) end
function blake2s_final (...) assert(C.blake2s_final(...) == 0) end

ffi.cdef[[
  struct hmac_blake2s_state {
    uint8_t i[BLAKE2S_BLOCKBYTES], o[BLAKE2S_BLOCKBYTES];
    uint8_t h[BLAKE2S_OUTBYTES];
    struct blake2s_state s;
  };
]]

hmac_blake2s_state_t = ffi.typeof("struct hmac_blake2s_state")

function hmac_blake2s_init (s, k, klen)
   assert(klen <= blake2s_BLOCKBYTES,
          "key length exceeds block size")
   ffi.fill(ffi.cast("uint8_t*", s), ffi.sizeof(s))
   blake2s_init(s.s, blake2s_OUTBYTES)
   ffi.copy(s.i, k, klen)
   for i = 0, blake2s_BLOCKBYTES - 1 do
      s.i[i] = bit.bxor(0x36, s.i[i])
   end
   ffi.copy(s.o, k, klen)
   for i = 0, blake2s_BLOCKBYTES - 1 do
      s.o[i] = bit.bxor(0x5C, s.o[i])
   end
   blake2s_update(s.s, s.i, blake2s_BLOCKBYTES)
end

function hmac_blake2s_update (s, inbytes, inlen)
   assert(inlen > 0, "input length must be positive")
   blake2s_update(s.s, inbytes, inlen)
end

function hmac_blake2s_final (s, out)
   blake2s_final(s.s, s.h, blake2s_OUTBYTES)
   blake2s_init(s.s, blake2s_OUTBYTES)
   blake2s_update(s.s, s.o, blake2s_BLOCKBYTES)
   blake2s_update(s.s, s.h, blake2s_OUTBYTES)
   blake2s_final(s.s, out, blake2s_OUTBYTES)
end

-- curve25519 FFI
ffi.cdef[[
  enum {
    CURVE25519_BYTES = 32U,
    CURVE25519_SCALARBYTES = 32U
  };

  int crypto_scalarmult_base_curve25519
  (unsigned char *q, const unsigned char *n);

  int crypto_scalarmult_curve25519
  (unsigned char *q,const unsigned char *n, const unsigned char *p);
]]

curve25519_BYTES = C.CURVE25519_BYTES
curve25519_SCALARBYTES = C.CURVE25519_SCALARBYTES

function curve25519_scalarmult_base (...)
   C.crypto_scalarmult_base_curve25519(...)
end

function curve25519_scalarmult (q, ...)
   C.crypto_scalarmult_curve25519(q, ...)
   -- Return false if q is the all-zero value
   local d = 0
   for i = 0, C.CURVE25519_BYTES-1 do
      d = bit.bor(d, q[i])
   end
   return d > 0
end

function selftest ()
   local lib = require("core.lib")
   -- test hmac_blake2s against test vector
   local s = ffi.new(hmac_blake2s_state_t)
   local h = ffi.new("uint8_t[?]", blake2s_OUTBYTES)
   hmac_blake2s_init(s, ("0"):rep(32), 32)
   hmac_blake2s_update(s, "test", 4)
   hmac_blake2s_final(s, h)
   assert(ffi.string(h, blake2s_OUTBYTES) == lib.hexundump(
             "51477cc5bdf1faf952cf97bb934ee936de1f4d5d7448a84eeb6f98d23b392166",
             blake2s_OUTBYTES), "wrong hmac_blake2s result")
   -- try a DH
   local s1 = ffi.new("uint8_t[?]", curve25519_SCALARBYTES)
   random_bytes(s1, curve25519_SCALARBYTES)
   local p1 = ffi.new("uint8_t[?]", curve25519_BYTES)
   curve25519_scalarmult_base(p1, s1)
   local s2 = ffi.new("uint8_t[?]", curve25519_SCALARBYTES)
   random_bytes(s2, curve25519_SCALARBYTES)
   local p2 = ffi.new("uint8_t[?]", curve25519_BYTES)
   curve25519_scalarmult_base(p2, s2)
   assert(not bytes_equal(p1, p2, curve25519_BYTES), "Broken bytes_equal?")
   local q1 = ffi.new("uint8_t[?]", curve25519_BYTES)
   assert(curve25519_scalarmult(q1, s1, p2))
   local q2 = ffi.new("uint8_t[?]", curve25519_BYTES)
   assert(curve25519_scalarmult(q2, s2, p1))
   assert(bytes_equal(q1, q2, curve25519_BYTES), "DH failed")
   local pzero = ffi.new("uint8_t[?]", curve25519_BYTES)
   local qzero = ffi.new("uint8_t[?]", curve25519_BYTES)
   assert(not curve25519_scalarmult(qzero, s1, pzero), "DH zero not signaled")
end
