##[

  Based on source code provided in https://tools.ietf.org/html/rfc1320 by RSA Data Security, Inc.

]##
type
  MD4State = array[4, uint32]
  MD4Block = array[64, uint8] 

  MD4Digest* = array[16, uint8]
  MD4Context* = object
    state: MD4State
    count: array[2, uint32]
    buffer: MD4Block


const
  S11 = 3
  S12 = 7
  S13 = 11
  S14 = 19
  S21 = 3
  S22 = 5
  S23 = 9
  S24 = 13
  S31 = 3
  S32 = 9
  S33 = 11
  S34 = 15
  Padding = "\x80\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" &
            "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"



# F, G and H are basic MD4 functions.
proc F(x, y, z: uint32): uint32 {.inline.} = (x and y) or ((not x) and z)
proc G(x, y, z: uint32): uint32 {.inline.} = (x and y) or (x and z) or (y and z)
proc H(x, y, z: uint32): uint32 {.inline.} = x xor y xor z

# ROTATE_LEFT rotates x left n bits.
proc ROTATE_LEFT(x: uint32, n: uint8): uint32 {.inline.} = (x shl n) or (x shr (32'u32 - n))


# FF, GG and HH are transformations for rounds 1, 2 and 3
# Rotation is separate from addition to prevent recomputation 
proc FF(a: var uint32, b, c, d, x: uint32, s: uint8) =
  a += F(b, c, d) + x
  a = ROTATE_LEFT(a, s)

proc GG(a: var uint32, b, c, d, x: uint32, s: uint8) =
  a += G(b, c, d) + x + 0x5a827999'u32
  a = ROTATE_LEFT(a, s)

proc HH(a: var uint32, b, c, d, x: uint32, s: uint8) =
  a += H(b, c, d) + x + 0x6ed9eba1'u32
  a = ROTATE_LEFT(a, s)



# Encodes input (UINT4) into output (unsigned char). Assumes len is
# a multiple of 4.
proc encode(output: var openarray[uint8], input: openarray[uint32], length: int) =
  var
    i = 0
    j = 0
  while j < length:
    output[j]   = (input[i] and 0xff).uint8
    output[j+1] = ((input[i] shr 8) and 0xff).uint8
    output[j+2] = ((input[i] shr 16) and 0xff).uint8
    output[j+3] = ((input[i] shr 24) and 0xff).uint8
    i += 1
    j += 4

# Decodes input (unsigned char) into output (UINT4). Assumes len is
# a multiple of 4.
proc decode(output: var openarray[uint32], input: MD4Block | string, length: int) =
  var
    i = 0
    j = 0
  while j < length:
    output[i] = input[j].uint32 or (input[j+1].uint32 shl 8) or
      (input[j+2].uint32 shl 16) or (input[j+3].uint32 shl 24)
    i += 1
    j += 4

# MD4 basic transformation. Transforms state based on block.
proc transform(state: var MD4State, bblock: MD4Block | string) =
  var
    a = state[0]
    b = state[1]
    c = state[2]
    d = state[3]
    x: array[16, uint32]

  decode(x, bblock, 64)

  # Round 1
  FF(a, b, c, d, x[ 0], S11) # 1
  FF(d, a, b, c, x[ 1], S12) # 2
  FF(c, d, a, b, x[ 2], S13) # 3
  FF(b, c, d, a, x[ 3], S14) # 4
  FF(a, b, c, d, x[ 4], S11) # 5
  FF(d, a, b, c, x[ 5], S12) # 6
  FF(c, d, a, b, x[ 6], S13) # 7
  FF(b, c, d, a, x[ 7], S14) # 8
  FF(a, b, c, d, x[ 8], S11) # 9
  FF(d, a, b, c, x[ 9], S12) # 10
  FF(c, d, a, b, x[10], S13) # 11
  FF(b, c, d, a, x[11], S14) # 12
  FF(a, b, c, d, x[12], S11) # 13
  FF(d, a, b, c, x[13], S12) # 14
  FF(c, d, a, b, x[14], S13) # 15
  FF(b, c, d, a, x[15], S14) # 16

  # Round 2
  GG(a, b, c, d, x[ 0], S21) # 17
  GG(d, a, b, c, x[ 4], S22) # 18
  GG(c, d, a, b, x[ 8], S23) # 19
  GG(b, c, d, a, x[12], S24) # 20
  GG(a, b, c, d, x[ 1], S21) # 21
  GG(d, a, b, c, x[ 5], S22) # 22
  GG(c, d, a, b, x[ 9], S23) # 23
  GG(b, c, d, a, x[13], S24) # 24
  GG(a, b, c, d, x[ 2], S21) # 25
  GG(d, a, b, c, x[ 6], S22) # 26
  GG(c, d, a, b, x[10], S23) # 27
  GG(b, c, d, a, x[14], S24) # 28
  GG(a, b, c, d, x[ 3], S21) # 29
  GG(d, a, b, c, x[ 7], S22) # 30
  GG(c, d, a, b, x[11], S23) # 31
  GG(b, c, d, a, x[15], S24) # 32

  # Round 3
  HH(a, b, c, d, x[ 0], S31) # 33
  HH(d, a, b, c, x[ 8], S32) # 34
  HH(c, d, a, b, x[ 4], S33) # 35
  HH(b, c, d, a, x[12], S34) # 36
  HH(a, b, c, d, x[ 2], S31) # 37
  HH(d, a, b, c, x[10], S32) # 38
  HH(c, d, a, b, x[ 6], S33) # 39
  HH(b, c, d, a, x[14], S34) # 40
  HH(a, b, c, d, x[ 1], S31) # 41
  HH(d, a, b, c, x[ 9], S32) # 42
  HH(c, d, a, b, x[ 5], S33) # 43
  HH(b, c, d, a, x[13], S34) # 44
  HH(a, b, c, d, x[ 3], S31) # 45
  HH(d, a, b, c, x[11], S32) # 46
  HH(c, d, a, b, x[ 7], S33) # 47
  HH(b, c, d, a, x[15], S34) # 48

  state[0] += a
  state[1] += b
  state[2] += c
  state[3] += d

  # Zeroize sensitive information.
  zeroMem(addr x, x.sizeof)



proc initMD4*(): MD4Context =
  # MD4 initialization. Begins an MD4 operation, writing a new context.
  result.count[0] = 0
  result.count[1] = 0

  # Load magic initialization constants.
  result.state[0] = 0x67452301'u32
  result.state[1] = 0xefcdab89'u32
  result.state[2] = 0x98badcfe'u32
  result.state[3] = 0x10325476'u32

  zeroMem(addr result.buffer[0], result.buffer.sizeof)


# MD4 block update operation. Continues an MD4 message-digest
# operation, processing another message block, and updating the
# context.
proc update*(c: var MD4Context, input: string, length: int) =
  var input = input

  # Compute number of bytes mod 64
  let
    index = ((c.count[0] shr 3) and 0x3f).int
  # Update number of bits
  c.count[0] += length.uint32 shl 3
  if c.count[0] < length.uint32 shl 3:
    c.count[1] += 1
  c.count[1] += length.uint32 shr 29

  let
    partLen = 64 - index

  # Transform as many times as possible.
  if length >= partLen:
    copyMem(addr c.buffer[index], addr input[0], partLen)
    transform(c.state, c.buffer)

    var i = partLen
    while i + 63 < length:
      transform(c.state, input[i..<i+64])
      i += 64
    if length-i != 0:
      copyMem(addr c.buffer[0], addr input[i], length-i)
  else:
    if length != 0:
      copyMem(addr c.buffer[index], addr input[0], length)

proc update*(c: var MD4Context, input: string) =
  c.update(input, input.len)


# MD4 finalization. Ends an MD4 message-digest operation, writing the
# the message digest and zeroizing the context.
proc finalize*(c: var MD4Context, digest: var MD4Digest) =
  var
    bits: array[8, uint8]

  # Save number of bits
  encode(bits, c.count, 8)

  # Pad out to 56 mod 64.
  let
    index = (c.count[0] shr 3) and 0x3f
    padLen = if index < 56: 56 - index.int else: 120 - index.int
  c.update(Padding, padLen)

  # Append length (before padding)
  c.update(cast[string](@bits), 8)
  # Store state in digest
  encode(digest, c.state, 16)

  # Zeroize sensitive information.
  zeroMem(addr c, MD4Context.sizeof)

proc finalize*(c: var MD4Context): MD4Digest =
  c.finalize(result)



proc `$`*(d: MD4Digest): string =
  ## converts a MD5Digest value into its string representation
  const digits = "0123456789abcdef"
  result = ""
  for i in 0..15:
    add(result, digits[((d[i] shr 4) and 0xF).int])
    add(result, digits[(d[i] and 0xF).int])


proc toMD4* (s: string): MD4Digest =
  ## computes the MD5Digest value for a string `s`
  var
    c = initMD4()
  c.update(s)
  c.finalize()

proc getMD4* (s: string): string =
  ## computes an MD5 value of `s` and returns its string representation
  $s.toMD4()