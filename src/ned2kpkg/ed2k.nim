##[
    eDonkey2000 hash: http://mldonkey.sourceforge.net/Ed2k-hash
]##
from math import ceil
import md4

export md4.`$`


const
  ChunkSize = 9728000


proc readString(f: File, buffer: var string) =
  let
    length = f.readBuffer(addr buffer[0], buffer.len)
  # should only happen at the end of files
  buffer.setLen(length)


proc getEd2k*(filename: string): MD4Digest =
  let
    file = open(filename)
  #  size = file.getFileSize()
  #  chunks = (size.int / ChunkSize).ceil.int

  var
    hashes = newSeq[uint8]()
    buffer = newString(ChunkSize)
  while not file.endOfFile():
    file.readString(buffer)
    hashes.add  buffer.toMd4()
  file.close()

  cast[string](hashes).toMd4()