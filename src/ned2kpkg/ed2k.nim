## Module for computing `eDonkey2000 checksums <http://mldonkey.sourceforge.net/Ed2k-hash>`_.
##
## **See also:**
## * `ED2K <http://mldonkey.sourceforge.net/Ed2k-hash>`_
from math import ceil
from os import extractFilename
import md4

export md4.`$`


const
  CHUNK_SIZE = 9728000

proc getEd2k*(file: File): MD4Digest =
  ## Computes the `ED2K checksum` for the given `file`.
  let
    size = file.getFileSize()
    chunks = (size.int / ChunkSize).ceil.int
  var
    hashes = newSeqOfCap[uint8](chunks*MD4Digest.len)
    buffer = newString(CHUNK_SIZE)
  while not file.endOfFile():
    let
      length = file.readBuffer(addr buffer[0], buffer.len)
    # should only happen at the end of files
    buffer.setLen(length)
    hashes &= buffer.toMd4()
  file.close()

  cast[string](hashes).toMd4()

proc ed2kLink*(file: File, filename: string): string =
  ## Computes the `ED2K Link` for `file`. `filename` is only used as a part of the returned link.
  "ed2k://|file|" & filename.extractFilename & '|' & $file.getFileSize & '|' & $file.getEd2k() & '|'

proc ed2kLink*(filename: string): string =
  ## Computes the `ED2K Link` for `filename`.
  ed2kLink(open(filename), filename)
