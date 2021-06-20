## Module for computing `eDonkey2000 checksums <http://mldonkey.sourceforge.net/Ed2k-hash>`_.
##
## 1. Files are split into chunks of 9500kB. The last chunk can be smaller.
## 2. An MD4 checksum value is computed for each chunk.
## 3. The checksum are concatenated together into a (number of chunks * 16) bytes long string.
## 4. The final checksum is the MD4 checksum of this string.
##
## For files whose size is a multiple of chunk size old versions of the original *ed2k_hash*
## tool calculated hashes with an additional 0 byte chunk at the end. Since this isn't the
## case anymore this module doesn't support this behaviour.
##
## **See also:**
## * `ED2K <http://mldonkey.sourceforge.net/Ed2k-hash>`_
from os import extractFilename
import md4

export md4.`$`


const
  CHUNK_SIZE = 9728000

proc getEd2k*(file: File): MD4Digest =
  ## Computes the `ED2K checksum` for the given `file`.
  var
    hash = md4Init()
    buffer = newString(CHUNK_SIZE)
  while not file.endOfFile():
    let
      length = file.readBuffer(addr buffer[0], buffer.len)
    # should only happen at the end of files
    buffer.setLen(length)
    hash.md4Update(buffer.toMd4())
  file.close()

  hash.md4Finalize()

proc ed2kLink*(file: File, filename: string): string =
  ## Computes the `ED2K Link` for `file`. `filename` is only used as a part of the returned link.
  "ed2k://|file|" & filename.extractFilename & '|' & $file.getFileSize & '|' & $file.getEd2k() & '|'

proc ed2kLink*(filename: string): string =
  ## Computes the `ED2K Link` for `filename`.
  ed2kLink(open(filename), filename)
