import os, ed2k


proc printHelp() =
  echo "usage: ned2k PATH"
  echo "PATH must be a valid file or directory."
  quit()

proc ed2kLink (filename: string): string =
  "ed2k://|file|" & filename.extractFilename & '|' & $filename.getFileSize & '|' & $filename.getEd2k() & '|'


if paramCount() < 1:
  printHelp()

let
  path = paramStr (1)

if fileExists (path):
  echo ed2kLink (path)
elif dirExists (path):
  for p in path.walkDir:
    if p.kind == pcFile or p.kind == pcLinkToFile:
      echo ed2kLink (p.path)
else:
  printHelp()