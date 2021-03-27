import
  std/[os, parseopt],
  ned2kpkg/ed2k



proc printHelp() =
  echo "usage: ned2k [OPTION]... [PATH]..."
  echo "PATH must be a valid file or directory."
  echo ""
  echo "Options"
  echo "  -r, --recursive       compute the ed2k links for files in the given directory recursively"
  echo "  -h, --help            display this help screen"

proc handleFile(path: string) =
  echo ed2kLink(path)

proc handleDir(path: string, isRecursive: bool) =
  let
    followFilter =
      if isRecursive:
        {pcDir, pcLinkToDir}
      else:
        {}
  for p in path.walkDirRec({pcFile, pcLinkToFile}, followFilter):
    echo ed2kLink(p)



var
  isRecursive = false
  paths = newSeq[string]()
  displayHelp = false


var
  opts = initOptParser()
while true:
  opts.next()
  case opts.kind
  of cmdEnd:
    break
  of cmdShortOption, cmdLongOption:
    case opts.key
    of "r", "recursive":
      isRecursive = true
    of "h", "help":
      displayHelp = true
    else:
      echo "Unknown option: " & opts.key
      quit()
  of cmdArgument:
    paths &= opts.key


if displayHelp or paths.len == 0:
  printHelp()
else:
  for path in paths:
    if fileExists(path):
      handleFile(path)
    elif dirExists(path):
      handleDir(path, isRecursive)
    else:
      echo "Invalid path '" & path & "'"
