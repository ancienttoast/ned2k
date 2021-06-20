# ned2k

Small utility and library to compute MD4 and ED2K checksums.

## Ned2k utility

### Building

```bash
nimble -d:release build
```

### Usage

Calculate the ED2K link for a single file.

```bash
$ ./ned2k LICENSE
ed2k://|file|LICENSE|1073|fd2b745e779c68b485e83acbedc9fe85|
```

Calculate the ED2K link for every file in a given directory.

```bash
$ ./ned2k src
ed2k://|file|ned2k.nim|1303|13dc137c5dca4e943ff392b4f5316b65|
```

Calculate the ED2K link for every file in a given directory and all of it's subdirectories.

```bash
$ ./ned2k --recursive src
ed2k://|file|ned2k.nim|1303|13dc137c5dca4e943ff392b4f5316b65|
ed2k://|file|ed2k.nim|1545|9846a73e7fd4ab2937b20ea5b655d7e3| 
ed2k://|file|md4.nim|7946|5aa7355a24ba83b23043a561b9e4f662|
```

## Library

### MD4

The MD4 module provides an API identical to the Nim stdlib [MD5](https://nim-lang.org/docs/md5.html) module.

Calculate the MD4 checksum in a single proc call.

```nim
import ned2k/md4

assert getMD4("abc") == "a448017aaf21d8525fc10ae87aa6729d"
```

Calculate the MD4 checksum in multiple steps.

```nim
import ned2k/md4

var
  c = md4Init()
c.md4Update("a")
c.md4Update("b")
c.md4Update("c")
assert $c.md4Finalize() == "a448017aaf21d8525fc10ae87aa6729d"
```

### ED2K

Generate the ED2K link for the _LICENSE_ file.

```nim
import ned2k/ed2k

assert ed2kLink("LICENSE") == "ed2k://|file|LICENSE|1073|fd2b745e779c68b485e83acbedc9fe85|"
```

## License

Licensed and distributed under the [MIT license](https://opensource.org/licenses/MIT)
