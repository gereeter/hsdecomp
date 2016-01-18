# hsdecomp
A decompiler for GHC-compiled Haskell

## Dependencies

- [pyelftools](https://github.com/eliben/pyelftools)
- The python bindings to the [Capstone Engine](http://www.capstone-engine.org)

## Trying it out

To decompile a file without any installation steps, simply run the `runner.py` script on the file you want to decompile:

```
python runner.py path/to/binary
```

## Installation

`hsdecomp` utilizes `setuptools` for packaging and installation. To install:

```
python setup.py install
```

## Known Limitations

Note that testing has been slim, so there probably are many other limitations not mentioned here.

- No support for stripped binaries.
- No support for direct manipulation of unboxed types. This generally shouldn't be a problem for unopimized
  binaries, as all that manipulation should be hidden behind library calls.
- Limited ability to display useful patterns in `case` expressions. As a replacement for proper names, patterns
  of the form `<tag n>` are shown.
- No support for FFI.
- Limited to x86 and x86-64.
- Limited to ELF files.
