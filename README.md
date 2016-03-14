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
- No support for tail recursion (which gets compiled to a loop).
- Limited ability to display useful patterns in `case` expressions. As a replacement for proper names, patterns
  of the form `<tag n>` are shown.
- No support for FFI.
- Limited to x86 and x86-64.
- Limited to ELF files.

## How It Works

The decompiler is composed of several distinct stages:

- *Metadata Parsing*. In this stage, we read basic metadata from the file, including the names of all symbols in
  the program, the version of GHC the program was compiled with, and whether the binary is 32 bit or 64 bit. Code
  for this process can be found in `hsdecomp/metadata.py`.
- *Code Parsing*. In this stage, we recursively locate and parse every relevant section of code into an internal
  interpretation representation. This is the meat of the work done by the decompiler, and can be found primarily
  in `hsdecomp/parse/__init__.py`. Note that much of the analysis is done by means of simulation, for which
  the code can be found at `hsdecomp/machine.py`.
- *Type Inference*. Although much of the interpretation of the binary can be found directly, the patterns which
  case expressions are branching on are initially opaque to the decompiler. Type inference allows displaying more
  precise patterns. Note that this stage is currently extremely primitive.
- *Optimization*. At this stage in the pipeline, the decompiler has a fairly clear understanding of what is going
  on. However, the information is laid out as it is in the binary, with many small, uninlined expressions. To increase
  readability, the decompiler will perform various passes over the interpretations to clean them up and make them
  easier for a human to understand. The code for this is at `hsdecomp/optimize.py`.
- *Display*. Finally, the decompiled code must be displayed to the user. This currently uses a fairly hacky pretty
  printer implemented at `hsdecomp/show.py`.

Unfortunately, I haven't written a full description of any of these stages or even adequately commented my code.
However, I wrote a [description](http://sctf.ehsandev.com/reversing/lambda1.html) of manually decompiling
[a file](http://compete.sctf.io/2015q2/problemfiles/42/%CE%BB1) for the [sCTF security competition](http://sctf.io/).
The output of this decompiler on that file can be found at `test/lambda1/output` in this repository.
