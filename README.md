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
