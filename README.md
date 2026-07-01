# fusil-h5py-plugin

An h5py-specific fuzzing plugin for [fusil](https://github.com/devdanzin/fusil)'s
Python fuzzer.

It teaches fusil's generator how to build and stress h5py objects — `File`, `Dataset`,
`Group`, `AttributeManager` — with type-aware operations (slicing, chunking, dtypes,
links, attributes, direct I/O) and a large library of pre-built "tricky" h5py objects
injected as hostile arguments into fuzzed calls.

This machinery used to live in-tree under `fusil/python/h5py/`. It was extracted into a
plugin so the core generator no longer carries ~4.6k LOC of optional, heavyweight h5py
code. The plugin registers through fusil's `fusil.plugins` entry-point group.

## Install

```bash
pip install -e .          # from a checkout, into the same venv as fusil
```

Requires `fusil`, `h5py`, and `numpy`.

## Use

The plugin activates automatically when h5py is the fuzz target:

```bash
PYTHONPATH=$PWD python fuzzers/fusil-python-threaded --force-unsafe --modules h5py
```

Or force it on for any target module with `--fuzz-h5py`. When neither applies, the plugin
is inert and fusil behaves exactly as if it were not installed.

## What it registers

| Hook | Provided by |
| --- | --- |
| `add_argument_generator` (`simple`, weight 50) | `H5PyArgumentGenerator.genH5PyObject` — references pre-built tricky objects |
| `add_definitions_provider` | tricky-object setup (`tricky_h5py_code`) + runtime slice/link helpers |
| `add_instance_dispatcher` | `WriteH5PyCode._dispatch_fuzz_on_h5py_instance` — per-type instance fuzzing |
| `add_class_handler` | `WriteH5PyCode.fuzz_one_h5py_class` — correct File/Dataset/Group instantiation |
| `--fuzz-h5py` CLI option | forces activation for non-h5py targets |

## Layout

- `fusil_h5py_plugin/__init__.py` — `register()` and the thin adapters that bind the
  writer/argument-generator into fusil's plugin hooks.
- `fusil_h5py_plugin/h5py_argument_generator.py` — `H5PyArgumentGenerator`: h5py value/expression generators.
- `fusil_h5py_plugin/h5py_tricky_weird.py` — `tricky_h5py_code`: the embedded setup that builds the tricky-object catalog at runtime.
- `fusil_h5py_plugin/write_h5py_code.py` — `WriteH5PyCode`: the h5py-aware code generator.
