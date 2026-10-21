# python

Werewolf's CPython: Wolfi's newest stable `python-3.15` recipe, captured unchanged,
plus policy patches
([design](https://github.com/werewolf-linux/werewolf/blob/main/docs/design/hardened-interpreters.md)).
Packages keep Wolfi's names, so forms that install `python-3.15` or `python3` get it.

## Differences from Wolfi's build

Interpreter preinitialization refuses effective UID 0, including embedded Python.
Start it after dropping root. The repository README describes the build-only marker;
the APKs cannot contain it or grant their own allowances.

Same as Wolfi: source commit, Wolfi's patches, toolchain, configure options but one,
the ordinary interpreter's PGO run, and the retained packages' tests.

- **Patches** (`patches/series`), applied after Wolfi's and before configuring Python:
  1. `-E -s` by default: `PYTHON*` variables are ignored unless the image allows the
     environment; the user site always is.
  2. No working directory on `sys.path` for `-m`, `-c` or stdin; a script keeps its own
     directory.
  3. `native`: `_ctypes` loads only when allowed, since native code removes any check.
  4. `deserialize`: `pickle` reconstructs an object only when allowed; plain data still
     unpickles. The pure-Python unpickler is gated too.
  5. `inline` and `writable-source` (in `main.c`): refuse `-c` and piped stdin, and a
     main script whose file is on a writable mount (so `/data` and `/tmp` are refused).
- **Configure**: no `--enable-loadable-sqlite-extensions`; `sqlite3` loads no native
  code.
- **Packages**: ship `python-3.15`, `python-3.15-base`, `python-3.15-dev` and
  `python-3.15-base-dev`. The development packages remain available for application
  builds: Open WebUI and Paperless already build with Python development headers.
  Runtime images need only the interpreter. Omit the free-threaded
  (`python-3.15t`, `python-3.15t-dev`) and experimental JIT packages, their
  source-tree copies, Tkinter (`-tk`) and manpages (`-doc`). GUI and manpage files
  are removed before packaging so they cannot fall back into the main or base package.
  Also omit `-privileged-netbindservice`, which puts `CAP_NET_BIND_SERVICE` on
  the interpreter file. Werewolf's service launcher grants that capability when
  a service declares a port below 1024; Python needs no special binary.
- **Allowances**: a capability group is an empty file, never a symlink, at
  `/etc/runtime-hardening/allow/<ns>/python/GROUP` or `.../all/python/GROUP`, read with
  `lstat`. `<ns>` is the service from `/proc/self/cgroup`. The build guest grants every
  group so CPython builds and its suite passes; packages ship nothing there.
- **Tests**: Wolfi's tests, then `tests/probe.sh`, which holds each protection and sees
  each group, and only a regular file, take its own back.
- **Packaging**: epoch `1000 × policy.json revision + Wolfi epoch` sorts above every
  Wolfi rebuild; each package provides `wolfi-origin:python-3.15:VERSION-rEPOCH` for CVE
  matching. Derivation stops for review when the checkout, the patch or clone order,
  the subpackage names, the removed option or the package identity changes.

## Behavior changes for applications

- `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, `PYTHONUNBUFFERED` and the rest have no
  effect. Use the matching option (`-u`, `-B`, `-X utf8`) or put code where `sys.path`
  looks.
- `pip install --user` and `~/.local` site-packages are not used; use a virtual
  environment, whose `pyvenv.cfg` still works.
- `python -c`, a piped-in script, and a script under `/data` or `/tmp` are refused; a
  form grants `python:inline` or `python:writable-source` to permit one.
- `import ctypes` raises `ImportError` unless `allow: [python:native]`.
- `pickle.load` of an object raises `UnpicklingError` unless `python:deserialize`.
  This does not reach third-party loaders such as PyYAML's `UnsafeLoader`.
- `sqlite3.Connection` has no `enable_load_extension`.
- Programs that embed CPython through the legacy `Py_Initialize` keep CPython's defaults
  for the environment and the user site; the other patches still apply.

## Building

`make PACKAGE=python refresh check derive prepare build` captures Wolfi's recipe,
verifies it, applies every patch and builds with Melange ([README](../../README.md)).
Unit tests, from the repository root:

    python3 -m unittest discover -s packages/python/tests -p 'test_*.py'

Patches are PSF-2.0, as CPython; Wolfi inputs keep their license.
