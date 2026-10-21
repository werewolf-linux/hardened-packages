# libffi static trampolines

`libffi-static-tramp` supplies the `libffi.so.8` ABI with read-only callback trampolines.

## Use

Werewolf: include `with: [libffi]` in the application form. Its recipe builds a
local overlay; the port is not in the automatic hardened feed. From the sibling
Werewolf checkout, build it directly with:

```sh
howl build-apk ../hardened-packages/ports/libffi/libffi.yaml
```

On Wolfi, build [libffi.yaml](libffi.yaml) with Melange, sign the APK and install
it into the application image using the corresponding trusted build key:

```sh
apk add /path/to/libffi-static-tramp-3.8.0-r0.apk
```

The library occupies Wolfi libffi's paths. Use the Werewolf overlay or resolve
package ownership while composing a Wolfi image; do not install two competing
owners of `libffi.so.8`. Rebuild the port to receive library updates.

## Patches and build controls

There are no source patches or libffi allowance files. The pinned 3.8.0 recipe
changes the build and packages only shared libraries and their license:

| Build control | One-line change | Allowance / policy |
|---|---|---|
| `--enable-exec-static-tramp` | Execute callbacks from read-only library code while keeping callback parameters writable. | Always on; build verifies `FFI_EXEC_STATIC_TRAMP=1` |
| `--disable-pax-emutramp` | Disable PaX emulated trampolines. | Build-time only |
| `--enable-portable-binary` | Enable libffi's portable binary configuration. | Build-time only |
| `--disable-builddir` | Build in the source directory for the shared-library packaging step. | Build-time only |

## Debug and allowances

| Symptom | Check / fix |
|---|---|
| Hardened Python refuses `import ctypes` | Grant `python:native` to the service; libffi cannot grant the interpreter's permission. |
| Callback allocation/execution fails under MDWE | Inspect `/proc/PID/maps` for the loaded `libffi.so.8`; confirm it is this build and exercise a real callback. |
| Writable/executable mapping refused | Keep MDWE (Memory-Deny-Write-Execute) enabled; remove the dynamic-code requirement or use static callbacks. |
| Loader reports missing `libffi.so.8` | Include the library in the service's actual root/OCI image and verify loader paths. |

Werewolf: add `allow: [python:native]` to the existing Python service. Wolfi:
create `/etc/runtime-hardening/allow/SERVICE/python/native` before startup; see
[allowance instructions](../../docs/usage.md#grant-an-allowance). This permits ctypes
but does not relax MDWE. There is no `libffi:*` grant or libffi runtime-denial logger.

Werewolf's Langflow native suites exercise callbacks, verify MDWE is enabled and
reject writable executable mappings. Recipe/license: MIT.
