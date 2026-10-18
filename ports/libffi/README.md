# libffi static trampolines

Standalone Melange port of libffi with read-only static callback trampolines,
for MDWE-compatible Python callbacks. The `libffi-static-tramp` APK supplies the
normal `libffi.so.8` ABI.

The Werewolf form in `../../../werewolf/forms/libffi` builds this context through
its declared recipe. Its Langflow native tests exercise callbacks, verify MDWE
and reject writable executable mappings.

From `../../../werewolf`:

```sh
howl build-apk ../hardened-packages/ports/libffi/libffi.yaml
```

This standalone port is not yet part of the automatic Wolfi capture and feed
publication workflow under `packages/`. Its package still travels as a locally
built form overlay.
