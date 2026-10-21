# glibc

Werewolf's glibc: Wolfi's recipe, captured unchanged, plus five policy patches
([design](https://github.com/werewolf-linux/werewolf/blob/main/docs/design/glibc-neutered.md),
[audit](docs/glibc-vuln-audit.md)). Every Werewolf image installs the resulting
`glibc-neutered` packages from `https://dist.werewolf-linux.org/apk/glibc`.

## Differences from Wolfi's build

Same as Wolfi: source commit, Wolfi's patches, toolchain, `openssf-compiler-options` and
configure hardening (bind-now, CET, fortify, strong stack protector, stack-guard randomization).

- **Patches** (`patches/series`): deny libc's internal environment reads, disable loader
  injection and audit dispatch, built-in NSS only, built-in converters only.
- **Configure**: `--disable-build-nscd --disable-nscd`, `--enable-kernel=6.18` (Wolfi: 4.9),
  `-fstrict-flex-arrays=3`, `-z separate-code`; tests need no `--library-path` exception.
- **Removed**: nscd, nss-db, nss-hesiod, sotruss, pcprofiledump, mtrace/xtrace/sprof,
  external gconv modules and `iconvconfig`; a fixed `/etc/nsswitch.conf` (files; hosts files dns).
- **Tests**: Wolfi's full suite, 5.5% raw failure ceiling (Wolfi: 2%), injection probes, ABI check.
- **Packaging**: provides Wolfi's names at priority 10244; epoch adds `policy.json`'s revision.

## Behavior changes for applications

- `getenv`, `setenv` and `secure_getenv` still work, but libc ignores its own variables:
  `GLIBC_TUNABLES`, every `LD_*`, `LANG`/`LC_*`, `LOCPATH`, `TZ`, resolver, `TMPDIR`, profiling.
- `setlocale(…, "")` gives `C`, not `C.UTF-8`; locales named explicitly still load.
- Bare-name `execvp`/`posix_spawnp` fail (ENOENT); `getopt` never reorders; `fnmatch` is POSIX;
  temporary names need an explicit directory; `~` expands from the account database.
- No preload or audit libraries from the environment, `/etc/ld.so.preload`, `ld.so` options
  or `DT_AUDIT`; binding is eager. Normal dependencies and `dlopen` remain.
- Audit dispatch is inert even with forged registration state. IFUNC CPU dispatch
  remains enabled. This removes the xz audit-hook mechanism; native libraries still
  share their process's authority ([design][xz-design]).
- NSS: files and DNS only. iconv: UTF-8, ASCII and UCS only (no UTF-16 or legacy charsets).
- Needs Linux 6.18 or later.

## Building and publishing

`make PACKAGE=glibc refresh check derive prepare build` captures Wolfi's latest stable
recipe, verifies it, applies every patch and builds with Melange ([README](../../README.md)).
CI checks Wolfi every ten minutes and publishes both architectures, signed, to the stable
repository ([publishing](../../docs/design/publishing.md)).
Revision 16's native validation is recorded in the [audit report](docs/audit/native-r16.md).
Patches are LGPL-2.1-or-later and Wolfi inputs keep their license (`LICENSES/`); tooling: `LICENSE`.

[xz-design]: https://github.com/werewolf-linux/werewolf/blob/main/docs/design/xzutils.md
