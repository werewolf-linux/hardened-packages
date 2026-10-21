# php

Werewolf's PHP: Wolfi's newest stable `php-8.5` recipe, captured unchanged, plus
policy patches
([design](https://github.com/werewolf-linux/werewolf/blob/main/docs/design/hardened-interpreters.md)).
Packages keep Wolfi's names, so forms that install `php-8.5` or its extensions get it.

## Differences from Wolfi's build

Module startup refuses effective UID 0 for CLI, FPM and embedded PHP. PHP-FPM must
start as its service user; a root master that drops privileges later is refused.
The repository README describes the build-only marker; the APKs cannot contain it
or grant their own allowances.

Same as Wolfi: source commit, Wolfi's two patches, toolchain, and the retained CLI,
FPM and extension build options and tests.

- **Patches** (`patches/series`), applied after Wolfi's:
  1. `PHPRC` and `PHP_INI_SCAN_DIR` are ignored; configuration comes from the root.
  2. Allowances: `/etc/runtime-hardening/allow/<ns>/php/GROUP` or
     `.../all/php/GROUP`, a regular file, never a link.
  3. `exec`, `system`, `passthru`, `shell_exec`, `proc_open`, `popen`, `pcntl_exec` and
     `dl` stay disabled, whatever `php.ini` or `-d` says, unless their capability
     group is allowed.
  4. `unserialize` makes objects only of classes `allowed_classes` names, unless
     `deserialize` is allowed.
  5. `allow_url_include` is always off.
  6. OPcache never loads compiled scripts from a file cache.
  7. A `phar://` wrapper guard remains in the source; this build disables Phar
     entirely, so an allowance cannot enable it.
  8. `inline` gates argv, stdin, `eval` and generated stream code. Suppressing an
     error with `@` does not permit execution. A writable-source grant alone does
     not permit stdin, filters or user-defined stream wrappers.
  9. Every compiled file, including includes and automatic prepends, needs a regular
     file descriptor on a read-only mount, unless `writable-source` is allowed.
     Failed provenance checks refuse execution. Symlinks are judged by the opened
     target. The compiler guard installs after OPcache startup, outside cache hits;
     the stream opener also guards preload compilation during startup.
  10. `upload` gates multipart parsing before boundaries, temporary files and progress
      callbacks, for automatic POST handling and `request_parse_body()`. It also gates
      `move_uploaded_file()`, rechecking the allowance when a file is moved.
      Session progress processing separately needs `upload-progress`, checked before
      progress state is allocated for each multipart body, even if its INI setting is on.
- **Packages**: keep CLI, FPM, their configuration, development headers and the
  extensions current Werewolf forms use. Headers support building native extensions
  such as APCu and Redis for this PHP. Omit Apache's `mod_php`, CGI, phpdbg, PEAR/PECL
  and documentation. CGI is explicitly disabled, the Apache install steps are removed,
  and manpages are discarded before splitting packages.
- **Extensions**: retain `bcmath`, `calendar`, `ctype`, `curl`, `dom`, `exif`,
  `fileinfo`, `gd`, `gmp`, `iconv`, `intl`, `ldap`, `mbstring`, `mysqli`, `mysqlnd`,
  `openssl`, `pcntl`, `pdo`, `pdo_mysql`, `pdo_pgsql`, `pdo_sqlite`, `pgsql`, `posix`,
  `simplexml`, `soap`, `sodium`, `sysvsem`, `xml`, `xmlreader`, `xmlwriter` and `zip`,
  with their configuration packages. These serve the WordPress, MediaWiki,
  Nextcloud, Moodle and LimeSurvey forms. Omit `bz2`, `ftp`, `gettext`, `odbc`,
  `pdo_dblib`, `pdo_odbc`, `phar`, `sockets`, `sysvshm`, `tidy` and `xsl`; no current
  form requires them. Phar is explicitly disabled because it defaults to enabled;
  removing only its shared-extension flag would compile it into the main executable.
- **Tests**: Wolfi's retained tests, then `tests/probe.sh`, which checks each protection with
  `php.ini-production` in place and that each allowance, and only a regular file, takes
  its function back. The omitted Tidy extension's test and test dependency are
  removed. The probe verifies that Phar's extension, class and wrapper remain absent,
  even with a Phar allowance. Probes exercise includes, source symlinks, stream
  wrappers, suppressed eval, stdin, a warm OPcache and multipart POST/PUT uploads,
  including symlink grants, explicit parsing and allowance revocation before moves.
- **Packaging**: epoch `1000 × policy.json revision + Wolfi epoch` sorts above every
  Wolfi rebuild; each package provides `wolfi-origin:php-8.5:VERSION-rEPOCH` for CVE
  matching. Derivation stops for review when the checkout, Wolfi's patches, a removed
  flag, the extension or subpackage names, or the package identity changes. A new
  extension needs an existing or almost-certain Werewolf consumer before inclusion.

## Behavior changes for applications

- Composer, WordPress plugins and the like that shell out fail with "Call to undefined
  function"; a form that needs one declares `allow: [php:exec]` in `form.yaml`.
- `unserialize($data)` without `allowed_classes` yields `__PHP_Incomplete_Class` for
  objects; name the classes, or declare `allow: [php:deserialize]`.
- File uploads and text-only multipart forms need `allow: [php:upload]`; `php.ini`
  cannot grant it. URL-encoded forms still work. This grants no code execution and
  does not restrict applications that read and save raw request bodies themselves.
- Phar is unavailable, including `phar://` and tools such as `composer.phar`.
  Our current app recipes use releases with dependencies already included.
- `PHPRC` and `PHP_INI_SCAN_DIR` do nothing; put settings in the image's `php.ini`.
- Generated templates and writable PHP configuration need conversion to data or
  precompilation into the image. `php:writable-source` permits writable files;
  `php:inline` separately permits evaluated and generated code. Neither grants the
  other. These grants apply image-wide in current Werewolf forms.
- Older PHP streams and runtimes bundled in OCI images do not acquire these guards
  by adding the feed. Migrate them separately before claiming runtime protection.
- No `phpdbg` and no `pear`/`pecl`; build extensions into the image instead.
- No `mod_php` or `php-cgi`; serve PHP with FPM, and use CLI for background jobs.

## Building

`make PACKAGE=php refresh check derive prepare build` captures Wolfi's recipe, verifies
it, applies every patch and builds with Melange ([README](../../README.md)). Unit tests,
from the repository root:

    python3 -m unittest discover -s packages/php/tests -p 'test_*.py'

Patches are PHP-3.01, as PHP (`LICENSES/PHP-3.01.txt`); Wolfi inputs keep their license.
