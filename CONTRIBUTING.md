# Contributing to TinyCA2 — GTK3 port

This branch (`gtk3-port`) carries the staged conversion of the GTK2 codebase to
GTK3 plus a test suite. Read `README.md` first for what TinyCA2 is and what this
fork adds on top of upstream.

## Target platform

- Debian / Ubuntu (anything with Perl 5.14+ and `libgtk3-perl` available).
- The port deliberately does not target Windows or macOS. Run on Linux or WSL.

## Required system packages

On a Debian/Ubuntu host (or WSL2):

```
sudo apt-get install \
    perl \
    libgtk3-perl libglib-perl libpango-perl libcairo-perl \
    libtest-deep-perl libtest-exception-perl libfile-temp-perl \
    libmime-base64-perl liblocale-gettext-perl \
    openssl zip tar
```

During the staged port (Stages 0–4) the test suite does **not** load any GTK
binding — business-logic tests run via a minimal in-tree stub
(`t/lib/MockGtk.pm` + `t/lib/MockGUIHelpers.pm`). You can therefore exercise the
non-GUI test suite without GTK installed.

From Stage 5 onwards (`use Gtk3` lands in the source tree) you will need
`libgtk3-perl` for module-load smoke tests and GTK3 itself for any manual
smoke testing of the application.

## Running the tests

```
perl Makefile.PL
make
make test
# or, more concisely:
prove -lr t/
```

The `prove -lr t/` form picks up `t/lib/` automatically.

### What each test directory contains

- `t/` — unit and integration tests that must pass on every commit.
- `xt/` — author-only tests (perltidy, POD coverage, etc.) — not run by
  `make test` by default.
- `t/lib/` — shared test helpers (`TestCA.pm`, `MockGtk.pm`,
  `MockGUIHelpers.pm`). These are **not** part of the installed distribution.

### Test design

- Business-logic modules (`CA`, `CERT`, `REQ`, `KEY`, `OpenSSL`, `HELPERS`,
  `TCONFIG`) are exercised against a real `openssl` binary in a per-test
  temporary directory built by `TestCA.pm`.
- GUI modules (`GUI.pm`, `GUI/HELPERS.pm`, `GUI/TCONFIG.pm`,
  `GUI/X509_browser.pm`, `GUI/X509_infobox.pm`, `GUI/CALLBACK.pm`,
  `GUI/WORDS.pm`) get module-load smoke tests once Stage 5 has been merged.

## Branching / staging

The port is broken into the stages tracked in `STAGES.md` (at the root of this
branch). Each stage must:

1. Leave the test suite green.
2. Be a single atomic commit (or a short series of related commits) with a
   `[stage-N]` prefix in the commit subject.
3. Touch only the files documented in that stage.

Do not skip stages. The order is load-bearing.

## Style

- Two-space indentation in existing files, three-space in new files
  (matches the upstream codebase). `perltidy --profile=.perltidyrc` settles
  disputes.
- `use strict; use warnings;` is mandatory in every new `.pm` and `.t`.
- New code should avoid introducing further coupling between business and
  GUI modules. The `GUI::UI` seam introduced in Stage 4 is the only sanctioned
  bridge.

## Reporting issues

Please flag any regression in fork-specific behaviour separately:

- Long random hex serials on signed certs.
- SHA-256 / 4096-bit defaults.
- `ENV::SUBJECTALTNAME*` substitution in `subjectAltName`.
- 15-digit `index.txt` dates (years > 2050).
- `crl_serial` / `crlnumber` support in `openssl.cnf`.

Those features must survive every stage.
