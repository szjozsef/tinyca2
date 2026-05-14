# GTK3 port — staged plan

| #  | Stage                                                              | State    |
| -- | ------------------------------------------------------------------ | -------- |
|  0 | Branch + test infrastructure                                       | done     |
|  1 | Integration tests for `HELPERS.pm` (baseline)                      | done     |
|  2 | Integration tests for `OpenSSL.pm` against real `openssl`          | done     |
|  3 | Integration tests for `CA` / `CERT` / `REQ` / `KEY` lifecycle      | done     |
|  4 | Introduce `UI` seam to decouple business modules from GTK          | done     |
|  5 | Mechanical `Gtk2 → Gtk3` package rename + `Pango` decoupling       | done     |
|  6 | Replace stock items with labels + themed icons                     | done     |
|  7 | Replace deprecated containers (HBox/VBox/Separator/ButtonBox/Table)| done     |
|  8 | Replace `Gtk2::Combo` with `Gtk3::ComboBoxText`                    | done     |
|  9 | Rewrite `SimpleMenu` and `ImageMenuItem` popups                    | done     |
| 10 | Polish: `set_alignment`, `Dialog->vbox`, `modify_font`, XLFD fonts | done     |
| 11 | Async refactor of `OpenSSL::newkey` progress bar                   | done     |
| 12 | Perl modernisation (use warnings, I18N, CI, 3 bug fixes)           | done     |
| 13 | Manual end-to-end smoke test on Debian/Ubuntu                      | active   |

## Test suite

After stage 12: 96 tests across 4 files, all green.

```
t/00-infra.t       — test-harness sanity (MockGtk, MockGUIHelpers, TestCA)
t/10-helpers.t     — HELPERS pure-function coverage (gen_name, parse_dn,
                     parse_extensions, gen_subjectaltname_contents,
                     enc_base64/dec_base64, mktmp, get/write_export_dir)
t/20-openssl.t     — OpenSSL.pm against real /usr/bin/openssl
                     (newkey, newcert, signreq, revoke, newcrl, parsecert,
                     parsereq, parsecrl, convdata, convkey, genp12,
                     read_index, _get_index_date)
t/30-lifecycle.t   — CA / CERT / REQ / KEY higher-level workflows
                     (create_ca_env, export_ca_cert, export_crl, parse_req,
                     parse_cert, export_cert, _check_key, key_change_passwd,
                     TCONFIG init_config)
```

## Real bugs fixed in Stage 12

These were locked down as "known bug, Stage 12 fix" by the Stage 2/3 tests, then fixed in Stage 12 A:

1. `OpenSSL::new` version regex now matches modern OpenSSL `X.Y.Z[letter]` (was: only 0.9.x / 1.0–1.2.x).
2. `OpenSSL::parsecert` SUBJECT regex now matches both legacy `subject= /C=US/…` and modern `subject=C = US, …`.
3. `KEY::key_change_passwd` DSA-detection arm now reads `/BEGIN DSA PRIVATE KEY/` (was: duplicated `/BEGIN RSA/`).

Plus a latent bug surfaced by Stage 12 B's `use warnings` rollout:

4. `HELPERS::parse_extensions` inner while-loop now bounds-checks `$i` before the regex matches, eliminating `Use of uninitialized value` warnings.

## Fork-specific behaviours preserved across every stage

These are the user-added features documented in `README.md`. The test suite locks each one down so the port (and Stage 12 fixes) couldn't accidentally regress them.

1. Long random hex serials on signed certs (`OpenSSL::newcert`, `REQ::sign_req`)
2. SHA-256 and 4096-bit RSA defaults
3. `subjectAltName = ${ENV::SUBJECTALTNAMEDNS}` plus the IP/DNS/email/raw dispatcher
4. `index.txt` 15-digit dates for cert validity > year 2050
5. Multi-line hex serial parsing in `OpenSSL::parsecert`
6. SHA-256 / SHA-384 / SHA-512 fingerprints in `parsecert`
7. `crl_serial` file + `crlnumber` recognised by `TCONFIG`
8. Modified `template/openssl.cnf` with `ocsp_url` / `aia_url` / `crl_url` placeholders, no `nsCertType` legacy junk
9. OpenSSL 1.x+ compatibility (`Public-Key:` line, `_run_with_fixed_input` helper, multi-line serial)

## Shim layers introduced

The port avoids touching ~400+ Gtk widget call sites in the GUI files by installing back-compat shims:

- `tinyca/UI.pm` — single seam business modules call instead of `GUI::HELPERS::*` and `Gtk2->*`. Owns `Glib::IO->add_watch` async pump for the openssl-newkey progress bar.
- `tinyca/UI/Stock.pm` — `Gtk3::Button->new_from_stock('gtk-X')` now returns a mnemonic-labelled button with a Freedesktop themed icon (same for `ToolButton` and `Image`).
- `tinyca/UI/Compat.pm` — covers `HBox`/`VBox`/`HSeparator`/`HButtonBox`/`Table` constructors, `Gtk2::Table`'s legacy `attach_defaults` / `set_col_spacing` API on top of `Gtk3::Grid`, the `Gtk2::Combo` → `ComboBoxText` translation, `ImageMenuItem`→`MenuItem`, the `Gtk3::SimpleMenu` reconstruction, and `TextView::modify_font` via a per-widget CSS provider.
- `tinyca/I18N.pm` — formalised `_()` gettext wrapper. Exported into every module via `use I18N qw(_);`. Replaces the legacy `sub _ { … }` in `bin/tinyca2::main` that relied on Perl bareword-fallback.

## Stage 13 — manual smoke-test plan

The automated suite covers the business / file-output surface but cannot construct GTK widgets. Manual smoke is required on a real Debian/Ubuntu system with libgtk-3-perl installed. Walk through each of the following on the `gtk3-port` branch:

### Pre-flight

- [ ] Install dependencies on Ubuntu 22.04 (or your distro equivalent):
  ```
  sudo apt-get install -y \
      libgtk-3-perl libglib-perl libpango-perl libcairo-perl \
      libmime-base64-perl liblocale-gettext-perl \
      libtest-deep-perl libtest-exception-perl \
      openssl zip tar
  ```
- [ ] `prove -lr t/` is green (96/96).
- [ ] Launch the app from the source tree:
  ```
  BEGIN_INC=$(pwd)/tinyca perl -Itinyca bin/tinyca2
  ```
  or set `$ENV{PATH_TO_TINYCA}` if the launcher hard-codes `/usr/share/tinyca`.
- [ ] App opens without compile-time errors. Menus, toolbar, statusbar, and the CA-selector window appear.

### CA creation + signing pipeline

- [ ] Create a new CA with default values (4096 RSA, sha256). Verify the CA appears in the listing.
- [ ] Confirm the directory layout matches `<basedir>/<caname>/{req,keys,certs,crl,newcerts}/` + `openssl.cnf`, `cacert.{pem,key}`, `index.txt`, `serial`, `crl_serial` (the last is the fork feature).
- [ ] Create a server CSR; confirm it appears under Requests.
- [ ] Sign the CSR with default values. Check that the resulting cert has a long random hex serial number (36-char `[1-9A-F][0-9A-F]{35}`) — fork feature 1.
- [ ] Set a DNS SAN during signing (e.g. `host1.example.com, host2.example.com`). Open the resulting cert's details and confirm both SANs are present — fork feature 7.
- [ ] Revoke the cert. Confirm STATUS changes to REVOKED in the certs list.
- [ ] Export the CRL in each of PEM / DER / TXT.
- [ ] Re-open the app: the revoked cert is still flagged.

### Cert export

- [ ] Export a cert in each format: PEM, DER, TXT, PKCS#12, ZIP, TAR.
- [ ] Open the PKCS#12 with `openssl pkcs12 -in ... -info` and verify it round-trips.

### Sub-CA

- [ ] Create a sub-CA. Verify the chain file `cachain.pem` exists in the sub-CA's directory.

### History view

- [ ] Open the history view; verify VALID rows render in green and EXPIRED/REVOKED in red.

### TCONFIG / openssl.cnf editor

- [ ] Open *Preferences → OpenSSL Configuration*. Tab through every page. The ~20 ComboBoxText dropdowns (subjAltNameType, keyUsage, extendedKeyUsage, etc.) should be populated, editable, and have working radio-coupling: selecting "Not set" should grey-out the related radios; selecting a value should ungrey them.
- [ ] Edit some field, click Apply, click OK. Re-open the dialog. The new value persists.

### Keys

- [ ] Export a key in PEM, DER, PKCS#12.
- [ ] Change a key's passphrase. Verify the on-disk file can be decrypted with the new passphrase via `openssl rsa -in key.pem`.

### Menu + popups

- [ ] File menu, Preferences menu, Help menu all open. Items have working accelerators (Alt+F, etc.). Click each to verify the action.
- [ ] Right-click on a certificate row → context menu opens with Details / View / Export / Revoke / Renew / Delete. Each works.
- [ ] Right-click on a request row → menu with Details / View / New / Import / Sign / Delete.
- [ ] Right-click on a key row → menu with Export / Delete.

### About + Help

- [ ] Help → About: dialog opens with version, copyright, license link.

### Regression flagging

If anything fails, capture:
- The exact step
- A screenshot if visual
- The console output (especially deprecation warnings)

Report each as a `[stage-13]` issue against the branch.
