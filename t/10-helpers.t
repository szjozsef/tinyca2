#!perl
# Stage 1 — baseline regression tests for tinyca/HELPERS.pm.
#
# Covers every pure function in the module:
#   gen_name, mktmp, parse_dn, parse_extensions, get_export_dir,
#   write_export_dir, gen_subjectaltname_contents, enc_base64, dec_base64.
#
# exit_clean is intentionally NOT exercised — it calls Gtk2->main_quit + exit;
# its Gtk shims are validated by t/00-infra.t.
#
# The fork-specific SAN heuristics (README bullet 7) and the URL-safe base64
# mapping are locked down with explicit fixtures; any future refactor must
# keep these green.

use strict;
use warnings;
use Test::More;
use Test::Deep;
use Test::Exception;

use FindBin ();
use lib "$FindBin::Bin/lib";

# Test helpers must come BEFORE business modules so the shims register
# their %INC entries.
use MockGtk;
use MockGUIHelpers;
MockGtk->install;
MockGUIHelpers->install;

# bin/tinyca2 defines `sub _ { ... }` in main:: that all modules call.
# Provide it for the test process so any string with `_(...)` works.
sub ::_ { return $_[0]; }

# MIME::Base64 is loaded by bin/tinyca2 in production; load it here.
use MIME::Base64 ();

use File::Temp ();

use lib "$FindBin::Bin/../tinyca";
use_ok('HELPERS') or BAIL_OUT('HELPERS.pm failed to load');

# ------------------------------------------------------------------
# gen_name
# ------------------------------------------------------------------
subtest 'gen_name: full DN' => sub {
    my $name = HELPERS::gen_name({
        CN => 'foo', EMAIL => 'foo@bar', OU => 'eng',
        O  => 'ACME', L => 'NYC', ST => 'NY', C => 'US',
    });
    is($name, 'foo:foo@bar:eng:ACME:NYC:NY:US',
       'all fields concatenated with ":"');
};

subtest 'gen_name: missing fields render as " " and no trailing colon' => sub {
    my $name = HELPERS::gen_name({ CN => 'foo', O => 'bar' });
    is($name, 'foo: : :bar: : : ',
       'missing fields become " ", no trailing colon after C');
};

subtest 'gen_name: empty strings treated as missing' => sub {
    my $name = HELPERS::gen_name({
        CN => 'foo', EMAIL => '', OU => 'eng',
        O  => '',    L => 'NYC', ST => '',   C => 'US',
    });
    is($name, 'foo: :eng: :NYC: :US', 'empty fields become " "');
};

subtest 'gen_name: OU arrayref picks first element' => sub {
    my $name = HELPERS::gen_name({
        CN => 'foo', OU => ['dept1', 'dept2'], C => 'US',
    });
    like($name, qr/^foo:.*:dept1:.*US$/,
         'first OU array element appears');
};

subtest 'gen_name: OU arrayref with undef first element -> space' => sub {
    my $name = HELPERS::gen_name({
        CN => 'foo', OU => [undef, 'dept2'], C => 'US',
    });
    like($name, qr/^foo:.*: :.*US$/,
         'undef first element of OU arrayref renders as " "');
};

# ------------------------------------------------------------------
# mktmp
# ------------------------------------------------------------------
subtest 'mktmp: returns non-existent name starting with base' => sub {
    my $tmp  = File::Temp->newdir;
    my $base = "$tmp/scratch.";
    my $name = HELPERS::mktmp($base);
    like($name, qr/^\Q$base\E[A-Z]{8}$/,
         "mktmp '$name' has base + 8 upper-case suffix");
    ok(!-e $name, 'returned filename does not yet exist');
};

subtest 'mktmp: successive calls produce different names' => sub {
    my $tmp = File::Temp->newdir;
    my $a = HELPERS::mktmp("$tmp/x.");
    my $b = HELPERS::mktmp("$tmp/x.");
    isnt($a, $b, 'two consecutive mktmp calls differ');
};

subtest 'mktmp: skips an existing file' => sub {
    my $tmp  = File::Temp->newdir;
    my $base = "$tmp/y.";

    # Use mktmp itself to discover a candidate, occupy it, then run mktmp
    # again. With 26**8 candidates the probability of an accidental
    # collision on the retry is effectively zero.
    my $first = HELPERS::mktmp($base);
    open my $fh, '>', $first or die "seed $first: $!";
    print $fh "blocking\n";
    close $fh;

    my $second = HELPERS::mktmp($base);
    isnt($second, $first, 'mktmp returns a different name when first is taken');
    ok(!-e $second, 'second returned filename does not yet exist');
};

# ------------------------------------------------------------------
# parse_dn
# ------------------------------------------------------------------
subtest 'parse_dn: slash-separated' => sub {
    my $d = HELPERS::parse_dn('/CN=foo/O=ACME/C=US');
    cmp_deeply($d, { CN => 'foo', O => 'ACME', C => 'US' }, 'slash-separated DN');
};

subtest 'parse_dn: comma-separated' => sub {
    my $d = HELPERS::parse_dn('CN=foo, O=ACME, C=US');
    cmp_deeply($d, { CN => 'foo', O => 'ACME', C => 'US' }, 'comma-separated DN');
};

subtest 'parse_dn: emailAddress normalized to EMAIL' => sub {
    my $d = HELPERS::parse_dn('/CN=foo/emailAddress=foo@bar/');
    is($d->{EMAIL}, 'foo@bar', 'emailAddress key normalized to EMAIL');
    ok(!exists $d->{EMAILADDRESS}, 'no EMAILADDRESS key');
};

subtest 'parse_dn: multiple OU stacks into arrayref' => sub {
    my $d = HELPERS::parse_dn('/CN=foo/OU=A/OU=B/OU=C');
    cmp_deeply($d->{OU}, ['A', 'B', 'C'], 'all three OUs preserved in order');
};

subtest 'parse_dn: lowercase keys uppercased' => sub {
    my $d = HELPERS::parse_dn('/cn=foo/o=bar');
    cmp_deeply($d, { CN => 'foo', O => 'bar' }, 'lowercase keys uppercased');
};

subtest 'parse_dn: whitespace around tokens stripped' => sub {
    my $d = HELPERS::parse_dn('/ CN = foo /  O  =  bar /');
    is($d->{CN}, 'foo', 'CN value trimmed');
    is($d->{O},  'bar', 'O value trimmed');
};

# ------------------------------------------------------------------
# parse_extensions
#
# Locking down the upstream's idiosyncratic key naming:
#
#   * "Key: value" lines (value on same line)  -> hash key includes ": value"
#   * "Key:" lines (value on following lines)  -> hash key is just "Key"
#
# That is genuinely the code's behaviour as of the fork; the documentation
# disagrees but the code wins. Any future cleanup must update this test.
# ------------------------------------------------------------------
subtest 'parse_extensions: cert mode' => sub {
    my @lines = split /\n/, <<'CERT';
Certificate:
    Data:
        Version: 3 (0x2)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name:
                DNS:example.com, DNS:www.example.com
    Signature Algorithm: sha256WithRSAEncryption
CERT
    my $ext = HELPERS::parse_extensions(\@lines, 'cert');
    ok(defined $ext, 'a hashref is returned');
    cmp_deeply($ext->{'X509v3 Basic Constraints: critical'},
               ['CA:FALSE'],
               'Basic Constraints captured under literal "Key: critical" form');
    cmp_deeply($ext->{'X509v3 Key Usage: critical'},
               bag('Digital Signature', 'Key Encipherment'),
               'Key Usage split on comma');
    cmp_deeply($ext->{'X509v3 Subject Alternative Name'},
               bag('DNS:example.com', 'DNS:www.example.com'),
               'subjectAltName captured (trailing colon stripped)');
};

subtest 'parse_extensions: req mode' => sub {
    my @lines = split /\n/, <<'REQ';
Certificate Request:
    Data:
        Subject: CN=server
        Requested extensions:
            X509v3 Subject Alternative Name:
                DNS:foo.example
    Signature Algorithm: sha256WithRSAEncryption
REQ
    my $ext = HELPERS::parse_extensions(\@lines, 'req');
    cmp_deeply($ext->{'X509v3 Subject Alternative Name'},
               ['DNS:foo.example'],
               'req-mode SAN captured');
};

subtest 'parse_extensions: missing header -> empty hashref' => sub {
    my @lines = ('some', 'unrelated', 'text');
    my $ext = HELPERS::parse_extensions(\@lines, 'cert');
    ok(defined $ext,           'hashref returned even on miss');
    is(ref $ext, 'HASH',       'is a hash');
    is(scalar keys %$ext, 0,   'with no entries');
};

subtest 'parse_extensions: CRL Distribution Points "Full Name" sub-section' => sub {
    my @lines = split /\n/, <<'CERT';
        X509v3 extensions:
            X509v3 CRL Distribution Points:
                Full Name:
                  URI:http://example.com/crl.pem
            X509v3 Basic Constraints:
                CA:FALSE
CERT
    my $ext = HELPERS::parse_extensions(\@lines, 'cert');
    ok((grep { /Full Name/ && /URI:http/ }
         @{$ext->{'X509v3 CRL Distribution Points'}}),
       'Full Name URI captured under CRL Distribution Points');
};

# ------------------------------------------------------------------
# get_export_dir / write_export_dir
# ------------------------------------------------------------------
subtest 'get_export_dir: undef when .exportdir missing' => sub {
    my $tmp = File::Temp->newdir;
    my $dir = HELPERS::get_export_dir({ cadir => "$tmp" });
    is($dir, undef, 'undef when .exportdir is absent');
};

subtest 'write_export_dir + get_export_dir: round-trip strips filename' => sub {
    my $tmp = File::Temp->newdir;
    HELPERS::write_export_dir({ cadir => "$tmp" }, '/some/path/cert.pem');
    my $dir = HELPERS::get_export_dir({ cadir => "$tmp" });
    is($dir, '/some/path',
       'trailing /cert.pem stripped before write; read returns directory only');
};

subtest 'write_export_dir: warns on unwritable target' => sub {
    my $tmp = File::Temp->newdir;
    my $cadir = "$tmp/missing";   # never created
    MockGUIHelpers->reset;
    my $rv = HELPERS::write_export_dir({ cadir => $cadir }, '/some/dir');
    is($rv, undef, 'returns undef on failure');
    my @w = MockGUIHelpers->calls('warning');
    ok(@w >= 1, 'GUI::HELPERS::print_warning was called');
    like($w[0]->{args}[0], qr/exportdir/i, 'warning mentions exportdir');
};

# ------------------------------------------------------------------
# gen_subjectaltname_contents (fork-specific SAN handling)
# ------------------------------------------------------------------
subtest 'gen_subjectaltname_contents: explicit type prefixes all elements' => sub {
    my @got = HELPERS::gen_subjectaltname_contents('IP:', '1.2.3.4', '5.6.7.8');
    cmp_deeply([sort @got], ['IP:1.2.3.4', 'IP:5.6.7.8'],
               'list context: each element prefixed with IP:');

    my $scalar = HELPERS::gen_subjectaltname_contents('DNS:', 'a.example', 'b.example');
    my @parts = split /,\s*/, $scalar;
    cmp_deeply([sort @parts], ['DNS:a.example', 'DNS:b.example'],
               'scalar context: comma-joined string');
};

subtest 'gen_subjectaltname_contents: comma+space-separated input is split' => sub {
    my @got = HELPERS::gen_subjectaltname_contents('DNS:',
        '1.example, 2.example 3.example');
    cmp_deeply([sort @got],
               ['DNS:1.example', 'DNS:2.example', 'DNS:3.example'],
               'commas AND spaces split input list');
};

subtest 'gen_subjectaltname_contents: heuristic - IP dotted-quad' => sub {
    my @got = HELPERS::gen_subjectaltname_contents('', '10.0.0.1');
    cmp_deeply(\@got, ['IP:10.0.0.1'], 'dotted-quad recognised as IP');
};

subtest 'gen_subjectaltname_contents: heuristic - email' => sub {
    my @got = HELPERS::gen_subjectaltname_contents('', 'foo@example.com');
    cmp_deeply(\@got, ['email:foo@example.com'],
               'mailbox@domain recognised as email');
};

subtest 'gen_subjectaltname_contents: heuristic - DNS fallback' => sub {
    my @got = HELPERS::gen_subjectaltname_contents('', 'foo.example.com');
    cmp_deeply(\@got, ['DNS:foo.example.com'],
               'bare hostname falls back to DNS');
};

subtest 'gen_subjectaltname_contents: per-element prefix overrides' => sub {
    my @got = HELPERS::gen_subjectaltname_contents('',
        'ip:1.2.3.4', 'dns:foo.example', 'email:bar@example.com');
    cmp_deeply([sort @got],
               ['DNS:foo.example', 'IP:1.2.3.4', 'email:bar@example.com'],
               'IP/DNS uppercased, email lowercased');
};

subtest 'gen_subjectaltname_contents: dedup identical entries' => sub {
    my @got = HELPERS::gen_subjectaltname_contents('IP:', '1.2.3.4', '1.2.3.4');
    cmp_deeply(\@got, ['IP:1.2.3.4'], 'duplicate IPs collapsed');
};

# ------------------------------------------------------------------
# enc_base64 / dec_base64 — URL-safe base64 (fork-specific INVERSE
# of the standard RFC 4648 URL-safe alphabet).
#
#   standard "/"  =>  fork's "-"
#   standard "+"  =>  fork's "_"
#
# If a future stage switches to RFC 4648, the values here must change
# in lock-step with any reader that consumes existing tokens.
# ------------------------------------------------------------------
subtest 'base64: fork-specific URL-safe substitution map' => sub {
    is(HELPERS::enc_base64('?>?>'), 'Pz4-Pg==',
       'standard "/" becomes "-"');

    is(HELPERS::enc_base64("\xfb"), '_w==',
       'standard "+" becomes "_"');

    my $enc = HELPERS::enc_base64('?>?>' . "\xfb");
    unlike($enc, qr![/+]!, 'no raw + or / leaks through');
};

subtest 'base64: round-trip preserves payload' => sub {
    for my $sample ('hello', '?>?>', "\x00\x01\x02\xff",
                    'CN=foo,O=bar', 'x' x 200) {
        is(HELPERS::dec_base64(HELPERS::enc_base64($sample)), $sample,
           'round-trip preserves: ' . unpack('H*', $sample));
    }
};

subtest 'base64: encoded string has no embedded whitespace' => sub {
    my $enc = HELPERS::enc_base64('x' x 100);
    unlike($enc, qr/\s/, 'no whitespace in URL-safe output');
};

done_testing();
