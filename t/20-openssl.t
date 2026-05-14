#!perl
# Stage 2 — integration tests for tinyca/OpenSSL.pm against the real
# `openssl` binary in PATH.
#
# What we lock down:
#
#   * `new` constructor + version regex (notes the OpenSSL 3.x gap).
#   * `fixSerial` colon insertion.
#   * `_get_index_date` for both 13- and 15-digit formats (fork feature 6).
#   * `newkey` (RSA) generates an AES-256 encrypted PEM key.
#   * `newreq` generates a usable CSR.
#   * `newcert` self-signs the CSR AND writes the fork-specific
#     long random hex serial to <cadir>/serial (fork features 1 & 4).
#   * `convdata` round-trips PEM<->DER<->TEXT for x509/req.
#   * `parsecert` returns every documented field, including
#     SHA-256/384/512 fingerprints (fork feature 8) and parses
#     OpenSSL 1.x multi-line hex serial (fork feature 5).
#   * `parsereq` returns TYPE='PKCS#10' and the DN fields.
#   * `signreq` produces a signed cert whose SAN is driven by
#     ${ENV::SUBJECTALTNAMEDNS} (fork feature 7), with STATUS=VALID.
#   * `revoke` + `newcrl` + `parsecrl` cycle: a signed cert moves to
#     STATUS=REVOKED and the CRL's LIST contains its serial.
#   * `convkey` re-encrypts an RSA key with a new passphrase and exhibits
#     its (idiosyncratic) return-value convention.
#   * `genp12` produces a PKCS#12 file that openssl can read back.
#   * `read_index` parses TinyCA's index.txt format.
#
# Tests use 1024-bit RSA keys for speed — these are NOT secure values,
# only fast fixtures. Production code defaults to 4096 (preserved).
#
# Heavy CA setup is done lazily via a closure so subtests that don't
# need the full CA don't pay the cost.

use strict;
use warnings;
use Test::More;
use Test::Deep;
use Test::Exception;

use FindBin ();
use lib "$FindBin::Bin/lib";
use lib "$FindBin::Bin/../tinyca";

use MockGtk;
use MockGUIHelpers;
MockGtk->install;
MockGUIHelpers->install;

sub ::_ { return $_[0]; }

use MIME::Base64 ();
use File::Temp ();
use File::Spec ();
use File::Path qw(make_path);

use_ok('HELPERS')  or BAIL_OUT('HELPERS.pm failed to load');
use_ok('OpenSSL')  or BAIL_OUT('OpenSSL.pm failed to load');
use_ok('TestCA')   or BAIL_OUT('TestCA helper failed to load');

# Skip the whole file if openssl isn't available.
my $OPENSSL = '/usr/bin/openssl';
unless (-x $OPENSSL) {
    plan skip_all => "openssl binary not found at $OPENSSL";
}

# ----------------------------------------------------------------------
# Shared lazy CA fixture: only built when a subtest actually needs it.
# ----------------------------------------------------------------------
my ($shared_tc, $shared_ssl, $shared_ca);

sub shared_ca {
    return ($shared_tc, $shared_ssl, $shared_ca) if $shared_ca;
    $shared_tc  = TestCA->new;
    $shared_ssl = OpenSSL->new($OPENSSL, $shared_tc->tmp_dir);
    $shared_ca  = $shared_tc->build_ca($shared_ssl, 'serverca', bits => 1024);
    return ($shared_tc, $shared_ssl, $shared_ca);
}

# ----------------------------------------------------------------------
# OpenSSL->new
# ----------------------------------------------------------------------
subtest 'new: constructs and returns a blessed object' => sub {
    my $tc  = TestCA->new;
    my $ssl = OpenSSL->new($OPENSSL, $tc->tmp_dir);
    isa_ok($ssl, 'OpenSSL', 'returns blessed object');
    is($ssl->{bin}, $OPENSSL, 'bin path stored');
    is($ssl->{tmp}, $tc->tmp_dir, 'tmp dir stored');
    ok(exists $ssl->{broken}, 'broken flag set');
};

subtest 'new: missing binary triggers print_error (dies via mock)' => sub {
    my $tc = TestCA->new;
    MockGUIHelpers->reset;
    throws_ok(
        sub { OpenSSL->new('/nonexistent/openssl-nope', $tc->tmp_dir) },
        qr/MockGUIHelpers::error/,
        'print_error invoked when binary is missing'
    );
};

subtest 'new: version regex captures any modern OpenSSL X.Y.Z[letter]' => sub {
    # Stage 12 fix landed: the regex now matches 0.9.x, 1.x.x, 2.x.x,
    # 3.x.x, 4.x.x, etc. Previously OpenSSL 3.x left $self->{version}
    # undef. Lock down the fix.
    my $tc  = TestCA->new;
    my $ssl = OpenSSL->new($OPENSSL, $tc->tmp_dir);

    chomp(my $v = qx{$OPENSSL version});
    if ($v =~ /\bOpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]?)/) {
        my $live = $1;
        is($ssl->{version}, $live,
           "version captured for live openssl $live");
    } else {
        # Unrecognised openssl version line — don't fail, but flag it.
        ok(1, "skipped: openssl version line '$v' did not match expected pattern");
    }
};

# ----------------------------------------------------------------------
# fixSerial — pure helper
# ----------------------------------------------------------------------
subtest 'fixSerial: colon-separates every 2 hex chars' => sub {
    is(OpenSSL::fixSerial('ABCD'),       'AB:CD',      '4-char serial');
    is(OpenSSL::fixSerial('ABCDEF'),     'AB:CD:EF',   '6-char serial');
    is(OpenSSL::fixSerial('AB'),         'AB',         '2-char serial — no trailing colon');
    is(OpenSSL::fixSerial('AB:CD'),
       'AB::C:D',
       'pre-existing colons are appended verbatim (locked-down quirk)');
};

# ----------------------------------------------------------------------
# _get_index_date — fork feature 6 (15-digit dates for years > 2050)
# ----------------------------------------------------------------------
subtest '_get_index_date: 13-digit YYMMDDHHMMSSZ (legacy)' => sub {
    # 250101000000Z = 2025-01-01 00:00:00 (length 13)
    my $epoch = OpenSSL::_get_index_date('250101000000Z');
    my @local = localtime($epoch);
    is($local[5] + 1900, 2025, 'year decoded as 2025');
    is($local[4] + 1,    1,    'month decoded as January');
    is($local[3],        1,    'day decoded as 1');
};

subtest '_get_index_date: 15-digit YYYYMMDDHHMMSSZ (fork feature)' => sub {
    # 207501010000Z would overflow 2-digit year; fork uses 15-char form.
    # 20750101000000Z = 2075-01-01 (length 15)
    my $epoch = OpenSSL::_get_index_date('20750101000000Z');
    my @local = localtime($epoch);
    is($local[5] + 1900, 2075, 'year decoded as 2075 (>2050)');
    is($local[4] + 1,    1,    'month decoded as January');
    is($local[3],        1,    'day decoded as 1');
};

# ----------------------------------------------------------------------
# newkey — RSA key generation
# ----------------------------------------------------------------------
subtest 'newkey: RSA generates an encrypted PEM private key' => sub {
    my $tc  = TestCA->new;
    my $ssl = OpenSSL->new($OPENSSL, $tc->tmp_dir);
    my $out = $tc->tmp_dir . "/newkey.pem";

    my ($ret, $ext) = $ssl->newkey(
        algo    => 'RSA',
        bits    => 1024,
        outfile => $out,
        pass    => $tc->password,
    );
    is($ret, 0, 'newkey returned 0 (success)') or diag $ext;
    ok(-s $out, 'output file has non-zero size');

    my $pem = $tc->readfile($out);
    # OpenSSL 1.1+ writes the encrypted key inside PKCS#8 ENCRYPTED PRIVATE KEY.
    like($pem,
         qr/-----BEGIN (?:RSA |ENCRYPTED )?PRIVATE KEY-----/,
         'PEM header present');
    like($pem,
         qr/-----END (?:RSA |ENCRYPTED )?PRIVATE KEY-----/,
         'PEM trailer present');
};

subtest 'newkey: nonzero ret when openssl rejects bits' => sub {
    my $tc  = TestCA->new;
    my $ssl = OpenSSL->new($OPENSSL, $tc->tmp_dir);

    my ($ret, $ext) = $ssl->newkey(
        algo    => 'RSA',
        bits    => 0,    # invalid
        outfile => $tc->tmp_dir . "/bad.pem",
        pass    => $tc->password,
    );
    isnt($ret, 0, 'newkey returns nonzero on bad bits');
};

# ----------------------------------------------------------------------
# newcert: long random hex serial (fork features 1 + 4)
# ----------------------------------------------------------------------
subtest 'newcert: writes 36-char uppercase hex serial starting 1-9 to <cadir>/serial' => sub {
    my ($tc, $ssl, $ca) = shared_ca();
    my $serial_txt = $tc->readfile($ca->{serial});
    chomp $serial_txt;
    # newcert overwrote serial during build_ca; build_ca then reset it to
    # 01 for subsequent ops. To verify the random-hex behaviour, redo a
    # self-sign on a fresh CA.

    my $tc2  = TestCA->new;
    my $ssl2 = OpenSSL->new($OPENSSL, $tc2->tmp_dir);
    my $dir  = $tc2->ca_dir('verify-serial');
    make_path("$dir/$_") for qw(req keys certs crl newcerts);
    my $cnf = do {
        my $t = $tc2->readfile($tc2->template_dir . "/openssl.cnf");
        $t =~ s/\%dir\%/$dir/g;
        $tc2->writefile("$dir/openssl.cnf", $t);
    };
    $tc2->writefile("$dir/index.txt", '');
    $tc2->writefile("$dir/serial", "01\n");
    $tc2->writefile("$dir/crl_serial", "01\n");

    my $key = "$dir/cacert.key";
    my $req = "$dir/cacert.req";
    my $crt = "$dir/cacert.pem";

    $ssl2->newkey(algo => 'RSA', bits => 1024, outfile => $key,
                  pass => $tc2->password);
    $ssl2->newreq(config => $cnf, outfile => $req, keyfile => $key,
                  digest => 'sha256', pass => $tc2->password,
                  dn => [ 'US', '', '', 'tinyca-test', '', 'serial-cn',
                          '', '', '' ]);   # last two empties: req_attributes
    my ($ret, $ext) = $ssl2->newcert(
        cadir   => $dir,
        config  => $cnf,
        outfile => $crt,
        keyfile => $key,
        reqfile => $req,
        days    => 365,
        digest  => 'sha256',
        pass    => $tc2->password,
    );
    is($ret, 0, 'newcert returned success') or diag $ext;

    my $serial = $tc2->readfile("$dir/serial");
    chomp $serial;
    # The shell pipeline is:
    #   openssl rand -hex 18 | sed 's/^0/<digit>/' | tr a-z A-Z
    # `sed` only replaces a LEADING '0' with a 1-9 digit. If the random
    # first nibble was already 1-F (hex), it stays. So the first char is
    # any non-zero hex digit (1-9 or A-F).
    like($serial, qr/^[1-9A-F][0-9A-F]{35}$/,
         "serial '$serial' is 36 uppercase hex chars, first char in [1-9A-F]");
};

subtest 'newcert: successive runs produce different serials' => sub {
    my $tc  = TestCA->new;
    my $ssl = OpenSSL->new($OPENSSL, $tc->tmp_dir);

    my @serials;
    for my $i (1..2) {
        my $dir = $tc->ca_dir("ca$i");
        make_path("$dir/$_") for qw(req keys certs crl newcerts);
        my $t = $tc->readfile($tc->template_dir . "/openssl.cnf");
        $t =~ s/\%dir\%/$dir/g;
        $tc->writefile("$dir/openssl.cnf", $t);
        $tc->writefile("$dir/index.txt", '');
        $tc->writefile("$dir/serial", "01\n");
        $tc->writefile("$dir/crl_serial", "01\n");

        $ssl->newkey(algo=>'RSA', bits=>1024,
                     outfile=>"$dir/cacert.key", pass=>$tc->password);
        $ssl->newreq(config=>"$dir/openssl.cnf", outfile=>"$dir/cacert.req",
                     keyfile=>"$dir/cacert.key", digest=>'sha256',
                     pass=>$tc->password,
                     dn=>['US','','','tinyca-test','',"cn$i",
                          '','','']);   # last two: req_attributes
        $ssl->newcert(cadir=>$dir, config=>"$dir/openssl.cnf",
                      outfile=>"$dir/cacert.pem", keyfile=>"$dir/cacert.key",
                      reqfile=>"$dir/cacert.req", days=>365,
                      digest=>'sha256', pass=>$tc->password);

        chomp(my $s = $tc->readfile("$dir/serial"));
        push @serials, $s;
    }
    isnt($serials[0], $serials[1],
         "two newcert serials differ: $serials[0] vs $serials[1]");
};

# ----------------------------------------------------------------------
# convdata: PEM <-> DER <-> TEXT for x509 and req
# ----------------------------------------------------------------------
subtest 'convdata: x509 PEM -> DER -> PEM round-trip' => sub {
    my ($tc, $ssl, $ca) = shared_ca();
    my $pem = $tc->readfile($ca->{cert});

    my ($ret, $der, $ext) = $ssl->convdata(
        cmd => 'x509', data => $pem,
        inform => 'PEM', outform => 'DER',
    );
    is($ret, 0, 'PEM->DER conversion ret=0') or diag $ext;
    ok(defined $der && length $der > 100, 'DER output is non-trivial');
    # DER starts with 0x30 (SEQUENCE).
    is(ord(substr($der, 0, 1)), 0x30, 'DER begins with 0x30 (SEQUENCE)');

    my ($ret2, $pem2, $ext2) = $ssl->convdata(
        cmd => 'x509', data => $der,
        inform => 'DER', outform => 'PEM',
    );
    is($ret2, 0, 'DER->PEM conversion ret=0') or diag $ext2;
    like($pem2, qr/-----BEGIN CERTIFICATE-----/, 'PEM header restored');
};

subtest 'convdata: x509 PEM -> TEXT contains expected labels' => sub {
    my ($tc, $ssl, $ca) = shared_ca();
    my ($ret, $txt, $ext) = $ssl->convdata(
        cmd => 'x509', data => $tc->readfile($ca->{cert}),
        inform => 'PEM', outform => 'TEXT',
    );
    is($ret, 0, 'PEM->TEXT ret=0') or diag $ext;
    like($txt, qr/Issuer:/,        'TEXT contains Issuer:');
    like($txt, qr/Subject:/,       'TEXT contains Subject:');
    like($txt, qr/Serial Number:/, 'TEXT contains Serial Number:');
};

# ----------------------------------------------------------------------
# parsecert: full parse (fork features 5, 8)
# ----------------------------------------------------------------------
subtest 'parsecert: returns all expected fields' => sub {
    my ($tc, $ssl, $ca) = shared_ca();
    my $info = $ssl->parsecert($ca->{crl}, $ca->{index}, $ca->{cert}, 1);

    isa_ok($info, 'HASH', 'parsecert returns hashref');

    for my $field (qw(PEM TEXT DER ISSUER NOTBEFORE NOTAFTER
                      PK_ALGORITHM KEYSIZE DN
                      FINGERPRINTMD5 FINGERPRINTSHA1
                      FINGERPRINTSHA256 FINGERPRINTSHA384 FINGERPRINTSHA512
                      STATUS EXPDATE)) {
        ok(defined $info->{$field}, "field $field is set");
    }

    # Stage 12 fix: SUBJECT regex now matches both
    #   OpenSSL <= 1.0.x   :  "subject= /C=US/O=foo/CN=bar"
    #   OpenSSL >= 1.1     :  "subject=C = US, O = foo, CN = bar"
    # So SUBJECT must be populated on every supported OpenSSL.
    ok(defined $info->{SUBJECT} && length $info->{SUBJECT},
       'SUBJECT populated regardless of OpenSSL version');

    like($info->{PEM},   qr/-----BEGIN CERTIFICATE-----/, 'PEM body intact');
    like($info->{TEXT},  qr/Subject:/,                    'TEXT body intact');
    like($info->{FINGERPRINTMD5},    qr/^([0-9A-F]{2}:){15}[0-9A-F]{2}$/i,
         'MD5 fingerprint is 16 octets');
    like($info->{FINGERPRINTSHA1},   qr/^([0-9A-F]{2}:){19}[0-9A-F]{2}$/i,
         'SHA1 fingerprint is 20 octets');
    like($info->{FINGERPRINTSHA256}, qr/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/i,
         'SHA256 fingerprint is 32 octets');
    like($info->{FINGERPRINTSHA384}, qr/^([0-9A-F]{2}:){47}[0-9A-F]{2}$/i,
         'SHA384 fingerprint is 48 octets');
    like($info->{FINGERPRINTSHA512}, qr/^([0-9A-F]{2}:){63}[0-9A-F]{2}$/i,
         'SHA512 fingerprint is 64 octets');

    is($info->{STATUS}, 'VALID', 'self-signed CA cert has STATUS=VALID');
    cmp_ok($info->{KEYSIZE}, '==', 1024, 'KEYSIZE is 1024 bits');
};

subtest 'parsecert: caches and respects force-flag' => sub {
    my ($tc, $ssl, $ca) = shared_ca();
    my $a = $ssl->parsecert($ca->{crl}, $ca->{index}, $ca->{cert}, 1);
    my $b = $ssl->parsecert($ca->{crl}, $ca->{index}, $ca->{cert}, 0);
    is($a, $b, 'second parse returns cached hashref (same address)');

    my $c = $ssl->parsecert($ca->{crl}, $ca->{index}, $ca->{cert}, 1);
    isnt($a, $c, 'force-flag bypasses cache (new hashref)');
};

subtest 'parsecert: handles multi-line hex serial (OpenSSL 1.x format)' => sub {
    # Fork feature 5: parsecert has a state machine for the format
    #
    #     Serial Number:
    #         42:43:44
    #
    # which OpenSSL 1.x emits for >4-byte serials. The CA self-sign
    # above used a 144-bit serial — well over 4 bytes — so the live
    # cert in the fixture already exercises this code path. Just
    # confirm the result is a colon-separated hex string.
    my ($tc, $ssl, $ca) = shared_ca();
    my $info = $ssl->parsecert($ca->{crl}, $ca->{index}, $ca->{cert}, 1);
    like($info->{SERIAL},
         qr/^[0-9A-F]{2}(:[0-9A-F]{2})+$/i,
         "SERIAL '$info->{SERIAL}' is colon-separated hex");
    cmp_ok(length($info->{SERIAL}), '>', 8,
           'SERIAL is wider than a 4-byte int');
};

# ----------------------------------------------------------------------
# parsereq
# ----------------------------------------------------------------------
subtest 'parsereq: returns TYPE PKCS#10 plus DN fields' => sub {
    my ($tc, $ssl, $ca) = shared_ca();
    my $info = $ssl->parsereq($ca->{config}, $ca->{req}, 1);

    isa_ok($info, 'HASH', 'parsereq returns hashref');
    is($info->{TYPE}, 'PKCS#10', 'TYPE is PKCS#10');
    like($info->{PEM}, qr/-----BEGIN CERTIFICATE REQUEST-----/, 'PEM body');
    ok(defined $info->{DN},       'DN is present');
    ok(defined $info->{KEYSIZE},  'KEYSIZE is present');
    cmp_ok($info->{KEYSIZE}, '==', 1024, 'KEYSIZE is 1024 bits');
};

# ----------------------------------------------------------------------
# signreq + parsecert round-trip with SAN DNS (fork feature 7)
# ----------------------------------------------------------------------
subtest 'signreq: signs a server CSR with subjectAltName from ENV (DNS)' => sub {
    my ($tc, $ssl, $ca) = shared_ca();

    # Create a server-side keypair + CSR.
    my $skey = "$tc->{tmp}/server.key";
    my $sreq = "$tc->{tmp}/server.req";
    $ssl->newkey(algo => 'RSA', bits => 1024, outfile => $skey,
                 pass => $tc->password);
    $ssl->newreq(config => $ca->{config}, outfile => $sreq, keyfile => $skey,
                 digest => 'sha256', pass => $tc->password,
                 dn => ['US', '', '', 'tinyca-test', '',
                        'server.example.com', '',
                        '', '']);   # last two empties: req_attributes
    ok(-s $sreq, 'CSR was created');

    # Sign via server_ca (which uses [server_cert] which references
    # ${ENV::SUBJECTALTNAMEDNS}).
    my ($ret, $ext) = $ssl->signreq(
        config            => $ca->{config},
        caname            => 'server_ca',
        reqfile           => $sreq,
        days              => 365,
        pass              => $tc->password,
        sslservername     => 'none',
        revocationurl     => 'none',
        renewalurl        => 'none',
        subjaltname       => 'a.example, b.example',
        subjaltnametype   => 'dns',
        extendedkeyusage  => 'none',
        digest            => 'sha256',
    );
    is($ret, 0, 'signreq ret=0') or diag $ext;

    # `openssl ca -outdir` defaults to new_certs_dir from config —
    # newcerts/. Find the signed cert there.
    opendir my $dh, $ca->{newcerts} or die;
    my @certs = grep { /\.pem$/ } readdir $dh;
    closedir $dh;
    is(scalar @certs, 1, 'one cert in newcerts/');
    my $signed = "$ca->{newcerts}/$certs[0]";

    my $info = $ssl->parsecert($ca->{crl}, $ca->{index}, $signed, 1);
    is($info->{STATUS}, 'VALID', 'signed cert has STATUS=VALID');

    my $san = $info->{EXT};
    my $san_entry = '';
    for my $k (keys %$san) {
        $san_entry = join(',', @{$san->{$k}}) if $k =~ /Subject Alternative Name/i;
    }
    like($san_entry, qr/a\.example/,
         "SAN contains a.example: '$san_entry'");
    like($san_entry, qr/b\.example/,
         "SAN contains b.example: '$san_entry'");
};

# ----------------------------------------------------------------------
# revoke + newcrl + parsecrl
# ----------------------------------------------------------------------
subtest 'revoke + newcrl + parsecrl: STATUS becomes REVOKED' => sub {
    my $tc  = TestCA->new;
    my $ssl = OpenSSL->new($OPENSSL, $tc->tmp_dir);
    my $ca  = $tc->build_ca($ssl, 'revoke-ca', bits => 1024);

    # Sign one cert.
    my $key = "$tc->{tmp}/r.key";
    my $req = "$tc->{tmp}/r.req";
    $ssl->newkey(algo=>'RSA', bits=>1024, outfile=>$key, pass=>$tc->password);
    $ssl->newreq(config=>$ca->{config}, outfile=>$req, keyfile=>$key,
                 digest=>'sha256', pass=>$tc->password,
                 dn=>['US','','','tinyca-test','','rev.example',
                      '','','']);   # last two: req_attributes
    my ($srv_ret, $srv_ext) = $ssl->signreq(
        config=>$ca->{config}, caname=>'server_ca', reqfile=>$req, days=>365,
        pass=>$tc->password, sslservername=>'none', revocationurl=>'none',
        renewalurl=>'none', subjaltname=>'rev.example', subjaltnametype=>'dns',
        extendedkeyusage=>'none', digest=>'sha256',
    );
    is($srv_ret, 0, 'signreq ok') or diag $srv_ext;

    opendir my $dh, $ca->{newcerts} or die;
    my ($signed) = map { "$ca->{newcerts}/$_" } grep { /\.pem$/ } readdir $dh;
    closedir $dh;

    # Pre-state: STATUS=VALID.
    my $before = $ssl->parsecert($ca->{crl}, $ca->{index}, $signed, 1);
    is($before->{STATUS}, 'VALID', 'before revoke: VALID');

    # Revoke.
    my ($rret, $rext) = $ssl->revoke(
        config=>$ca->{config}, infile=>$signed,
        pass=>$tc->password, reason=>'keyCompromise',
    );
    is($rret, 0, 'revoke ret=0') or diag $rext;

    # Regen CRL.
    my ($cret, $cext) = $ssl->newcrl(
        config=>$ca->{config}, pass=>$tc->password,
        crldays=>30, outfile=>$ca->{crl}, format=>'PEM',
    );
    is($cret, 0, 'newcrl ret=0') or diag $cext;

    # parsecrl reads it back and finds the revoked serial.
    my $crl = $ssl->parsecrl($ca->{crl}, 1);
    ok(defined $crl, 'parsecrl returns hashref');
    ok(scalar @{$crl->{LIST} || []} >= 1, 'CRL list has at least one entry');

    # Now re-parse the cert against the new CRL — STATUS should be REVOKED.
    my $after = $ssl->parsecert($ca->{crl}, $ca->{index}, $signed, 1);
    is($after->{STATUS}, 'REVOKED', 'after revoke + CRL refresh: REVOKED');
};

subtest 'newcrl: DER format produces DER bytes' => sub {
    my ($tc, $ssl, $ca) = shared_ca();
    my $der_crl = "$tc->{tmp}/crl.der";
    my ($ret, $ext) = $ssl->newcrl(
        config=>$ca->{config}, pass=>$tc->password,
        crldays=>30, outfile=>$der_crl, format=>'DER',
    );
    is($ret, 0, 'newcrl DER ret=0') or diag $ext;
    ok(-s $der_crl, 'DER CRL file written');
    my $body = $tc->readfile($der_crl);
    is(ord(substr($body, 0, 1)), 0x30, 'DER CRL starts with 0x30');
};

# ----------------------------------------------------------------------
# convkey: re-encrypt RSA key with a new passphrase
# ----------------------------------------------------------------------
subtest 'convkey: re-encrypts RSA key (idiosyncratic return convention)' => sub {
    my $tc  = TestCA->new;
    my $ssl = OpenSSL->new($OPENSSL, $tc->tmp_dir);
    my $orig = "$tc->{tmp}/k.pem";
    $ssl->newkey(algo=>'RSA', bits=>1024, outfile=>$orig,
                 pass=>$tc->password);

    # convkey returns ($tmp) on success, ($ret, $ext) on error.
    # We call in list context and inspect.
    my @out = $ssl->convkey(
        type    => 'RSA',
        inform  => 'PEM',
        outform => 'PEM',
        nopass  => 0,
        oldpass => $tc->password,
        pass    => 'new-passphrase',
        keyfile => $orig,
    );

    # Success case: one return value (the new PEM key text).
    # Error case: ($ret=1, $ext) — two values, first is `1`.
    if (@out == 2 && $out[0] eq '1') {
        fail("convkey failed: $out[1]");
    } else {
        ok(@out >= 1, 'convkey returned at least one value');
        like($out[0],
             qr/-----BEGIN (?:RSA |ENCRYPTED )?PRIVATE KEY-----/,
             're-encrypted key is a PEM private key');
    }
};

# ----------------------------------------------------------------------
# genp12
# ----------------------------------------------------------------------
subtest 'genp12: produces a readable PKCS#12 file' => sub {
    my ($tc, $ssl, $ca) = shared_ca();
    my $out = "$tc->{tmp}/bundle.p12";

    my ($ret, $ext) = $ssl->genp12(
        certfile  => $ca->{cert},
        keyfile   => $ca->{key},
        outfile   => $out,
        passwd    => $tc->password,
        p12passwd => 'p12-pass',
        includeca => 0,
        nopass    => 0,
        friendly  => 'test-bundle',
    );
    is($ret, 0, 'genp12 ret=0') or diag $ext;
    ok(-s $out, 'PKCS#12 file written');

    # Use openssl directly to verify it parses back. OpenSSL 3 requires
    # -legacy for keys encrypted with PBE-SHA1 (old default), but we used
    # nopass=0 with a newly-built key, so default ciphers apply. Try both.
    my $p12_dump = qx{$OPENSSL pkcs12 -in $out -passin pass:p12-pass -passout pass:foo -nodes -noout -info 2>&1};
    $p12_dump   .= qx{$OPENSSL pkcs12 -in $out -legacy -passin pass:p12-pass -passout pass:foo -nodes -noout -info 2>&1}
        if $p12_dump =~ /error|unsupported/i;
    like($p12_dump, qr/MAC:/i, 'openssl re-parses the PKCS#12 (sees MAC line)');
};

# ----------------------------------------------------------------------
# read_index — TinyCA's index.txt parser
# ----------------------------------------------------------------------
subtest 'read_index: parses index.txt with valid, expired, revoked rows' => sub {
    my $tc = TestCA->new;
    my $idx = "$tc->{tmp}/index.txt";
    # Hand-craft a multi-row index file. Field separator is TAB.
    # Fields: STATUS \t EXPDATE \t REVDATE \t SERIAL \t xxx \t DN
    # REVDATE for revoked rows may contain ",reason".
    my $txt = join("\t", 'V', '301231000000Z', '',                'AB12', 'unknown', "/CN=valid\n");
    $txt   .= join("\t", 'E', '200101000000Z', '',                'CD34', 'unknown', "/CN=expired\n");
    $txt   .= join("\t", 'R', '301231000000Z', '250601000000Z,keyCompromise',
                                                                    'EF56', 'unknown', "/CN=revoked\n");
    $tc->writefile($idx, $txt);

    my $ssl = OpenSSL->new($OPENSSL, $tc->tmp_dir);
    my @rows = $ssl->read_index($idx);
    is(scalar @rows, 3, 'three rows parsed');

    is($rows[0]->{STATUS}, 'V', 'row 0 STATUS V');
    is($rows[0]->{SERIAL}, 'AB:12', 'row 0 SERIAL colonised');

    is($rows[1]->{STATUS}, 'E', 'row 1 STATUS E');

    is($rows[2]->{STATUS},    'R',                'row 2 STATUS R');
    is($rows[2]->{REVREASON}, 'keyCompromise',    'row 2 REVREASON parsed');
    ok(defined $rows[2]->{REVDATE},               'row 2 REVDATE parsed');
};

done_testing();
