package TestCA;

# Build a throwaway CA directory tree for integration tests.
#
# Usage (basic — just a tempdir + template):
#
#     use lib 't/lib';
#     use TestCA;
#
#     my $ca = TestCA->new;
#     $ca->root;                     # /tmp/.../tinyca-root
#     $ca->openssl_cnf('myca');      # path to that CA's openssl.cnf
#     $ca->password;                 # canned passphrase
#
# Usage (full — a real, signed CA ready for cert ops):
#
#     my $ssl = OpenSSL->new('/usr/bin/openssl', $ca->tmp_dir);
#     my $info = $ca->build_ca($ssl, 'myca', bits => 1024);
#     # $info: { dir, config, key, cert, serial, index, crl, password, ... }
#
# Cleanup is automatic — File::Temp's tempdir is unlinked when the object
# goes out of scope.

use strict;
use warnings;

use File::Temp ();
use File::Path qw(make_path);
use File::Copy qw(copy);
use File::Basename qw(dirname);
use File::Spec ();
use FindBin qw($Bin);

sub new {
    my ($class, %opts) = @_;

    my $tmp = File::Temp->newdir(
        TEMPLATE => 'tinyca-test-XXXXXX',
        CLEANUP  => !$opts{keep},
        TMPDIR   => 1,
    );

    my $self = {
        tmp           => $tmp,                  # File::Temp::Dir
        root          => "$tmp/tinyca-root",
        export        => "$tmp/tinyca-export",
        template      => "$tmp/tinyca-template",
        tmp_dir       => "$tmp/tinyca-tmp",
        password      => 'test-passphrase',
        project_root  => _project_root(),
    };
    bless $self, $class;

    make_path($self->{root}, $self->{export}, $self->{template},
              $self->{tmp_dir});
    $self->_install_template;

    return $self;
}

sub root         { $_[0]->{root} }
sub export_dir   { $_[0]->{export} }
sub template_dir { $_[0]->{template} }
sub tmp_dir      { $_[0]->{tmp_dir} }
sub password     { $_[0]->{password} }
sub project_root { $_[0]->{project_root} }

sub ca_dir {
    my ($self, $name) = @_;
    return File::Spec->catdir($self->{root}, $name);
}

sub openssl_cnf {
    my ($self, $name) = @_;
    return File::Spec->catfile($self->ca_dir($name), 'openssl.cnf');
}

sub writefile {
    my ($self, $path, $data) = @_;
    make_path(dirname($path)) unless -d dirname($path);
    open my $fh, '>', $path or die "writefile $path: $!";
    binmode $fh;
    print {$fh} $data;
    close $fh;
    return $path;
}

sub readfile {
    my ($self, $path) = @_;
    open my $fh, '<', $path or die "readfile $path: $!";
    binmode $fh;
    local $/;
    my $data = <$fh>;
    close $fh;
    return $data;
}

sub init_hash {
    my $self = shift;
    return {
        opensslbin  => '/usr/bin/openssl',
        zipbin      => '/usr/bin/zip',
        tarbin      => '/bin/tar',
        templatedir => $self->{template},
        basedir     => $self->{root},
        exportdir   => $self->{export},
        tmpdir      => $self->{tmp_dir},
    };
}

# ----------------------------------------------------------------------
# build_ca($ssl, $name, %opts) — stand up a complete CA tree ready for
# cert operations.
#
# Replicates the directory layout that CA.pm::create_ca_env builds:
#
#   <root>/<name>/openssl.cnf
#   <root>/<name>/cacert.key
#   <root>/<name>/cacert.pem
#   <root>/<name>/serial
#   <root>/<name>/crl_serial
#   <root>/<name>/index.txt
#   <root>/<name>/index.txt.attr
#   <root>/<name>/{req,keys,certs,crl,newcerts}/
#
# Returns a hash:
#
#   { dir, config, key, cert, serial, crl_serial, index, crl,
#     newcerts, certs, keys, req, password }
#
# Uses 1024-bit RSA by default for speed. Pass `bits => 2048` if a test
# needs stronger keys. Subject is "/CN=Test CA <name>/O=tinyca-test/C=US".
# ----------------------------------------------------------------------
sub build_ca {
    my ($self, $ssl, $name, %opts) = @_;

    my $bits   = $opts{bits}   // 1024;
    my $days   = $opts{days}   // 365;
    my $digest = $opts{digest} // 'sha256';
    my $cn     = $opts{cn}     // "Test CA $name";

    my $dir = $self->ca_dir($name);
    make_path("$dir/$_") for qw(req keys certs crl newcerts);

    # Seed openssl.cnf from template with %dir% substituted, like
    # CA::create_ca_env does.
    my $template = $self->readfile(
        File::Spec->catfile($self->{template}, 'openssl.cnf'));
    $template =~ s/\%dir\%/$dir/g;
    my $config = "$dir/openssl.cnf";
    $self->writefile($config, $template);

    # Empty index + initial serial files.
    $self->writefile("$dir/index.txt", '');
    $self->writefile("$dir/index.txt.attr", "unique_subject = yes\n");
    $self->writefile("$dir/serial", "01\n");
    $self->writefile("$dir/crl_serial", "01\n");

    my $key  = "$dir/cacert.key";
    my $req  = "$dir/cacert.req";
    my $cert = "$dir/cacert.pem";
    # Production CA::create_ca writes the CRL to <dir>/crl/crl.pem (CA.pm
    # line ~1162) and CERT::parse_cert hardcodes that same path. Mirror it.
    my $crl  = "$dir/crl/crl.pem";

    # Generate CA key.
    my ($ret, $ext) = $ssl->newkey(
        algo    => 'RSA',
        bits    => $bits,
        outfile => $key,
        pass    => $self->{password},
    );
    die "build_ca: newkey failed (ret=$ret)\n$ext" if $ret;

    # Generate CA CSR.
    # NOTE: the openssl.cnf template's [req] section sets
    #   attributes = req_attributes
    # so openssl will prompt for TWO more values beyond the 7 DN fields
    # (challengePassword + unstructuredName). REQ::create_req in
    # production also tacks two empty strings on the end. Mirror that
    # contract — without it openssl waits forever on stdin.
    ($ret, $ext) = $ssl->newreq(
        config  => $config,
        outfile => $req,
        keyfile => $key,
        digest  => $digest,
        pass    => $self->{password},
        dn      => [ 'US', '', '', 'tinyca-test', '', $cn, '', '', '' ],
    );
    die "build_ca: newreq failed (ret=$ret)\n$ext" if $ret;

    # Self-sign as CA via newcert. newcert generates a random hex serial
    # and writes it to $cadir/serial — that's the fork's signature
    # behaviour and we want it exercised by the fixture itself.
    ($ret, $ext) = $ssl->newcert(
        cadir   => $dir,
        config  => $config,
        outfile => $cert,
        keyfile => $key,
        reqfile => $req,
        days    => $days,
        digest  => $digest,
        pass    => $self->{password},
    );
    die "build_ca: newcert failed (ret=$ret)\n$ext" if $ret;

    # Reset serial to '01' AFTER the self-sign — newcert wrote the
    # random hex serial to the file, but signreq's `openssl ca` needs
    # a parseable hex serial in the file for the next-issued cert.
    # CA::create_ca actually does this too (it doesn't reset, but the
    # serial file is updated by `openssl ca` itself).
    # We DO need a usable starting serial; '01' works.
    $self->writefile("$dir/serial", "01\n");

    # Initial CRL — empty.
    ($ret, $ext) = $ssl->newcrl(
        config  => $config,
        pass    => $self->{password},
        crldays => 30,
        outfile => $crl,
        format  => 'PEM',
    );
    die "build_ca: newcrl failed (ret=$ret)\n$ext" if $ret;

    return {
        name       => $name,
        dir        => $dir,
        config     => $config,
        key        => $key,
        cert       => $cert,
        req        => $req,
        serial     => "$dir/serial",
        crl_serial => "$dir/crl_serial",
        index      => "$dir/index.txt",
        crl        => $crl,
        certs      => "$dir/certs",
        newcerts   => "$dir/newcerts",
        keys       => "$dir/keys",
        password   => $self->{password},
    };
}

sub _install_template {
    my $self = shift;
    my $src = File::Spec->catfile($self->{project_root}, 'template', 'openssl.cnf');
    die "template/openssl.cnf missing at $src" unless -f $src;
    copy($src, File::Spec->catfile($self->{template}, 'openssl.cnf'))
        or die "copy template: $!";
}

sub _project_root {
    return File::Spec->rel2abs(File::Spec->catdir($Bin, '..'));
}

1;
