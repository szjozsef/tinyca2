# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: OpenSSL.pm,v 1.14 2006/07/13 22:36:13 sm Exp $
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.

use strict;
use warnings;

package OpenSSL;

use POSIX;
use IPC::Open3;
use IO::Select;
use Symbol qw(gensym);   # Stage 12: explicit import for the gensym call in _run_with_fixed_input
use Time::Local;
use UI;
use I18N qw(_);

sub new {
   my $self  = {};
   my ($that, $opensslbin, $tmpdir) = @_;
   my $class = ref($that) || $that;

   $self->{'bin'} = $opensslbin;
   my $t = sprintf("Can't execute OpenSSL: %s", $self->{'bin'});
   UI->error($t)
      if (! -x $self->{'bin'});

   $self->{'tmp'}  = $tmpdir;

   open(TEST, "$self->{'bin'} version|");
   my $v = <TEST>;
   close(TEST);

   # Capture any modern OpenSSL version string. Format examples:
   #   "OpenSSL 0.9.7a 17 Oct 2008"
   #   "OpenSSL 1.0.2u  20 Dec 2019"
   #   "OpenSSL 1.1.1w  11 Sep 2023"
   #   "OpenSSL 3.0.2 15 Mar 2022"
   #   "OpenSSL 3.2.1 30 Jan 2024"
   # Stage 12 fix: the previous regex matched only 0.9.x and 1.0/1.1/1.2.x,
   # leaving $self->{version} undef on any OpenSSL >= 3.x.
   if ($v =~ /\bOpenSSL\s+(\d+\.\d+\.\d+[a-z]?)\b/) {
      $self->{'version'} = $1;
   }

   # CRL output was broken before openssl 0.9.7f. Everything from 0.9.7f
   # onwards (including 1.x and 3.x) is fine.
   if ($v =~ /\b0\.9\.[0-6][a-z]?\b/ || $v =~ /\b0\.9\.7[a-e]?\b/) {
      $self->{'broken'} = 1;
   } else {
      $self->{'broken'} = 0;
   }
   bless($self, $class);
}

# Stage 24c: human-friendly rendering of the X.509 Public Key Algorithm
# string OpenSSL prints. Falls through unchanged if it's already a
# friendly name (e.g. an exotic key type not in this table).
sub _pretty_pk_algorithm {
    my $raw = shift // '';
    $raw =~ s/^\s+|\s+$//g;
    my %map = (
        'id-ecPublicKey'    => 'ECDSA',
        'ecPublicKey'       => 'ECDSA',
        'rsaEncryption'     => 'RSA',
        'rsassaPss'         => 'RSA-PSS',
        'rsa'               => 'RSA',
        'dsaEncryption'     => 'DSA',
        'id-dsa'            => 'DSA',
        'dsa'               => 'DSA',
        'ED25519'           => 'Ed25519',
        'ed25519'           => 'Ed25519',
        'ED448'             => 'Ed448',
        'ed448'             => 'Ed448',
    );
    return $map{$raw} // $raw;
}




sub newkey {
   my $self = shift;
   my $opts = { @_ };

   my ($cmd, $ext, $box, $bar, $t, $param, $pid, $ret);

   # Stage 24: algorithm dispatch covers RSA, DSA, ECDSA, Ed25519, Ed448.
   #
   #   algo='rsa' / bits=<integer>        legacy `genrsa`
   #   algo='dsa' / bits=<integer>        legacy two-step dsaparam + gendsa
   #   algo='ec'  / bits=<curve name>     modern `genpkey -algorithm EC`
   #   algo='ed25519'                     modern `genpkey -algorithm Ed25519`
   #   algo='ed448'                       modern `genpkey -algorithm Ed448`
   #
   # The DSA branch keeps its two-step shape so progress feedback still
   # works in pump_until_eof.
   my $algo = lc($opts->{'algo'} // 'rsa');

   if ($algo eq "dsa") {
      $param = HELPERS::mktmp($self->{'tmp'}."/param");

      $cmd = "$self->{'bin'} dsaparam";
      $cmd .= " -out $param";
      $cmd .= " $opts->{'bits'}";
      my($rdfh, $wtfh);
      $ext = "$cmd\n\n";
      $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
      $t = _("Creating DSA key in progress...");
      ($box, $bar) = UI->activity_bar($t);
      $ext .= UI->pump_until_eof($rdfh, sub { $bar->pulse });

      $box->destroy();
      waitpid($pid, 0);
      $ret = $? >> 8;
      return($ret, $ext) if($ret);

      $cmd = "$self->{'bin'} gendsa";
      $cmd .= " -aes256";
      $cmd .= " -passout env:SSLPASS";
      $cmd .= " -out \"$opts->{'outfile'}\"";
      $cmd .= " $param";
   }
   elsif ($algo eq "ec") {
      # Curve name carried in `bits` (e.g. "P-256", "P-384", "P-521",
      # "secp256k1"). genpkey accepts the standard NIST aliases.
      my $curve = $opts->{'bits'} // 'P-256';
      $cmd  = "$self->{'bin'} genpkey";
      $cmd .= " -algorithm EC";
      $cmd .= " -pkeyopt ec_paramgen_curve:$curve";
      $cmd .= " -aes-256-cbc";
      $cmd .= " -pass env:SSLPASS";
      $cmd .= " -out \"$opts->{'outfile'}\"";
   }
   elsif ($algo eq "ed25519" || $algo eq "ed448") {
      # Edwards-curve algorithms — fixed key size, no parameter.
      # The capitalised name matters: openssl expects "Ed25519"/"Ed448".
      my $name = $algo eq "ed25519" ? "Ed25519" : "Ed448";
      $cmd  = "$self->{'bin'} genpkey";
      $cmd .= " -algorithm $name";
      $cmd .= " -aes-256-cbc";
      $cmd .= " -pass env:SSLPASS";
      $cmd .= " -out \"$opts->{'outfile'}\"";
   }
   else {
      # Default: RSA via the legacy `genrsa` subcommand. Could be
      # `genpkey -algorithm RSA` too; we keep `genrsa` because the
      # progress-bar pumping is well-tested against its output.
      $cmd  = "$self->{'bin'} genrsa";
      $cmd .= " -aes256";
      $cmd .= " -passout env:SSLPASS";
      $cmd .= " -out \"$opts->{'outfile'}\"";
      $cmd .= " $opts->{'bits'}";
   }

   $ENV{'SSLPASS'} = $opts->{'pass'};
   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   $t = _("Creating RSA key in progress...");
   ($box, $bar) = UI->activity_bar($t);

   $ext .= UI->pump_until_eof($rdfh, sub { $bar->pulse });

   $box->destroy();

   waitpid($pid, 0);
   $ret = $? >> 8;

   if(defined($param) && $param ne '') {
      unlink($param);
   }

   delete($ENV{'SSLPASS'});

   return($ret, $ext);
}

sub signreq {
   my $self = shift;
   my $opts = { @_ };

   my ($ext, $cmd, $pid, $ret);
   $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';

   $cmd = "$self->{'bin'} ca -batch";
   $cmd .= " -passin env:SSLPASS -notext";
   $cmd .= " -config $opts->{'config'}";
   $cmd .= " -name $opts->{'caname'}" if($opts->{'caname'} ne "");
   $cmd .= " -in \"$opts->{'reqfile'}\"";
   $cmd .= " -days $opts->{'days'}";
   $cmd .= " -preserveDN";
   # Stage 24: only emit `-md X` when X is a plain message-digest name.
   # Algorithm-level identifiers like "ED25519" / "ED448" / "ecdsa-with-*"
   # leak through some upstream code paths and openssl ca rejects them
   # with "inner_evp_generic_fetch: unsupported". Drop -md in that case
   # and let openssl pick its built-in hash for the CA's key type.
   {
      my $d = lc($opts->{'digest'} // '');
      my %ok = map { $_ => 1 } qw(md4 md5 mdc2 ripemd160 sha1 sha224
                                  sha256 sha384 sha512);
      $cmd .= " -md $opts->{'digest'}" if $ok{$d};
   }

   if(defined($opts->{'mode'}) && $opts->{'mode'} eq "sub") {
      $cmd .= " -keyfile \"$opts->{'keyfile'}\"";
      $cmd .= " -cert \"$opts->{'cacertfile'}\"";
      $cmd .= " -outdir \"$opts->{'outdir'}\"";
      $ENV{'SSLPASS'} = $opts->{'parentpw'};
   } else {
      $ENV{'SSLPASS'} = $opts->{'pass'};
   }

   if(defined($opts->{'sslservername'}) && $opts->{'sslservername'} ne 'none') {
      $ENV{'NSSSLSERVERNAME'} = $opts->{'sslservername'};
   }
   if(defined($opts->{'revocationurl'}) && $opts->{'revocationurl'} ne 'none') {
      $ENV{'NSREVOCATIONURL'} = $opts->{'revocationurl'};
   }
   if(defined($opts->{'renewalurl'}) && $opts->{'renewalurl'} ne 'none') {
      $ENV{'NSRENEWALURL'} = $opts->{'renewalurl'};
   }
   if($opts->{'subjaltname'} ne 'none' &&
         $opts->{'subjaltname'} ne 'emailcopy') {
      if($opts->{'subjaltnametype'} eq 'ip') {
         $ENV{'SUBJECTALTNAMEIP'} = HELPERS::gen_subjectaltname_contents('IP:', $opts->{'subjaltname'});
      }elsif($opts->{'subjaltnametype'} eq 'dns') {
         $ENV{'SUBJECTALTNAMEDNS'} = HELPERS::gen_subjectaltname_contents('DNS:', $opts->{'subjaltname'});
      }elsif($opts->{'subjaltnametype'} eq 'mail') {
         $ENV{'SUBJECTALTNAMEEMAIL'} = HELPERS::gen_subjectaltname_contents('email:', $opts->{'subjaltname'});
      }elsif($opts->{'subjaltnametype'} eq 'raw') {
         $ENV{'SUBJECTALTNAMERAW'} = HELPERS::gen_subjectaltname_contents(undef, $opts->{'subjaltname'});
      }
   }
   if($opts->{'extendedkeyusage'} ne 'none') {
      $ENV{'EXTENDEDKEYUSAGE'} = $opts->{'extendedkeyusage'};
   }

   if(defined($opts->{'noemaildn'}) && $opts->{'noemaildn'}) {
      $cmd .= " -noemailDN";
   }

   my($rdfh, $wtfh);
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   $ext = "$cmd\n\n";
   while(<$rdfh>) {
      $ext .= $_;
      if($_ =~ /unable to load CA private key/) {
         delete($ENV{'SSLPASS'});
         $ENV{'NSSSLSERVERNAME'}     = 'dummy';
         $ENV{'NSREVOCATIONURL'}     = 'dummy';
         $ENV{'NSRENEWALURL'}        = 'dummy';
         $ENV{'SUBJECTALTNAMEIP'}    = 'dummy';
         $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';
         $ENV{'SUBJECTALTNAMEEMAIL'} = 'dummy';
         $ENV{'SUBJECTALTNAMERAW'}   = 'dummy';
         $ENV{'EXTENDEDKEYUSAGE'}    = 'dummy';
         waitpid($pid, 0);
         return(1, $ext);
      } elsif($_ =~ /trying to load CA private key/) {
         delete($ENV{'SSLPASS'});
         $ENV{'NSSSLSERVERNAME'}     = 'dummy';
         $ENV{'NSREVOCATIONURL'}     = 'dummy';
         $ENV{'NSRENEWALURL'}        = 'dummy';
         $ENV{'SUBJECTALTNAMEIP'}    = 'dummy';
         $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';
         $ENV{'SUBJECTALTNAMEEMAIL'} = 'dummy';
         $ENV{'SUBJECTALTNAMERAW'}   = 'dummy';
         $ENV{'EXTENDEDKEYUSAGE'}    = 'dummy';
         waitpid($pid, 0);
         return(2, $ext);
      } elsif($_ =~ /There is already a certificate for/) {
         delete($ENV{'SSLPASS'});
         $ENV{'NSSSLSERVERNAME'}     = 'dummy';
         $ENV{'NSREVOCATIONURL'}     = 'dummy';
         $ENV{'NSRENEWALURL'}        = 'dummy';
         $ENV{'SUBJECTALTNAMEIP'}    = 'dummy';
         $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';
         $ENV{'SUBJECTALTNAMEEMAIL'} = 'dummy';
         $ENV{'SUBJECTALTNAMERAW'}   = 'dummy';
         $ENV{'EXTENDEDKEYUSAGE'}    = 'dummy';
         waitpid($pid, 0);
         return(3, $ext);
      } elsif($_ =~ /bad ip address/) {
         delete($ENV{'SSLPASS'});
         $ENV{'NSSSLSERVERNAME'}     = 'dummy';
         $ENV{'NSREVOCATIONURL'}     = 'dummy';
         $ENV{'NSRENEWALURL'}        = 'dummy';
         $ENV{'SUBJECTALTNAMEIP'}    = 'dummy';
         $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';
         $ENV{'SUBJECTALTNAMEEMAIL'} = 'dummy';
         $ENV{'SUBJECTALTNAMERAW'}   = 'dummy';
         $ENV{'EXTENDEDKEYUSAGE'}    = 'dummy';
         waitpid($pid, 0);
         return(4, $ext);
      }
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   delete($ENV{'SSLPASS'});
   $ENV{'NSSSLSERVERNAME'}     = 'dummy';
   $ENV{'NSREVOCATIONURL'}     = 'dummy';
   $ENV{'NSRENEWALURL'}        = 'dummy';
   $ENV{'SUBJECTALTNAMEIP'}    = 'dummy';
   $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';
   $ENV{'SUBJECTALTNAMEEMAIL'} = 'dummy';
   $ENV{'SUBJECTALTNAMERAW'}   = 'dummy';
   $ENV{'EXTENDEDKEYUSAGE'}    = 'dummy';

   return($ret, $ext);
}

sub revoke {
   my $self = shift;
   my $opts = { @_ };

   my ($ext, $cmd, $ret, $pid);
   $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';

   $cmd = "$self->{'bin'} ca";
   $cmd .= " -passin env:SSLPASS";

   $cmd .= " -config $opts->{'config'}";
   $cmd .= " -revoke $opts->{'infile'}";

   if($opts->{'reason'} ne 'none') {
      $cmd .= " -crl_reason $opts->{'reason'}";
   }

   $ENV{'SSLPASS'} = $opts->{'pass'};
   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>) {
      $ext .= $_;
      if($_ =~ /unable to load CA private key/) {
         delete($ENV{'SSLPASS'});
         waitpid($pid, 0);
         return(1, $ext);
      } elsif($_ =~ /trying to load CA private key/) {
         delete($ENV{'SSLPASS'});
         waitpid($pid, 0);
         return(2, $ext);
      } elsif($_ =~ /^ERROR:/) {
         delete($ENV{'SSLPASS'});
         waitpid($pid, 0);
         return(3, $ext);
      }
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   delete($ENV{'SSLPASS'});

   return($ret, $ext);
}

sub newreq {
   my $self = shift;
   my $opts = { @_ };

   my ($ext, $ret, $cmd, $pid);
   $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';

   $cmd = "$self->{'bin'} req -new";
   $cmd .= " -keyform PEM";
   $cmd .= " -outform PEM";
   $cmd .= " -passin env:SSLPASS";

   $cmd .= " -config $opts->{'config'}";
   $cmd .= " -out $opts->{'outfile'}";
   $cmd .= " -key $opts->{'keyfile'}";
   $cmd .= " -"."$opts->{'digest'}";

   $ENV{'SSLPASS'} = $opts->{'pass'};

   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";


   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);

   foreach(@{$opts->{'dn'}}) {
      if(defined($_)) {
         print $wtfh "$_\n";
      } else {
         print $wtfh ".\n";
      }
   }

   while(<$rdfh>) {
      $ext .= $_;
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   delete($ENV{'SSLPASS'});

   return($ret, $ext);
}

sub newcert {
   my $self = shift;
   my $opts = { @_ };

   my ($ext, $cmd, $ret, $pid, $serial, $r);
   $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';


   $serial = $opts->{'cadir'}."/serial";
   $r = int(rand(9)) + 1;
   $cmd="openssl rand -hex 18 | sed 's/^0/".$r."/' | tr /a-z/ /A-Z/ > ".$serial;
   system($cmd);
   open(IN, "<$serial") || do {
      print STDERR "Can't read serial";
      return(1,"Can't read serial");
   };
   $serial = <IN>;
   chomp($serial);
   close IN;


   $cmd = "$self->{'bin'} req -x509";
   $cmd .= " -keyform PEM";
   $cmd .= " -outform PEM";
   $cmd .= " -passin env:SSLPASS";

   $cmd .= " -config $opts->{'config'}";
   $cmd .= " -out \"$opts->{'outfile'}\"";
   $cmd .= " -key \"$opts->{'keyfile'}\"";
   $cmd .= " -in \"$opts->{'reqfile'}\"";
   $cmd .= " -days $opts->{'days'}";
   $cmd .= " -set_serial \"0x$serial\"";
   $cmd .= " -"."$opts->{'digest'}";

   $ENV{'SSLPASS'} = $opts->{'pass'};

   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>) {
      $ext .= $_;
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   delete($ENV{'SSLPASS'});

   return($ret, $ext);
}

sub newcrl {
   my $self = shift;
   my $opts = { @_ };

   my ($out, $ext, $tmpfile, $cmd, $ret, $pid, $crl);
   $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';

   $tmpfile = HELPERS::mktmp($self->{'tmp'}."/crl");
   $cmd = "$self->{'bin'} ca -gencrl";
   $cmd .= " -passin env:SSLPASS";
   $cmd .= " -config $opts->{'config'}";
   $cmd .= " -crlexts crl_ext";
   $cmd .= " -out $tmpfile";
   $cmd .= " -crldays $opts->{'crldays'}";

   $ENV{'SSLPASS'} = $opts->{ 'pass'};
   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>) {
      $ext .= $_;
      if($_ =~ /unable to load CA private key/) {
         delete($ENV{'SSLPASS'});
         waitpid($pid, 0);
         return(1, $ext);
      } elsif($_ =~ /trying to load CA private key/) {
         delete($ENV{'SSLPASS'});
         waitpid($pid, 0);
         return(2, $ext);
      }
   }
   waitpid($pid, 0);
   $ret = $?>>8;

   delete($ENV{'SSLPASS'});

   return($ret, $ext) if($ret);

   $crl = $self->parsecrl($tmpfile, 1);
   unlink( $tmpfile);

   $opts->{'format'} = 'PEM' if ( !defined( $opts->{ 'format'}));
   if($opts->{'format'} eq 'PEM') {
      $out = $crl->{'PEM'};
   } elsif ($opts->{'format'} eq 'DER') {
      $out = $crl->{'DER'};
   } elsif ($opts->{'format'} eq 'TXT') {
      $out = $crl->{'TXT'};
   } else {
      $out = $crl->{'PEM'};
   }

   unlink( $opts->{'outfile'});
   open(OUT, ">$opts->{'outfile'}") or return;
   print OUT $out;
   close OUT;

   return($ret, $ext);
}

sub fixSerial {
    my ($inSerial) = @_;
    my ($b, $i);
    for ($i = 0; $i < length($inSerial); $i++) {
      $b .= substr($inSerial,$i,1);
      if ($i%2 == 1 && $i != length($inSerial)-1) { $b .= ":"; };
    }
    return ($b);
}

sub parsecrl {
   my ($self, $file, $force) = @_;

   my $tmp   = {};
   my (@lines, $i, $t, $ext, $ret);

   # check if crl is cached
   if($self->{'CACHE'}->{$file} && not $force) {
      return($self->{'CACHE'}->{$file});
   }
   delete($self->{'CACHE'}->{$file});

   open(IN, $file) || do {
      $t = sprintf(_("Can't open CRL '%s': %s"), $file, $!);
      UI->warning($t);
      return;
   };

   # convert crl to PEM, DER and TEXT
   $tmp->{'PEM'} .= $_ while(<IN>);
   ($ret, $tmp->{'TXT'}, $ext) = $self->convdata(
         'cmd'     => 'crl',
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'TEXT'
         );

   if($ret) {
      $t = _("Error converting CRL");
      UI->warning($t, $ext);
      return;
   }

   ($ret, $tmp->{'DER'}, $ext) = $self->convdata(
         'cmd'     => 'crl',
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'DER'
         );

   if($ret) {
      $t = _("Error converting CRL");
      UI->warning($t, $ext);
      return;
   }

   # get "normal infos"
   if ($tmp->{'TXT'}) {
      @lines = split(/\n/, $tmp->{'TXT'});
   } else {
      @lines = ();
   }
   foreach(@lines) {
      if ($_ =~ /Signature Algorithm.*: (\w+)/i) {
         $tmp->{'SIG_ALGORITHM'} = $1;
      } elsif ($_ =~ /Issuer: (.+)/i) {
         $tmp->{'ISSUER'} = $1;
         $tmp->{'ISSUER'} =~ s/,/\//g;
         $tmp->{'ISSUER'} =~ s/\/ /\//g;
         $tmp->{'ISSUER'} =~ s/^\///;
      } elsif ($_ =~ /Last Update.*: (.+)/i) {
         $tmp->{'LAST_UPDATE'} = $1;
      } elsif ($_ =~ /Next Update.*: (.+)/i) {
         $tmp->{'NEXT_UPDATE'} = $1;
      }
   }

   # get revoked certs
   $tmp->{'LIST'} = [];
   for($i = 0;
         ($i < scalar(@lines)) &&
         ($lines[$i] !~ /^[\s\t]*Revoked Certificates:$/i);
       $i++) {
      $self->{'CACHE'}->{$file} = $tmp;
      return($tmp) if ($lines[$i] =~ /No Revoked Certificates/i);
   }
   $i++;

   while($i < @lines) {
      if($lines[$i] =~ /Serial Number.*: (.+)/i) {
         my $t= {};
         $t->{'SERIAL'} = length($1)%2?"0".uc($1):uc($1);
         $t->{'SERIAL'} = fixSerial($t->{'SERIAL'});
         $i++;
         if($lines[$i] =~ /Revocation Date: (.*)/i ) {
            $t->{'DATE'} = $1;
            $i++;
            push(@{$tmp->{'LIST'}}, $t);
         } else {
            $t = sprintf("CRL seems to be corrupt: %s\n", $file);
            UI->warning($t);
            return;
         }

      } else {
         $i++;
      }
   }

   $self->{'CACHE'}->{$file} = $tmp;

   return($tmp);
}


sub parsecert {
   my ($self, $crlfile, $indexfile, $file, $force, $opts) = @_;
   $opts //= {};
   my $lite = $opts->{lite} ? 1 : 0;

   my $tmp   = {};
   my (@lines, $dn, $i, $c, $v, $k, $cmd, $crl, $time, $t, $ext, $ret, $pid, $inserial);

   $time = time();

   $force && delete($self->{'CACHE'}->{$file});

   # Cache check — applies in lite mode too. A cached full parse has
   # everything a lite caller needs (plus extra fields the caller will
   # just ignore). Skipping this for lite mode meant every Open CA
   # would re-run the STATUS code, including _set_expired which
   # rewrites index.txt for every expired cert — touching the file's
   # mtime on every CA open without any user-visible change.
   if($self->{'CACHE'}->{$file}) {
      return($self->{'CACHE'}->{$file});
   }

   open(IN, $file) || do {
      $t = sprintf("Can't open Certificate '%s': %s", $file, $!);
      UI->warning($t);
      return;
   };

   # convert certificate to PEM, DER and TEXT
   $tmp->{'PEM'} .= $_ while(<IN>);
   ($ret, $tmp->{'TEXT'}, $ext) = $self->convdata(
         'cmd'     => 'x509',
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'TEXT'
         );

   if($ret) {
      $t = _("Error converting Certificate");
      UI->warning($t, $ext);
      return;
   }

   unless ($lite) {
      ($ret, $tmp->{'DER'}, $ext) = $self->convdata(
            'cmd'     => 'x509',
            'data'    => $tmp->{'PEM'},
            'inform'  => 'PEM',
            'outform' => 'DER'
            );

      if($ret) {
         $t = _("Error converting Certificate");
         UI->warning($t, $ext);
         return;
      }
   }

   # get "normal infos"
   @lines = split(/\n/, $tmp->{'TEXT'});
   $inserial = 0;
   foreach(@lines) {
      if($_ =~ /Serial Number.*: (.+) /i) {
         # shit, -text shows serial as decimal number :(
         # dirty fix (incompleted) --curly
         $i = sprintf( "%x", $1);
         $tmp->{'SERIAL'} = length($i)%2?"0".uc($i):uc($i);
         $tmp->{'SERIAL'} = fixSerial($tmp->{'SERIAL'});
      } elsif ($_ =~ /Serial Number.*:/i) {
        $inserial = 1;
      } elsif ($inserial && $_ =~ /.* (\S+)/i) {
        $tmp->{'SERIAL'} = uc($1);
        $inserial = 0;
      } elsif ($_ =~ /Signature Algorithm.*: (\w+)/i) {
         $tmp->{'SIG_ALGORITHM'} = $1;
      } elsif ($_ =~ /Issuer: (.+)/i) {
         $tmp->{'ISSUER'} = $1;
         $tmp->{'ISSUER'} =~ s/,/\//g;
         $tmp->{'ISSUER'} =~ s/\/ /\//g;
         $tmp->{'ISSUER'} =~ s/^\///;
      } elsif ($_ =~ /Not Before.*: (.+)/i) {
         $tmp->{'NOTBEFORE'} = $1;
      } elsif ($_ =~ /Not After.*: (.+)/i) {
         $tmp->{'NOTAFTER'} = $1;
      } elsif ($_ =~ /Public Key Algorithm.*: (.+)/i) {
         $tmp->{'PK_ALGORITHM'} = _pretty_pk_algorithm($1);
      } elsif ($_ =~ /Modulus \((\d+) .*\)/i) {
         $tmp->{'KEYSIZE'} = $1;
      } elsif ($_ =~ /Public-Key: \((\d+) .*\)/i) {
         $tmp->{'KEYSIZE'} = $1;
      } elsif ($_ =~ /Subject.*: (.+)/i) {
         $tmp->{'DN'} = $1;
      }
   }
   # parse subject DN
   $dn = HELPERS::parse_dn($tmp->{'DN'});
   foreach(keys(%$dn)) {
      $tmp->{$_} = $dn->{$_};
   }

   # parse issuer DN
   $tmp->{'ISSUERDN'} = HELPERS::parse_dn($tmp->{'ISSUER'});

   # get extensions
   $tmp->{'EXT'} = HELPERS::parse_extensions(\@lines, "cert");

   # Stage 13: skip the five fingerprint shell-outs + the subject
   # extraction when called in `lite` mode (e.g. CERT::read_certlist
   # only needs STATUS to populate the list view). Each cert otherwise
   # costs ~6 openssl process spawns just to render one list row,
   # which is unbearable on CAs with thousands of certs.
   FINGERPRINTS_AND_SUBJECT: {
      last FINGERPRINTS_AND_SUBJECT if $lite;

   # get fingerprint
   $cmd = "$self->{'bin'} x509 -noout -fingerprint -md5 -in $file";
   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>){
      $ext .= $_;
      ($k, $v) = split(/=/);
      $tmp->{'FINGERPRINTMD5'} = $v if($k =~ /MD5 Fingerprint/i);
      chomp($tmp->{'FINGERPRINTMD5'});
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   if($ret) {
      $t = _("Error reading fingerprint from Certificate");
      UI->warning($t, $ext);
   }

   $cmd = "$self->{'bin'} x509 -noout -fingerprint -sha1 -in $file";
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>){
      $ext .= $_;
      ($k, $v) = split(/=/);
      $tmp->{'FINGERPRINTSHA1'} = $v if($k =~ /SHA1 Fingerprint/i);
      chomp($tmp->{'FINGERPRINTSHA1'});
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   if($ret) {
      $t = _("Error reading fingerprint from Certificate");
      UI->warning($t, $ext);
   }

   $cmd = "$self->{'bin'} x509 -noout -fingerprint -sha256 -in $file";
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>){
      $ext .= $_;
      ($k, $v) = split(/=/);
      $tmp->{'FINGERPRINTSHA256'} = $v if($k =~ /SHA256 Fingerprint/i);
      chomp($tmp->{'FINGERPRINTSHA256'});
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   $cmd = "$self->{'bin'} x509 -noout -fingerprint -sha384 -in $file";
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>){
      $ext .= $_;
      ($k, $v) = split(/=/);
      $tmp->{'FINGERPRINTSHA384'} = $v if($k =~ /SHA384 Fingerprint/i);
      chomp($tmp->{'FINGERPRINTSHA384'});
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   $cmd = "$self->{'bin'} x509 -noout -fingerprint -sha512 -in $file";
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>){
      $ext .= $_;
      ($k, $v) = split(/=/);
      $tmp->{'FINGERPRINTSHA512'} = $v if($k =~ /SHA512 Fingerprint/i);
      chomp($tmp->{'FINGERPRINTSHA512'});
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   if($ret) {
      $t = _("Error reading fingerprint from Certificate");
      UI->warning($t, $ext);
   }

   # get subject in openssl format
   $cmd = "$self->{'bin'} x509 -noout -subject -in $file";
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>){
      $ext .= $_;
      # Stage 12 fix: OpenSSL 1.1+ prints "subject=C = US, CN = foo" (no
      # space after "="); 1.0.x and earlier printed "subject= /C=US/...".
      # Accept either form, trim the captured value.
      if ($_ =~ /^subject\s*=\s*(.+?)\s*$/i) {
         $tmp->{'SUBJECT'} = $1;
      }
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   if($ret) {
      $t = _("Error reading subject from Certificate");
      UI->warning($t, $ext);
   }

   }   # end FINGERPRINTS_AND_SUBJECT block

   $tmp->{'EXPDATE'} = _get_date( $tmp->{'NOTAFTER'});

   if(defined($crlfile) && defined($indexfile)) {
      $crl = $self->parsecrl($crlfile, 1);

      defined($crl) || UI->error(_("Can't read CRL"));

      $tmp->{'STATUS'} = _("VALID");

      if($tmp->{'EXPDATE'} < $time) {
         $tmp->{'STATUS'} = _("EXPIRED");
         # keep database up to date
         if($crl->{'ISSUER'} eq $tmp->{'ISSUER'}) {
            _set_expired($tmp->{'SERIAL'}, $indexfile);
         }
      }

      if (defined($tmp->{'SERIAL'})) {
         foreach my $revoked (@{$crl->{'LIST'}}) {
            next if ($tmp->{'SERIAL'} ne $revoked->{'SERIAL'});
            if ($tmp->{'SERIAL'} eq $revoked->{'SERIAL'}) {
               $tmp->{'STATUS'} = _("REVOKED");
            }
         }
      }
   } else {
      $tmp->{'STATUS'} = _("UNDEFINED");
   }

   # Only cache the FULL parse — caching a lite result would mean a
   # later non-lite call would get back the cheap value missing
   # fingerprints/DER/SUBJECT.
   $self->{'CACHE'}->{$file} = $tmp unless $lite;

   return($tmp);
}

sub parsereq {
   my ($self, $config, $file, $force) = @_;

   my $tmp    = {};

   my (@lines, $dn, $i, $c, $v, $k, $cmd, $t, $ext, $ret);

   # check if request is cached
   if($self->{'CACHE'}->{$file} && !$force) {
      return($self->{'CACHE'}->{$file});
   } elsif($force) {
      delete($self->{'CACHE'}->{$file});
   }

   open(IN, $file) || do {
      $t = sprintf(_("Can't open Request file %s: %s"), $file, $!);
      UI->warning($t);
      return;
   };

   # convert request to PEM, DER and TEXT
   $tmp->{'PEM'} .= $_ while(<IN>);

   ($ret, $tmp->{'TEXT'}, $ext) = $self->convdata(
         'cmd'     => 'req',
         'config'  => $config,
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'TEXT'
         );

   if($ret) {
      $t = _("Error converting Request");
      UI->warning($t, $ext);
      return;
   }

   ($ret, $tmp->{'DER'}, $ext) = $self->convdata(
         'cmd'     => 'req',
         'config'  => $config,
         'data'    => $tmp->{'PEM'},
         'inform'  => 'PEM',
         'outform' => 'DER'
         );

   if($ret) {
      $t = _("Error converting Request");
      UI->warning($t, $ext);
      return;
   }

   # get "normal infos"
   @lines = split(/\n/, $tmp->{'TEXT'});
   foreach(@lines) {
      if ($_ =~ /Signature Algorithm.*: (\w+)/i) {
         $tmp->{'SIG_ALGORITHM'} = $1;
      } elsif ($_ =~ /Public Key Algorithm.*: (.+)/i) {
         $tmp->{'PK_ALGORITHM'} = _pretty_pk_algorithm($1);
      } elsif ($_ =~ /Modulus \((\d+) .*\)/i) {
         $tmp->{'KEYSIZE'} = $1;
      } elsif ($_ =~ /Public-Key: \((\d+) .*\)/i) {
         $tmp->{'KEYSIZE'} = $1;
      } elsif ($_ =~ /Subject.*: (.+)/i) {
         $tmp->{'DN'} = $1;
      } elsif ($_ =~ /Version: \d.*/i) {
         $tmp->{'TYPE'} = 'PKCS#10';
      }
   }

   $dn = HELPERS::parse_dn($tmp->{'DN'});
   foreach(keys(%$dn)) {
      $tmp->{$_} = $dn->{$_};
   }

   # get extensions
   $tmp->{'EXT'} = HELPERS::parse_extensions(\@lines, "req");

   $self->{'CACHE'}->{$file} = $tmp;

   return($tmp);
}

sub convdata {
   my $self = shift;
   my $opts = { @_ };
   $ENV{'SUBJECTALTNAMEDNS'}   = 'dummy';

   my ($tmp, $ext, $ret, $file, $pid, $cmd, $cmdout, $cmderr);
   $file = HELPERS::mktmp($self->{'tmp'}."/data");

   $cmd = "$self->{'bin'} $opts->{'cmd'}";
   $cmd .= " -config $opts->{'config'}" if(defined($opts->{'config'}));
   $cmd .= " -inform $opts->{'inform'}";
   $cmd .= " -out \"$file\"";
   if($opts->{'outform'} eq 'TEXT') {
      $cmd .= " -text -noout";
   } else {
      $cmd .= " -outform $opts->{'outform'}";
   }

   ($ret, $tmp, $ext) = _run_with_fixed_input($cmd, $opts->{'data'});

   if($self->{'broken'}) {
       if(($ret != 0 && $opts->{'cmd'} ne 'crl') ||
          ($ret != 0 && $opts->{'outform'} ne 'TEXT' && $opts->{'cmd'} eq 'crl') ||
          ($ret != 1 && $opts->{'outform'} eq 'TEXT' && $opts->{'cmd'} eq 'crl')) {
          unlink($file);
          return($ret, undef, $ext);
       } else {
          $ret = 0;
       }
   } else { # wow, they fixed it :-)
      if($ret != 0) {
         unlink($file);
         return($ret, undef, $ext);
      } else {
         $ret = 0;
      }
   }

   if (-s $file) { # If the file is empty, the payload is in $tmp (via STDOUT of the called process).
      open(IN, $file) || do {
         my $t = sprintf(_("Can't open file %s: %s"), $file, $!);
         UI->warning($t);
         return;
      };
      $tmp .= $_ while(<IN>);
      close(IN);
   }
   unlink($file);

   return($ret, $tmp, $ext);
}

sub convkey {
   my $self = shift;
   my $opts = { @_ };

   my ($tmp, $ext, $pid, $ret);
   my $file = HELPERS::mktmp($self->{'tmp'}."/key");

   my $cmd = "$self->{'bin'}";

   # Stage 13: pick the right openssl subcommand for the key format.
   #
   #   RSA   -> `openssl rsa`  (legacy PKCS#1 PEM, BEGIN RSA PRIVATE KEY)
   #   DSA   -> `openssl dsa`  (legacy PKCS#1-style PEM)
   #   else  -> `openssl pkey` (universal: PKCS#8 / EC / Ed25519 / etc.)
   #
   # Without this fallback, modern OpenSSL 3.0+ keys ended up with
   # $type='UNKNOWN' or 'PKCS8' and no subcommand was appended,
   # producing the malformed `openssl -inform PEM ...` command line
   # which openssl rejected with "Invalid command '-inform'", which
   # the wrapper then mis-reported as "Wrong password given".
   my $type = $opts->{'type'} // '';
   if($type eq "RSA") {
      $cmd .= " rsa";
   } elsif($type eq "DSA") {
      $cmd .= " dsa";
   } else {
      $cmd .= " pkey";
   }

   $cmd .= " -inform $opts->{'inform'}";
   $cmd .= " -outform $opts->{'outform'}";
   $cmd .= " -in \"$opts->{'keyfile'}\"";
   $cmd .= " -out \"$file\"";

   $cmd .= " -passin env:SSLPASS";
   # Stage 13: cipher options (-aes256 + -passout) only apply to PEM
   # output. `openssl pkey -outform DER -aes256 ...` errors with
   # "Cipher options are supported only for PEM output" on modern
   # OpenSSL (the legacy `openssl rsa` silently accepted+ignored the
   # flag, masking the issue). DER output of a private key is always
   # unencrypted at this code path; for encrypted DER export we'd
   # need a separate `openssl pkcs8 -topk8 -outform DER` pipeline.
   my $is_pem_out = (uc($opts->{'outform'} // '') eq 'PEM');
   $cmd .= " -passout env:SSLPASSOUT -aes256"
       if(not $opts->{'nopass'} and $is_pem_out);

   $ENV{'SSLPASS'}    = defined($opts->{'oldpass'}) ? $opts->{'oldpass'} :
                        $opts->{'pass'};
   $ENV{'SSLPASSOUT'} = $opts->{'pass'}
       if(not $opts->{'nopass'} and $is_pem_out);

   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>) {
      $ext .= $_;
      if($_ =~ /unable to load key/) {
         delete($ENV{'SSLPASS'});
         delete($ENV{'SSLPASSOUT'});
         return(1, $ext);
      }
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   delete($ENV{'SSLPASS'});
   delete($ENV{'SSLPASSOUT'});

   return(1, $ext) if($ret);

   open(IN, $file) || return(undef);
   $tmp .= $_ while(<IN>);
   close(IN);

   unlink($file);

   return($tmp);
}

sub genp12 {
   my $self = shift;
   my $opts = { @_ };

   my($cmd, $ext, $ret, $pid);

   $cmd = "$self->{'bin'} pkcs12 -export";
   $cmd .= " -out \"$opts->{'outfile'}\"";
   $cmd .= " -in \"$opts->{'certfile'}\"";
   $cmd .= " -inkey \"$opts->{'keyfile'}\"";
   if(not $opts->{'nopass'}) {
      $cmd .= " -passout env:P12PASS";
   } else {
      $cmd .= " -passout pass:";
   }
   $cmd .= " -passin env:SSLPASS";
   $cmd .= " -certfile $opts->{'cafile'}" if($opts->{'includeca'});
   # Stage 13: drop `-nodes` here. With `-export` (which `genp12` always
   # uses) modern OpenSSL emits:
   #   Warning: output encryption option -nodes ignored with -export
   # because the p12 output's private-key encryption is controlled by
   # `-passout pass:` (empty password = no encryption), not by `-nodes`.
   # The previous code added `-nodes` AND set `-passout pass:` when
   # nopass=1; the latter is sufficient and is already in the command
   # above (see `-passout pass:` block earlier in this sub).
   $cmd .= " -name \"$opts->{'friendly'}\"" if($opts->{'friendly'} ne "");


   $ENV{'P12PASS'} = $opts->{'p12passwd'} if(not $opts->{'nopass'});
   $ENV{'SSLPASS'} = $opts->{'passwd'};
   my($rdfh, $wtfh);
   $ext = "$cmd\n\n";
   $pid = open3($wtfh, $rdfh, $rdfh, $cmd);
   while(<$rdfh>) {
      $ext .= $_;
      if($_ =~ /Error loading private key/) {
         delete($ENV{'SSLPASS'});
         delete($ENV{'P12PASS'});
         return(1, $ext);
      }
   }
   waitpid($pid, 0);
   $ret = $? >> 8;

   delete($ENV{'P12PASS'});
   delete($ENV{'SSLPASS'});

   return($ret, $ext);
}

sub read_index {
   my ($self, $index) = @_;

   my (@lines, @index);

   open(IN, "<$index") || do {
      my $t = sprintf(_("Can't read index %s: %s"), $index, $!);
      UI->warning($t);
      return;
   };
   @lines = <IN>;
   close(IN);
   foreach my $l (@lines) {
      my $tmp = {};
      ($tmp->{'STATUS'},
       $tmp->{'EXPDATE'},
       $tmp->{'REVDATE'},
       $tmp->{'SERIAL'},
       $tmp->{'xxx'},
       $tmp->{'DN'}) = split(/\t/, $l);

      ($tmp->{'REVDATE'}, $tmp->{'REVREASON'}) = split(/,/, $tmp->{'REVDATE'});

      $tmp->{'EXPDATE'} = _get_index_date($tmp->{'EXPDATE'});
      if(defined($tmp->{'REVDATE'}) && ($tmp->{'REVDATE'} ne '')) {
         $tmp->{'REVDATE'} = _get_index_date( $tmp->{'REVDATE'});
      }
      $tmp->{'SERIAL'} = fixSerial($tmp->{'SERIAL'});
      push(@index, $tmp);
   }

   return(@index);
}

sub _set_expired {
   my ($serial, $index) = @_;

   open(IN, "<$index") || do {
      my $t = sprintf(_("Can't read index %s: %s"), $index, $!);
      UI->warning($t);
      return;
   };

   my @lines = <IN>;
   close IN;

   # Stage 13: only rewrite the file if there's actually a V->E
   # transition for this serial. Without this guard, every call to
   # _set_expired (one per already-expired cert during read_certlist)
   # rewrites the entire index.txt with identical bytes, bumping its
   # mtime on every Open CA even though `diff` shows no change.
   my $needs_rewrite = 0;
   foreach my $l (@lines) {
      if ($l =~ /^V\t[^\t]*\t[^\t]*\t\Q$serial\E\t/) {
         $needs_rewrite = 1;
         last;
      }
   }
   return unless $needs_rewrite;

   open(OUT, ">$index") || do {
      my $t = sprintf(_("Can't write index %s: %s"), $index, $!);
      UI->warning($t);
      return;
   };

   foreach my $l (@lines) {
      if($l =~ /\t$serial\t/) {
         $l =~ s/^V/E/;
      }
      print OUT $l;
   }

   close OUT;

   return;
}

sub _get_date {
   my $string = shift;

   $string =~ s/  / /g;

   my @t1 = split(/ /, $string);
   my @t2 = split(/:/, $t1[2]);

   $t1[0] = _get_index($t1[0]);

   my $ret = Time::Local::timelocal($t2[2],$t2[1],$t2[0],$t1[1],$t1[0],$t1[3]);

   return($ret);
}

sub _get_index_date {
   my $string = shift;

   my ($y, $m, $d);

   if(length($string) == 15) {
      $y = substr($string, 0, 4);
      $m = substr($string, 4, 2) - 1;
      $d = substr($string, 6, 2);
   } else {
      $y = substr($string, 0, 2) + 2000;
      $m = substr($string, 2, 2) - 1;
      $d = substr($string, 4, 2);
   }

   my $ret = Time::Local::timelocal(0, 0, 0, $d, $m, $y);

   return($ret);
}

sub _get_index {
   my $m = shift;

   my @a = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);

   for(my $i = 0; $a[$i]; $i++) {
      return $i if($a[$i] eq $m);
   }
}


=over

=item _run_with_fixed_input($cmd, $input)

This function runs C<$cmd> and writes the C<$input> to STDIN of the
new process (all at once).

While the command runs, all of its output to STDOUT and STDERR is
collected.

After the command terminates (closes both STDOUT and STDIN) the
function returns the command's return value as well as everything it
wrote to its STDOUT and STDERR in a list.

=back

=cut

sub _run_with_fixed_input {
   my $cmd = shift;
   my $input = shift;

   my ($wtfh, $rdfh, $erfh, $pid, $sel, $ret, $stdout, $stderr);
   $erfh = Symbol::gensym; # Must not be false, otherwise it is lumped together with rdfh

   # Run the command
   $pid = open3($wtfh, $rdfh, $erfh, $cmd);
   print $wtfh $input, "\n";

   $stdout = '';
   $stderr = '';
   $sel = new IO::Select($rdfh, $erfh);
   while (my @fhs = $sel->can_read()) {
      foreach my $fh (@fhs) {
         if ($fh == $rdfh) { # STDOUT
            my $bytes_read = sysread($fh, my $buf='', 1024);
            if ($bytes_read == -1) {
               warn("Error reading from child's STDOUT: $!\n");
               $sel->remove($fh);
             } elsif ($bytes_read == 0) {
               # print("Child's STDOUT closed.\n");
               $sel->remove($fh);
             } else {
               $stdout .= $buf;
             }
         }
         elsif ($fh == $erfh) { # STDERR
            my $bytes_read = sysread($fh, my $buf='', 1024);
            if ($bytes_read == -1) {
               warn("Error reading from child's STDERR: $!\n");
               $sel->remove($fh);
            } elsif ($bytes_read == 0) {
               # print("Child's STDERR closed.\n");
               $sel->remove($fh);
            } else {
              $stderr .= $buf;
            }
         }
      }
   }

   waitpid($pid, 0);
   $ret = $?>>8;

   return ($ret, $stdout, $stderr)
   }

1
