# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: REQ.pm,v 1.7 2006/06/28 21:50:42 sm Exp $
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

package REQ;

use POSIX;
use UI;
use I18N qw(_);

sub new {
   my $that = shift;
   my $class = ref($that) || $that;

   my $self = {};

   $self->{'OpenSSL'} = shift;

   bless($self, $class);
}

#
# check if all data for creating a new request is available
#
sub get_req_create {
   my ($self, $main, $opts, $box) = @_;

   $box->destroy() if(defined($box));

   my ($name, $action, $parsed, $reqfile, $keyfile, $ca, $t);

   $ca   = $main->{'CA'}->{'actca'};

   if(!(defined($opts)) || !(ref($opts))) {
      if(defined($opts) && $opts eq "signserver") {
         $opts = {};
         $opts->{'sign'} = 1;
         $opts->{'type'} = "server";
#         $opts->{'digest'} = $main->{'CA'}->$ca->{'server_ca'}->{'default_md'};
      } elsif(defined($opts) && $opts eq "signclient") {
         $opts = {};
         $opts->{'sign'} = 1;
         $opts->{'type'} = "client";
#         $opts->{'digest'} = $ca->{'opts'}->{'client_ca'}->{'default_md'};
      } elsif (defined($opts)) {
         $t = sprintf(_("Strange value for 'opts': %s"), $opts);
         UI->error($t);
      }
      $opts->{'bits'}   = 4096;
      $opts->{'digest'} = 'sha256';
#      $opts->{'digest'} = $ca->{$opts->{'type'}.'_ca'}->{'default_md'};
      $opts->{'algo'}   = 'rsa';
      if(defined($opts) && $opts eq "sign") {
         $opts->{'sign'} = 1;
      }

      $parsed = $main->{'CERT'}->parse_cert($main, 'CA');

      defined($parsed) ||
         UI->error(_("Can't read CA certificate"));

      # set defaults
      if(defined $parsed->{'C'}) {
         $opts->{'C'} = $parsed->{'C'};
      }
      if(defined $parsed->{'ST'}) {
         $opts->{'ST'} = $parsed->{'ST'};
      }
      if(defined $parsed->{'L'}) {
         $opts->{'L'} = $parsed->{'L'};
      }
      if(defined $parsed->{'O'}) {
         $opts->{'O'} = $parsed->{'O'};
      }
      my $cc = 0;
      foreach my $ou (@{$parsed->{'OU'}}) {
         $opts->{'OU'}->[$cc++] = $ou;
      }

      $main->show_req_dialog($opts);
      return;
   }

   if((not defined($opts->{'CN'})) ||
      ($opts->{'CN'} eq "") ||
      (not defined($opts->{'passwd'})) ||
      ($opts->{'passwd'} eq "")) {
      $main->show_req_dialog($opts);
      UI->warning(
            _("Please specify at least Common Name ")
            ._("and Password"));
      return;
   }

   if((not defined($opts->{'passwd2'})) ||
       $opts->{'passwd'} ne $opts->{'passwd2'}) {
      $main->show_req_dialog($opts);
      UI->warning(_("Passwords don't match"));
      return;
   }

   $opts->{'C'} = uc($opts->{'C'});

   if((defined $opts->{'C'}) &&
      ($opts->{'C'} ne "") &&
      (length($opts->{'C'}) != 2)) {
      $main->show_req_dialog($opts);
      UI->warning(
            _("Country must be exact 2 letter code"));
      return;
   }

   $name = HELPERS::gen_name($opts);

   $opts->{'reqname'} = HELPERS::enc_base64($name);

   $reqfile = $main->{'CA'}->{$ca}->{'dir'}."/req/".$opts->{'reqname'}.".pem";
   $keyfile = $main->{'CA'}->{$ca}->{'dir'}."/keys/".$opts->{'reqname'}.".pem";

   if(-s $reqfile || -s $keyfile) {
      $main->show_req_overwrite_warning($opts);
      return;
   }

   $self->create_req($main, $opts);

   return;
}

#
# create new request and key
#
sub create_req {
   my ($self, $main, $opts) = @_;

   my($reqfile, $keyfile, $ca, $ret, $ext, $cadir);

   UI->cursor($main, 1);

   $ca    = $main->{'CA'}->{'actca'};
   $cadir = $main->{'CA'}->{$ca}->{'dir'};

   $reqfile = $cadir."/req/".$opts->{'reqname'}.".pem";
   $keyfile = $cadir."/keys/".$opts->{'reqname'}.".pem";

   ($ret, $ext) = $self->{'OpenSSL'}->newkey(
         'algo'    => $opts->{'algo'},
         'bits'    => $opts->{'bits'},
         'outfile' => $keyfile,
         'pass'    => $opts->{'passwd'}
         );

   if (not -s $keyfile || $ret) {
      unlink($keyfile);
      UI->cursor($main, 0);
      UI->warning(_("Generating key failed"), $ext);
      return;
   }

   my @dn = ( $opts->{'C'}, $opts->{'ST'}, $opts->{'L'}, $opts->{'O'} );
   if(ref($opts->{'OU'})) {
      foreach my $ou (@{$opts->{'OU'}}) {
        push(@dn,$ou);
      }
   } else {
      push(@dn, $opts->{'OU'});
   }
   @dn = (@dn, $opts->{'CN'}, $opts->{'EMAIL'}, '', '');
   ($ret, $ext) = $self->{'OpenSSL'}->newreq(
         'config'   => $main->{'CA'}->{$ca}->{'cnf'},
         'outfile'  => $reqfile,
         'keyfile'  => $keyfile,
         'digest'   => $opts->{'digest'},
         'pass'     => $opts->{'passwd'},
         'dn'       => \@dn,
         );

   if (not -s $reqfile || $ret) {
      unlink($keyfile);
      unlink($reqfile);
      UI->cursor($main, 0);
      UI->warning(_("Generating Request failed"), $ext);
      return;
   }

   my $parsed = $self->parse_req($main, $opts->{'reqname'}, 1);

   $main->{'reqbrowser'}->update($cadir."/req",
                                 $cadir."/crl/crl.pem",
                                 $cadir."/index.txt",
                                 0);

   $main->{'keybrowser'}->update($cadir."/keys",
                                 $cadir."/crl/crl.pem",
                                 $cadir."/index.txt",
                                 0);

   UI->cursor($main, 0);

   if($opts->{'sign'}) {
      $opts->{'reqfile'} = $reqfile;
      $opts->{'passwd'}  = undef; # to sign request, ca-password is needed
      $self->get_sign_req($main, $opts);
   }

   return;
}

#
# get name of requestfile to delete
#
sub get_del_req {
   my ($self, $main) = @_;

   my($reqname, $req, $reqfile, $row, $ind, $ca, $cadir);

   $ca    = $main->{'reqbrowser'}->selection_caname();
   $cadir = $main->{'reqbrowser'}->selection_cadir();

   if(not(defined($reqfile))) {
      $req = $main->{'reqbrowser'}->selection_dn();


      if(not defined($req)) {
         UI->info(_("Please select a Request first"));
         return;
      }

      $reqname = HELPERS::enc_base64($req);
      $reqfile = $cadir."/req/".$reqname.".pem";

   }

   if(not -s $reqfile) {
      UI->warning(_("Request file not found"));
      return;
   }

   $main->show_del_confirm($reqfile, 'req');

   return;
}

#
# now really delete the requestfile
#
sub del_req {
   my ($self, $main, $file) = @_;

   my ($ca, $cadir);

   UI->cursor($main, 1);

   unlink($file);

   $ca    = $main->{'reqbrowser'}->selection_caname();
   $cadir = $main->{'reqbrowser'}->selection_cadir();

   $main->{'reqbrowser'}->update($cadir."/req",
                                 $cadir."/crl/crl.pem",
                                 $cadir."/index.txt",
                                 0);

   UI->cursor($main, 0);

   return;
}

sub read_reqlist {
   my ($self, $reqdir, $crlfile, $indexfile, $force, $main) = @_;

   my ($f, $modt, $d, $reqlist, $c, $p, $t);

   UI->cursor($main, 1);

   $reqlist = [];

   $modt = (stat($reqdir))[9];

   # Stage 13: cache check matches CERT.pm/read_certlist (which already
   # honoured the $force flag). Two changes vs the original:
   #   1. Bypass the cache when $force is set — callers like import_req,
   #      del_req and revoke chains pass force=0 today, but the flag is
   #      still useful for explicit refreshes.
   #   2. Use `>` instead of `>=`. time() is 1-second resolution and the
   #      directory mtime is also second-granular: when a new request
   #      file is written in the same wall-clock second as the previous
   #      read, lastread == modt and the old `>=` returned cached data,
   #      leaving the in-memory reqlist out of sync with disk. The
   #      observed failure was a "would overwrite existing certificate"
   #      false alarm when signing a freshly-imported request — the
   #      stale reqlist made selection_dn() return the previous (now-
   #      revoked) request's DN, whose cert file still existed on disk.
   if(defined($self->{'lastread'}) &&
      ($self->{'lastread'} > $modt) &&
      not $force) {
      UI->cursor($main, 0);
      return(0);
   }

   opendir(DIR, $reqdir) || do {
      UI->cursor($main, 0);
      UI->warning(_("Can't open Request directory"));
      return(0);
   };

   while($f = readdir(DIR)) {
      next if $f =~ /^\./;
      $c++;
   }
   rewinddir(DIR);

   $main->{'barbox'}->pack_start($main->{'progress'}, 0, 0, 0);
   $main->{'progress'}->show();

   # Stage 13: batch the GUI updates and drop the 25 ms per-request
   # `select(...)` sleep. The sleep added up to seconds per CA on
   # large request directories, and the Gtk3 introspected binding's
   # per-call overhead on UI->status / set_fraction / UI->yield is
   # already heavy enough that one update per cert is wasteful.
   my $UPDATE_EVERY = 25;
   my $idx = 0;
   while($f = readdir(DIR)) {
      next if $f =~ /^\./;
      $f =~ s/\.pem//;
      $d = HELPERS::dec_base64($f);
      next if not defined($d);
      next if $d eq "";
      push(@{$reqlist}, $d);

      if(defined($main) && ($idx % $UPDATE_EVERY == 0)) {
         $p = ($idx / $c) * 100;
         $t = sprintf(_("   Read Request: %s"), $d);
         UI->status($main, $t);
         if($p/100 <= 1) {
            $main->{'progress'}->set_fraction($p/100);
            UI->yield;
         }
      }
      $idx++;
   }
   @{$reqlist} = sort(@{$reqlist});
   closedir(DIR);

   delete($self->{'reqlist'});
   $self->{'reqlist'} = $reqlist;

   $self->{'lastread'} = time();

   if(defined($main)) {
      $main->{'progress'}->set_fraction(0);
      $main->{'barbox'}->remove($main->{'progress'});
      UI->cursor($main, 0);
      # Stage 13: clear the per-file "Read Request: <dn>" status that
      # the loop above sets every 25 iterations. Without this, the
      # status bar keeps showing the last enumerated request long after
      # enumeration is done, even if the user has selected a different
      # request (confusing on small request lists where only the first
      # entry triggers a status update).
      my $ca = $main->{'CA'} && $main->{'CA'}->{'actca'};
      UI->status($main, defined($ca)
            ? sprintf(_("  Actual CA: %s - Requests"), $ca)
            : '');
   }

   return(1);  # got new list
}

#
# get name of request to sign
#
sub get_sign_req {
   my ($self, $main, $opts, $box) = @_;

   my($time, $parsed, $ca, $cadir, $ext, $ret);

   $box->destroy() if(defined($box));

   $time  = time();
   $ca    = $main->{'reqbrowser'}->selection_caname();
   $cadir = $main->{'reqbrowser'}->selection_cadir();

   if(not(defined($opts->{'reqfile'}))) {
      $opts->{'req'} = $main->{'reqbrowser'}->selection_dn();

      if(not defined($opts->{'req'})) {
         UI->info(_("Please select a Request first"));
         return;
      }

      $opts->{'reqname'} = HELPERS::enc_base64($opts->{'req'});
      $opts->{'reqfile'} = $cadir."/req/".$opts->{'reqname'}.".pem";
   }

   if(not -s $opts->{'reqfile'}) {
         UI->warning(_("Request file not found"));
         return;
   }

   if((-s $cadir."/certs/".$opts->{'reqname'}.".pem") &&
      (!(defined($opts->{'overwrite'})) || ($opts->{'overwrite'} ne 'true'))) {
      $main->show_cert_overwrite_confirm($opts);
      return;
   }

   $parsed = $main->{'CERT'}->parse_cert($main, 'CA');

   defined($parsed) ||
      UI->error(_("Can't read CA certificate"));

   if(!defined($opts->{'passwd'})) {
      $opts->{'days'} =
         $main->{'TCONFIG'}->{$opts->{'type'}."_ca"}->{'default_days'};

      if($opts->{'days'} > (($parsed->{'EXPDATE'}/86400) - ($time/86400))) {
         $opts->{'days'} = int(($parsed->{'EXPDATE'}/86400) - ($time/86400));
      }

      $main->show_req_sign_dialog($opts);
      return;
   }

   if((($time + ($opts->{'days'} * 86400)) > $parsed->{'EXPDATE'}) &&
      (!(defined($opts->{'ignoredate'})) ||
       $opts->{'ignoredate'} ne 'true')){
      $main->show_req_date_warning($opts);
      return;
   }

   # try to find message digest used for the request
   $parsed = undef;
   $parsed = $self->parse_req($main, $opts->{'reqname'}, 1);
   defined($parsed) ||
      UI->error(_("Can't read Request file"));

   # Stage 24: map the parsed SIG_ALGORITHM to a digest name that
   # `openssl ca -md ...` accepts. Substring matching covers all
   # the forms openssl prints for the algorithms tinyca supports:
   #   RSA   : "sha256WithRSAEncryption" / "sha384WithRSAEncryption" / ...
   #   DSA   : "dsa_with_SHA256" / "dsaWithSHA1" / ...
   #   ECDSA : "ecdsa-with-SHA256" / "ecdsa-with-SHA384" / ...
   #   EdDSA : "ED25519" / "ED448"                            <- no digest
   #
   # Edwards-curve algorithms have a built-in hash (Ed25519 uses SHA-512,
   # Ed448 uses SHAKE-256); `openssl ca -md ED25519` errors with
   # "inner_evp_generic_fetch: unsupported". For those, set digest to 0
   # so OpenSSL::signreq omits the `-md` flag entirely and openssl picks
   # its built-in hash.
   if(defined($parsed->{'SIG_ALGORITHM'})) {
      my $sig = lc($parsed->{'SIG_ALGORITHM'});
      if    ($sig =~ /sha512/)          { $opts->{'digest'} = 'sha512';    }
      elsif ($sig =~ /sha384/)          { $opts->{'digest'} = 'sha384';    }
      elsif ($sig =~ /sha256/)          { $opts->{'digest'} = 'sha256';    }
      elsif ($sig =~ /sha224/)          { $opts->{'digest'} = 'sha256';    }
      elsif ($sig =~ /sha1|md[245]/)    { $opts->{'digest'} = 'sha256';    }
      elsif ($sig =~ /ripemd160/)       { $opts->{'digest'} = 'ripemd160'; }
      elsif ($sig =~ /mdc2/)            { $opts->{'digest'} = 'mdc2';      }
      elsif ($sig =~ /ed25519|ed448/)   { $opts->{'digest'} = 0;           }
      else                              { $opts->{'digest'} = 0;           }
   } else {
      $opts->{'digest'} = 0;
   }

   ($ret, $ext) = $self->sign_req($main, $opts);

   return($ret, $ext);
}

#
# now really sign the request
#
sub sign_req {
   my ($self, $main, $opts) = @_;

   my($serial, $certout, $certfile, $certfile2, $ca, $cadir, $ret, $t, $ext, $r, $cmd);

   UI->cursor($main, 1);

   $ca    = $main->{'reqbrowser'}->selection_caname();
   $cadir = $main->{'reqbrowser'}->selection_cadir();

   $serial = $cadir."/serial";
   $r = int(rand(9)) + 1;
   $cmd="openssl rand -hex 18 | sed 's/^0/".$r."/' | tr /a-z/ /A-Z/ > ".$serial;
   system($cmd);
   open(IN, "<$serial") || do {
      UI->cursor($main, 0);
      UI->warning(_("Can't read serial"));
      return;
   };
   $serial = <IN>;
   chomp($serial);
   close IN;

   if(not defined($opts->{'nsSslServerName'})) {
      $opts->{'nsSslServerName'} = 'none';
   }
   if(not defined($opts->{'nsRevocationUrl'})) {
      $opts->{'nsRevocationUrl'} = 'none';
   }
   if(not defined($opts->{'nsRenewalUrl'})) {
      $opts->{'nsRenewalUrl'} = 'none';
   }
   if(not defined($opts->{'subjectAltName'})) {
      $opts->{'subjectAltName'}     = 'none';
      $opts->{'subjectAltNameType'} = 'none';
   } else {
       $opts->{'subjectAltNameType'} =
          $main->{TCONFIG}->{$opts->{'type'}.'_cert'}->{'subjectAltNameType'};
   }
   if(not defined($opts->{'extendedKeyUsage'})) {
      $opts->{'extendedKeyUsage'}     = 'none';
      $opts->{'extendedKeyUsageType'} = 'none';
   } else {
      $opts->{'extendedKeyUsageType'} =
         $main->{TCONFIG}->{$opts->{'type'}.'_cert'}->{'extendedKeyUsageType'};
   }

   if(defined($opts->{'mode'}) && $opts->{'mode'} eq "sub") {
      ($ret, $ext) = $self->{'OpenSSL'}->signreq(
            'mode'                 => $opts->{'mode'},
            'config'               => $main->{'CA'}->{$ca}->{'cnf'},
            'reqfile'              => $opts->{'reqfile'},
            'keyfile'              => $opts->{'keyfile'},
            'cacertfile'           => $opts->{'cacertfile'},
            'outdir'               => $opts->{'outdir'},
            'days'                 => $opts->{'days'},
            'parentpw'             => $opts->{'parentpw'},
            'caname'               => "ca_ca",
            'revocationurl'        => $opts->{'nsRevocationUrl'},
            'renewalurl'           => $opts->{'nsRenewalUrl'},
            'subjaltname'          => $opts->{'subjectAltName'},
            'subjaltnametype'      => $opts->{'subjectAltNameType'},
            'extendedkeyusage'     => $opts->{'extendedKeyUsage'},
            'extendedkeyusagetype' => $opts->{'extendedKeyUsageType'},
            'noemaildn'            => $opts->{'noemaildn'},
            'digest'               => $opts->{'digest'}
            );
   } else {
      ($ret, $ext) = $self->{'OpenSSL'}->signreq(
            'config'               => $main->{'CA'}->{$ca}->{'cnf'},
            'reqfile'              => $opts->{'reqfile'},
            'days'                 => $opts->{'days'},
            'pass'                 => $opts->{'passwd'},
            'caname'               => $opts->{'type'}."_ca",
            'sslservername'        => $opts->{'nsSslServerName'},
            'revocationurl'        => $opts->{'nsRevocationUrl'},
            'renewalurl'           => $opts->{'nsRenewalUrl'},
            'subjaltname'          => $opts->{'subjectAltName'},
            'subjaltnametype'      => $opts->{'subjectAltNameType'},
            'extendedkeyusage'     => $opts->{'extendedKeyUsage'},
            'extendedkeyusagetype' => $opts->{'extendedKeyUsageType'},
            'noemaildn'            => $opts->{'noemaildn'},
            'digest'               => $opts->{'digest'}
            );
   }

   UI->cursor($main, 0);

   if($ret eq 1) {
      $t = _("Wrong CA password given\nSigning of the Request failed");
      UI->warning($t, $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   } elsif($ret eq 2) {
      $t = _("CA Key not found\nSigning of the Request failed");
      UI->warning($t, $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   } elsif($ret eq 3) {
      $t = _("Certificate already existing\nSigning of the Request failed");
      UI->warning($t, $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   } elsif($ret eq 4) {
      $t = _("Invalid IP Address given\nSigning of the Request failed");
      UI->warning($t, $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   } elsif($ret) {
      UI->warning(
            _("Signing of the Request failed"), $ext);
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return($ret, $ext);
   }

   if(defined($opts->{'mode'}) && $opts->{'mode'} eq "sub") {
      $certout  = $cadir."/newcerts/".$serial.".pem";
      $certfile = $opts->{'outfile'};
      $certfile2 = $cadir."/certs/".$opts->{'reqname'}.".pem";
   } else {
      $certout  = $cadir."/newcerts/".$serial.".pem";
      $certfile = $cadir."/certs/".$opts->{'reqname'}.".pem";
   }

   if (not -s $certout) {
         UI->warning(
               _("Signing of the Request failed"), $ext);
         delete($opts->{$_}) foreach(keys(%$opts));
         $opts = undef;
         return;
   }

   open(IN, "<$certout") || do {
      UI->warning(_("Can't read Certificate file"));
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   };
   open(OUT, ">$certfile") || do {
      UI->warning(_("Can't write Certificate file"));
      delete($opts->{$_}) foreach(keys(%$opts));
      $opts = undef;
      return;
   };
   print OUT while(<IN>);

   if(defined($opts->{'mode'}) && $opts->{'mode'} eq "sub") {
      close OUT;
      open(OUT, ">$certfile2") || do {
         UI->warning(_("Can't write Certificate file"));
         delete($opts->{$_}) foreach(keys(%$opts));
         $opts = undef;
         return;
      };
      seek(IN, 0, 0);
      print OUT while(<IN>);
   }

   close IN; close OUT;

   UI->info(
         _("Request signed succesfully.\nCertificate created"), $ext);

   UI->cursor($main, 1);

   $main->{'CERT'}->reread_cert($main,
         HELPERS::dec_base64($opts->{'reqname'}));

   $main->{'certbrowser'}->update($cadir."/certs",
                                  $cadir."/crl/crl.pem",
                                  $cadir."/index.txt",
                                  0);

   delete($opts->{$_}) foreach(keys(%$opts));
   $opts = undef;

   UI->cursor($main, 0);

   return($ret, $ext);
}

#
# get informations/verifications to import request from file
#
sub get_import_req {
   my ($self, $main, $opts, $box) = @_;

   my ($ret, $ext, $der);

   $box->destroy() if(defined($box));

   my($ca, $parsed, $file, $format);

   $ca = $main->{'CA'}->{'actca'};

   if(not defined($opts)) {
      $main->show_req_import_dialog();
      return;
   }

   if(not defined($opts->{'infile'})) {
      $main->show_req_import_dialog();
      UI->warning(_("Please select a Request file first"));
      return;
   }
   if(not -s $opts->{'infile'}) {
      $main->show_req_import_dialog();
      UI->warning(
            _("Can't find Request file: ").$opts->{'infile'});
      return;
   }

   open(IN, "<$opts->{'infile'}") || do {
      UI->warning(
            _("Can't read Request file:").$opts->{'infile'});
      return;
   };

   $opts->{'in'} .= $_ while(<IN>);

   if($opts->{'in'} =~ /-BEGIN[\s\w]+CERTIFICATE REQUEST-/i) {
      $format = "PEM";
      $file = $opts->{'infile'};
   } else {
      $format = "DER";
   }
   close(IN);

   if($format eq "DER") {
      ($ret, $opts->{'in'}, $ext) = $self->{'OpenSSL'}->convdata(
            'cmd'     => 'req',
            'data'    => $opts->{'in'},
            'inform'  => 'DER',
            'outform' => 'PEM'
            );

      if($ret) {
         UI->warning(
               _("Error converting Request"), $ext);
         return;
      }

      $opts->{'tmpfile'} =
         HELPERS::mktmp($self->{'OpenSSL'}->{'tmp'}."/import");

      open(TMP, ">$opts->{'tmpfile'}") || do {
         UI->warning( _("Can't create temporary file: %s: %s"),
               $opts->{'tmpfile'}, $!);
         return;
      };
      print TMP $opts->{'in'};
      close(TMP);
      $file = $opts->{'tmpfile'};
   }

   $parsed = $self->{'OpenSSL'}->parsereq(
                        $main->{'CA'}->{$ca}->{'cnf'},
                        $file);

   if(not defined($parsed)) {
      unlink($opts->{'tmpfile'});
      UI->warning(_("Parsing Request failed"));
      return;
   }

   $main->show_import_verification("req", $opts, $parsed);
   return;
}

#
# import request
#
sub import_req {
   my ($self, $main, $opts, $parsed, $box) = @_;

   my ($ca, $cadir);

   $box->destroy() if(defined($box));

   UI->cursor($main, 1);

   $ca    = $main->{'reqbrowser'}->selection_caname();
   $cadir = $main->{'reqbrowser'}->selection_cadir();

   $opts->{'name'} = HELPERS::gen_name($parsed);

   $opts->{'reqname'} = HELPERS::enc_base64($opts->{'name'});

   $opts->{'reqfile'} = $cadir."/req/".$opts->{'reqname'}.".pem";

   open(OUT, ">$opts->{'reqfile'}") || do {
      unlink($opts->{'tmpfile'});
      UI->cursor($main, 0);
      UI->warning(_("Can't open output file: %s: %s"),
            $opts->{'reqfile'}, $!);
      return;
   };
   print OUT $opts->{'in'};
   close OUT;

   $main->{'reqbrowser'}->update($cadir."/req",
                                 $cadir."/crl/crl.pem",
                                 $cadir."/index.txt",
                                 0);

   UI->cursor($main, 0);

   return;
}

sub parse_req {
   my ($self, $main, $name, $force) = @_;

   my ($parsed, $ca, $reqfile, $req);

   UI->cursor($main, 1);

   $ca = $main->{'CA'}->{'actca'};

   $reqfile = $main->{'CA'}->{$ca}->{'dir'}."/req/".$name.".pem";

   $parsed = $self->{'OpenSSL'}->parsereq($main->{'CA'}->{$ca}->{'cnf'},
         $reqfile, $force);

   UI->cursor($main, 0);

   return($parsed);
}

1
