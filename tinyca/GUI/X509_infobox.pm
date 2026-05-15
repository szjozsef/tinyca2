# Copyright (c) Olaf Gellert <og@pre-secure.de> and
#               Stephan Martin <sm@sm-zone.net>
#
# $Id: X509_infobox.pm,v 1.7 2006/06/28 21:50:42 sm Exp $
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
package GUI::X509_infobox;

use HELPERS;
use GUI::HELPERS;
use GUI::WORDS;

use POSIX;
use I18N qw(_);           # Stage 12: formalised gettext wrapper

my $version = "0.1";
my $true = 1;
my $false = undef;

sub new {
   my $that = shift;
   my $self = {};

   my $class = ref($that) || $that;

   $self->{'init'} = shift;

   bless($self, $class);

   $self;
}


sub display {
  my ($self, $parent, $parsed, $mode, $title) = @_;

  my ($bottombox, $textbox, $lefttable, $righttable, $leftbox, $rightbox,
        @fields, $scrolled);

  $self->{'root'} = $parent;

  if (defined $self->{'child'}) {
    $self->{'child'}->destroy();
    }

  # if title is given create a surrounding frame with the title
  if (defined $title) {
     $self->{'child'}= Gtk3::Frame->new($title);
     $self->{'x509textbox'}= Gtk3::Box->new('vertical', 0);
     $self->{'child'}->add($self->{'x509textbox'});
  }
  # otherwise we create the VBox directly inside the root widget
  else {
     $self->{'child'} = Gtk3::Box->new('vertical', 0);
     $self->{'x509textbox'} = $self->{'child'};
  }

  # and pack it there
  $self->{'root'}->pack_start($self->{'child'}, 1, 1, 0);

   if (($mode eq 'cert') || ($mode eq 'cacert')) {
      # fingerprint in the top of certtextbox
      if(defined($self->{'certfingerprintmd5'})) {
         $self->{'certfingerprintmd5'}->destroy();
      }
      $self->{'certfingerprintmd5'} = GUI::HELPERS::create_label(
            _("Fingerprint (MD5)").": ".$parsed->{'FINGERPRINTMD5'},
            'center', 0, 0);
      $self->{'x509textbox'}->pack_start( $self->{'certfingerprintmd5'},
            0, 0, 0);

      if(defined($self->{'certfingerprintsha1'})) {
         $self->{'certfingerprintsha1'}->destroy();
      }
      $self->{'certfingerprintsha1'} = GUI::HELPERS::create_label(
            _("Fingerprint (SHA1)").": ".$parsed->{'FINGERPRINTSHA1'},
            'center', 0, 0);
      $self->{'x509textbox'}->pack_start($self->{'certfingerprintsha1'},
            0, 0, 0);

      if(defined($self->{'certfingerprintsha256'})) {
         $self->{'certfingerprintsha256'}->destroy();
      }
      $self->{'certfingerprintsha256'} = GUI::HELPERS::create_label(
            _("Fingerprint (SHA256)").": ".$parsed->{'FINGERPRINTSHA256'},
            'center', 0, 0);
      $self->{'x509textbox'}->pack_start($self->{'certfingerprintsha256'},
            0, 0, 0);
   }

   if (($mode eq 'cert') || ($mode eq 'cacert')) {
      $bottombox  = 'certbottombox';
      $textbox    = 'x509textbox';
      $lefttable  = 'certlefttable';
      $leftbox    = 'certleftbox';
      $righttable = 'certrighttable';
      $rightbox   = 'certrightbox';
   }else{
      $bottombox  = 'reqbottombox';
      $textbox    = 'x509textbox';
      $lefttable  = 'reqlefttable';
      $leftbox    = 'reqleftbox';
      $righttable = 'reqrighttable';
      $rightbox   = 'reqrightbox';
   }

   # hbox in the bottom
   if(defined($self->{$bottombox})) {
      $self->{$bottombox}->destroy();
   }
   $self->{$bottombox} = Gtk3::Box->new('horizontal', 0);
   $self->{$bottombox}->set_homogeneous(1);
   $self->{$textbox}->pack_start($self->{$bottombox}, 1, 1, 5);

   # Stage 13: layout mode.
   #   'cacert' — the CA tab; this panel IS the whole tab, so it must
   #     fill the available vertical space. Use vexpand+expand=1/fill=1
   #     packing so the data area stretches with the window.
   #   'cert' / 'req' — the bottom panel of a list+info layout; the
   #     panel's natural height drives how tall it is, list above
   #     gets the rest. Use natural-size packing with valign='start'
   #     so the shorter column doesn't leave empty rows below its
   #     last data row (HBox forces equal column heights — without
   #     valign='start' on each column, the shorter side's SW would
   #     stretch to match the taller column and show empty space inside).
   my $fill_tab = ($mode eq 'cacert');
   # Stage 13: per-row pixel budget. Adwaita on Gtk3.24 lays out
   # CellRendererText rows at ~28-30 px (default font 10pt + 4-6 px
   # vertical padding). 26 was too tight — the Certificates tab's
   # right column has 8 fields and would show a vertical scrollbar
   # to reveal "Type". Bump to 30 with a small safety pad to ensure
   # all rows are visible without needing to scroll.
   my $row_h    = 30;
   my $row_pad  = 10;
   my ($left_rows, $right_rows);

   # vbox in the bottom/left
   if(defined($self->{$lefttable})) {
      $self->{$lefttable}->destroy();
   }
   @fields = qw( CN EMAIL O OU L ST C);
   $self->{$lefttable} = _create_detail_table(\@fields, $parsed);

   $left_rows = $self->{$lefttable}->get_model->iter_n_children(undef);
   $left_rows = 1 if $left_rows < 1;   # never request 0px tall
   $self->{$lefttable}->set_size_request(-1, $left_rows * $row_h + $row_pad);
   $self->{$lefttable}->set_vexpand($fill_tab ? 1 : 0);

   # the only widget i know to set shadow type :-(
   $scrolled = Gtk3::ScrolledWindow->new();
   $scrolled->set_shadow_type('etched-in');
   $scrolled->set_policy('never', 'automatic');
   $scrolled->set_propagate_natural_height(1);

   $self->{$leftbox} = Gtk3::Box->new('vertical', 0);
   $self->{$leftbox}->set_valign('start') unless $fill_tab;
   $self->{$bottombox}->pack_start($self->{$leftbox}, 1, 1, 0);

   if ($fill_tab) {
      $self->{$leftbox}->pack_start($scrolled, 1, 1, 0);
   } else {
      $self->{$leftbox}->pack_start($scrolled, 0, 0, 0);
   }
   $scrolled->add($self->{$lefttable});

   # vbox in the bottom/right
   if(defined($self->{$righttable})) {
      $self->{$righttable}->destroy();
   }
   if ($mode eq "cacert") {
     @fields = qw(SERIAL NOTBEFORE NOTAFTER KEYSIZE PK_ALGORITHM SIG_ALGORITHM
        TYPE);
   } else {
     @fields = qw(STATUS SERIAL NOTBEFORE NOTAFTER KEYSIZE PK_ALGORITHM
        SIG_ALGORITHM TYPE);
   }

   $self->{$righttable} = _create_detail_table(\@fields, $parsed);

   $right_rows = $self->{$righttable}->get_model->iter_n_children(undef);
   $right_rows = 1 if $right_rows < 1;
   $self->{$righttable}->set_size_request(-1, $right_rows * $row_h + $row_pad);
   $self->{$righttable}->set_vexpand($fill_tab ? 1 : 0);

   $scrolled = Gtk3::ScrolledWindow->new();
   $scrolled->set_shadow_type('etched-in');
   $scrolled->set_policy('never', 'automatic');
   $scrolled->set_propagate_natural_height(1);

   $self->{$rightbox} = Gtk3::Box->new('vertical', 0);
   $self->{$rightbox}->set_valign('start') unless $fill_tab;
   $self->{$bottombox}->pack_start($self->{$rightbox}, 1, 1, 0);

   if ($fill_tab) {
      $self->{$rightbox}->pack_start($scrolled, 1, 1, 0);
   } else {
      $self->{$rightbox}->pack_start($scrolled, 0, 0, 0);
   }
   $scrolled->add($self->{$righttable});

   $self->{$textbox}->show_all();

   $parent->show_all();
}

sub hide {
  my $self = shift;

  if (defined $self->{'child'}) {
    $self->{'child'}->destroy();
    undef $self->{'child'};
    }
}

#
# create standard table with details (cert/req)
#
sub _create_detail_table {
   my ($fields, $parsed) = @_;

   my ($list, $store, $words, $iter, $column, $renderer);

   $words = GUI::WORDS->new();

   $store = Gtk3::ListStore->new('Glib::String', 'Glib::String');

   # Stage 13: populate the store BEFORE attaching it to a TreeView.
   # The Gtk3 binding on Debian 12 mishandles row-inserted signals for
   # rows added after attachment, AND the parent ScrolledWindow has
   # `set_policy('never','never')` so the TreeView's height-request is
   # baked in at construction time (empty model => 0 height => fields
   # appear missing). Pre-populating fixes both.
   foreach my $f (@{$fields}) {
      if(defined($parsed->{$f})){
         if(ref($parsed->{$f})) {
            foreach(@{$parsed->{$f}}) {
               $iter = $store->append();
               $store->set($iter, 0 => $words->{$f}, 1 => $_);
            }
         }else{
            $iter = $store->append();
            $store->set($iter, 0 => $words->{$f}, 1 => $parsed->{$f});
         }
      }
   }

   $list  = Gtk3::TreeView->new_with_model($store);
   $list->set_headers_visible(0);
   $list->get_selection->set_mode('none');

   $renderer = Gtk3::CellRendererText->new();
   $column = Gtk3::TreeViewColumn->new_with_attributes(
         '', $renderer, 'text' => 0);
   $list->append_column($column);

   $renderer = Gtk3::CellRendererText->new();
   $column = Gtk3::TreeViewColumn->new_with_attributes(
         '', $renderer, 'text' => 1);
   $list->append_column($column);

   return($list);
}


1;


__END__

=head1 NAME

GUI::X509_infobox - show X.509 certificates and requests in a Gtk3::VBox

=head1 SYNOPSIS

    use X509_infobox;

    $infobox=X509_infobox->new();
    $infobox->update($parent,$parsed,$mode,$title);
    $infobox->update($parent,$parsed,$mode);
    $infobox->hide();

=head1 DESCRIPTION

This displays the information of an X.509v3 certificate or
certification request (CSR) inside a given Gtk3::VBox.

Creation of an X509_infobox is done by calling B<new()>,
no arguments are required.

The infobox is shown when inserted into an already
existing Gtk3::VBox using the method B<update()>. Arguments
to update are:

=over 1

=item $parent:

the existing Gtk3::VBox inside which the info will be
displayed.

=item $parsed:

a structure returned by OpenSSL::parsecert() or OpenSSL::parsecrl()
containing the required information.

=item $mode:

what type of information is to be displayed. Valid modes
are 'req' (certification request), 'cert' (certificate), 'key' or 'cacert'
(same as certificate but without displaying the validity information
of the cert because this cannot be decided on from the view of the
actual CA).

=item $title:

if specified, a surrounding frame with the given title
is drawn.

=back

An existing infobox is destroyed by calling B<hide()>.

=cut
are 'req' (certification request), 'cert' (certific