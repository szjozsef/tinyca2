# Copyright (c) Olaf Gellert <og@pre-secure.de> and
#               Stephan Martin <sm@sm-zone.net>
#
# $Id: X509_browser.pm,v 1.6 2006/06/28 21:50:42 sm Exp $
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
package GUI::X509_browser;

use HELPERS;
use GUI::HELPERS;
use GUI::X509_infobox;

use POSIX;
use I18N qw(_);           # Stage 12: formalised gettext wrapper

my $tmpdefault="/tmp";

my $version = "0.1";
my $true = 1;
my $false = undef;

sub new {
   my $that = shift;
   my $self = {};

   $self->{'main'} = shift;
   my $mode = shift;

   my $class = ref($that) || $that;


   if ((defined $mode) &&
         (($mode eq 'cert') || ($mode eq 'req') || ($mode eq 'key'))) {
      $self->{'mode'} = $mode;
   } else {
      printf STDERR "No mode specified for X509browser\n";
      return undef;
   }

   # Stage 10: removed dead-code initialisation of $self->{stylebold} and
   # $self->{stylefix}. The original code created Gtk2::Style objects
   # using XLFD font strings ("-adobe-helvetica-*") that don't resolve on
   # modern fontconfig systems, then stored them on $self without ever
   # applying them to any widget. Gtk3 removed Gtk2::Style entirely
   # (replaced by Gtk3::StyleContext / CSS), so these lines also no
   # longer compile-load. They are deleted; if a later stage needs bold
   # or monospace fonts in the browser, use Pango attribute lists or a
   # CSS provider on the relevant widget.

   bless($self, $class);

   $self;
}

sub set_window {
  my $self = shift;
  my $widget = shift;

  if ( (not defined $self->{'browser'}) || ( $self->{'browser'} == undef )) {
     $self->{'browser'}=$widget;
  } else {
     # browser widget already exists
     return $false;
  }
}

sub add_list {
   my ($self, $actca, $directory, $crlfile, $indexfile) = @_;

   my ($x509listwin, @titles, @certtitles, @reqtitles, @keytitles, $column,
         $color, $text, $iter, $renderer);

   @reqtitles = (_("Common Name"),
                 _("eMail Address"),
                 _("Organizational Unit"),
                 _("Organization"),
                 _("Location"),
                 _("State"),
                 _("Country"));

   @certtitles = (_("Common Name"),
                  _("eMail Address"),
                  _("Organizational Unit"),
                  _("Organization"),
                  _("Location"),
                  _("State"),
                  _("Country"),
                  _("Status"));

   @keytitles = (_("Common Name"),
                 _("eMail Address"),
                 _("Organizational Unit"),
                 _("Organization"),
                 _("Location"),
                 _("State"),
                 _("Country"),
                 _("Type"));

   $self->{'actca'}    = $actca;
   $self->{'actdir'}   = $directory;
   $self->{'actcrl'}   = $crlfile;
   $self->{'actindex'} = $indexfile;

   if(defined($self->{'x509box'})) {
      $self->{'browser'}->remove($self->{'x509box'});
      $self->{'x509box'}->destroy();
   }

   $self->{'x509box'} = Gtk3::Box->new('vertical', 0);

   # Stage 13: NO VPaned. The original Gtk2 code put the list on top
   # and the cert/req info panel below it inside a VPaned with a
   # draggable divider. On this binding (libgtk3-perl 0.038) the
   # combination of VPaned->pack1 + ScrolledWindow + TreeView ends up
   # collapsing the TreeView's row area to zero height while still
   # giving the pane its allocated pixels — the symptom we saw on
   # TEST-SUB CA where the top of cert/req tabs rendered fully blank
   # (no column headers, no rows) even though the model was populated
   # and the selection was valid (info panel below was filled in
   # correctly). The keys tab works because it never used a VPaned.
   #
   # Replace with a plain VBox layout: list (expand=1) on top, info
   # panel (expand=0, natural size) on bottom for cert/req. Key mode
   # has no info panel — list takes the entire tab. Losing the
   # draggable divider is acceptable; the list now actually renders.
   my $has_info = ($self->{'mode'} eq 'cert' || $self->{'mode'} eq 'req');

   $self->{'browser'}->pack_start($self->{'x509box'}, 1, 1, 0);

   # now the list
   $x509listwin = Gtk3::ScrolledWindow->new(undef, undef);
   # Stage 13: 'always' policy so scrollbars are visible on
   # modern Adwaita-style Gtk3 themes (otherwise hidden until hover).
   $x509listwin->set_policy('always', 'always');
   $x509listwin->set_shadow_type('etched-in');
   # Stage 13: keep a modest minimum (~3 rows). The info panel below
   # (cert/req modes) is row-count-sized and can need ~340 px when
   # a cert has 8 right-column fields + 3 fingerprint lines. A larger
   # list minimum here pushes the info panel beyond the visible tab
   # area and content gets clipped at the bottom. Keys mode has no
   # info panel below — the list still expands to fill the tab.
   $x509listwin->set_min_content_height(100);

   # List on top, takes available vertical space.
   $self->{'x509box'}->pack_start($x509listwin, 1, 1, 0);

   # shall we display certificates, requests or keys?
   if ((defined $self->{'mode'}) && ($self->{'mode'} eq "cert")) {

      $self->{'x509store'} = Gtk3::ListStore->new(
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::Int');

      @titles = @certtitles;

   } elsif ((defined $self->{'mode'}) && ($self->{'mode'} eq "req")) {

      $self->{'x509store'} = Gtk3::ListStore->new(
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::Int');

      @titles = @reqtitles;

   } elsif ((defined $self->{'mode'}) && ($self->{'mode'} eq "key")) {

      $self->{'x509store'} = Gtk3::ListStore->new(
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::String',
        'Glib::Int');

      @titles = @keytitles;

   } else {
     # undefined mode
      return undef;
   }

   $self->{'x509store'}->set_sort_column_id(0, 'ascending');

   $self->{'x509clist'} = Gtk3::TreeView->new_with_model($self->{'x509store'});
   $self->{'x509clist'}->get_selection->set_mode ('single');

   for(my $i = 0; $titles[$i]; $i++) {
      $renderer = Gtk3::CellRendererText->new();
      $column = Gtk3::TreeViewColumn->new_with_attributes(
            $titles[$i], $renderer, 'text' => $i);
      $column->set_sort_column_id($i);
      $column->set_resizable(1);
      if (($i == 7) && ($self->{'mode'} eq 'cert')) {
         $column->set_cell_data_func ($renderer, sub {
               my ($column, $cell, $model, $iter) = @_;
               $text = $model->get($iter, 7);
               $color = $text eq _("VALID")?'green':'red';
               $cell->set (text => $text, foreground => $color);
               });
      }
      $self->{'x509clist'}->append_column($column);
   }

   if ((defined $self->{'mode'}) && ($self->{'mode'} eq 'cert')) {
      $self->{'x509clist'}->get_selection->signal_connect('changed' =>
            sub { _fill_info($self, 'cert') });
   } elsif ((defined $self->{'mode'}) && ($self->{'mode'} eq 'req')) {
      $self->{'x509clist'}->get_selection->signal_connect('changed' =>
            sub { _fill_info($self, 'req') });
   }

   $x509listwin->add($self->{'x509clist'});

   # Stage 13: pre-create the bottom info panel for cert/req modes BEFORE
   # the initial update() call. update_cert/req calls select_path(), which
   # synchronously fires the selection 'changed' signal → _fill_info →
   # update_info, and update_info needs both 'infowin' and 'infobox' to
   # already exist on $self. Previously add_info() (called from GUI.pm)
   # did this setup AFTER add_list, leaving the first 'changed' signal
   # with infowin undef.
   #
   # infobox is packed with expand=0,fill=0 so it sits at the bottom at
   # its natural height; the list above it gets the remaining space.
   if ($has_info) {
      $self->{'infowin'} = GUI::X509_infobox->new()
            unless defined $self->{'infowin'};
      $self->{'infobox'} = Gtk3::Box->new('vertical', 0);
      $self->{'x509box'}->pack_start($self->{'infobox'}, 0, 0, 0);
   }

   update($self, $directory, $crlfile, $indexfile, $true);

}

sub update {
  my ($self, $directory, $crlfile, $indexfile, $force) = @_;

  $self->{'actdir'}   = $directory;
  $self->{'actcrl'}   = $crlfile;
  $self->{'actindex'} = $indexfile;

  if ($self->{'mode'} eq "cert") {
     update_cert($self, $directory, $crlfile, $indexfile, $force);
  } elsif ($self->{'mode'} eq "req") {
     update_req($self, $directory, $crlfile, $indexfile, $force);
  } elsif ($self->{'mode'} eq "key") {
     update_key($self, $directory, $crlfile, $indexfile, $force);
  } else {
     return undef;
  }

  if ((defined $self->{'infowin'}) && ($self->{'infowin'} ne "")) {
     update_info($self);
  }

  $self->{'browser'}->show_all();

  return($true);
}

sub update_req {
    my ($self, $directory, $crlfile, $indexfile, $force) = @_;

    my ($ind, $name, $state, @line, $iter);

    $self->{'main'}->{'REQ'}->read_reqlist(
          $directory, $crlfile, $indexfile, $force, $self->{'main'});

    # Stage 13: fresh ListStore each update — see update_cert.
    my $new_store = Gtk3::ListStore->new(
        'Glib::String', 'Glib::String', 'Glib::String', 'Glib::String',
        'Glib::String', 'Glib::String', 'Glib::String',
        'Glib::Int',
    );
    # Case-sensitive sort (matches Gtk2). See update_cert for rationale.
    $new_store->set_sort_func(0, sub {
        my ($model, $a, $b) = @_;
        return ($model->get_value($a, 0) // '')
            cmp ($model->get_value($b, 0) // '');
    });
    $new_store->set_sort_column_id(0, 'ascending');

    $ind = 0;
    foreach my $n (@{$self->{'main'}->{'REQ'}->{'reqlist'}}) {
      ($name, $state) = split(/\%/, $n);
      @line = split(/\:/, $name);
      $iter = $new_store->append();
      $new_store->set($iter,
            0 => $line[0],
            1 => $line[1],
            2 => $line[2],
            3 => $line[3],
            4 => $line[4],
            5 => $line[5],
            6 => $line[6],
            7 => $ind);
      $ind++;
    }

    {
       my $vadj = $self->{'x509clist'}->get_vadjustment;
       $vadj->set_value(0) if $vadj;
    }
    $self->{'x509store'} = $new_store;
    $self->{'x509clist'}->set_model($new_store);

     # now select the first row to display certificate informations
     $self->{'x509clist'}->get_selection->select_path(
           Gtk3::TreePath->new_first());

}

sub update_cert {
    my ($self, $directory, $crlfile, $indexfile, $force) = @_;

    my ($ind, $name, $state, @line, $iter);

    $self->{'main'}->{'CERT'}->read_certlist(
          $directory, $crlfile, $indexfile, $force, $self->{'main'});

    # Stage 13: build a brand-new ListStore each update. Reusing the
    # store + detach/reattach was supposed to dodge the row-inserted
    # signal glitch in this binding, but it still dropped the first
    # row on the cert tab. A fresh store, populated up-front, attached
    # in one shot is the same pattern that finally worked for the
    # Open CA dialog.
    my $new_store = Gtk3::ListStore->new(
        'Glib::String', 'Glib::String', 'Glib::String', 'Glib::String',
        'Glib::String', 'Glib::String', 'Glib::String', 'Glib::String',
        'Glib::Int',
    );
    # Stage 13: use Perl's `cmp` (case-sensitive ASCII order) instead
    # of Gtk3's default locale-aware collation (case-insensitive on
    # most modern systems). This restores Gtk2's behaviour where
    # "General..." sorted before lowercase "c1...".
    $new_store->set_sort_func(0, sub {
        my ($model, $a, $b) = @_;
        return ($model->get_value($a, 0) // '')
            cmp ($model->get_value($b, 0) // '');
    });
    $new_store->set_sort_column_id(0, 'ascending');

    $ind = 0;
    foreach my $n (@{$self->{'main'}->{'CERT'}->{'certlist'}}) {
       ($name, $state) = split(/\%/, $n);
       @line = split(/\:/, $name);
       $iter = $new_store->append();
       $new_store->set($iter,
             0 => $line[0],
             1 => $line[1],
             2 => $line[2],
             3 => $line[3],
             4 => $line[4],
             5 => $line[5],
             6 => $line[6],
             7 => $state,
             8 => $ind);

        $ind++;
     }

    # Reset scroll-to-top, then swap to the new store atomically.
    {
       my $vadj = $self->{'x509clist'}->get_vadjustment;
       $vadj->set_value(0) if $vadj;
    }
    $self->{'x509store'} = $new_store;
    $self->{'x509clist'}->set_model($new_store);

     # now select the first row to display certificate informations
     $self->{'x509clist'}->get_selection->select_path(
           Gtk3::TreePath->new_first());
}

sub update_key {
    my ($self, $directory, $crlfile, $indexfile, $force) = @_;

    my ($ind, $name, @line, $iter, $state);

    $self->{'main'}->{'KEY'}->read_keylist($self->{'main'});

    # Stage 13: fresh ListStore each update — see update_cert.
    my $new_store = Gtk3::ListStore->new(
        'Glib::String', 'Glib::String', 'Glib::String', 'Glib::String',
        'Glib::String', 'Glib::String', 'Glib::String', 'Glib::String',
        'Glib::Int',
    );
    # Case-sensitive sort (matches Gtk2). See update_cert for rationale.
    $new_store->set_sort_func(0, sub {
        my ($model, $a, $b) = @_;
        return ($model->get_value($a, 0) // '')
            cmp ($model->get_value($b, 0) // '');
    });
    $new_store->set_sort_column_id(0, 'ascending');

    $ind = 0;
    foreach my $n (@{$self->{'main'}->{'KEY'}->{'keylist'}}) {
       ($name, $state) = split(/\%/, $n);
       @line = split(/\:/, $name);
       $iter = $new_store->append();
       $new_store->set($iter,
             0 => $line[0],
             1 => $line[1],
             2 => $line[2],
             3 => $line[3],
             4 => $line[4],
             5 => $line[5],
             6 => $line[6],
             7 => $state,
             8 => $ind);

        $ind++;
     }

    {
       my $vadj = $self->{'x509clist'}->get_vadjustment;
       $vadj->set_value(0) if $vadj;
    }
    $self->{'x509store'} = $new_store;
    $self->{'x509clist'}->set_model($new_store);

}

sub update_info {
    my ($self)=@_;

    my ($title, $parsed, $dn);

    $dn = selection_dn($self);

    if (defined $dn) {
       $dn = HELPERS::enc_base64($dn);

       if ($self->{'mode'} eq 'cert') {
          $parsed = $self->{'main'}->{'CERT'}->parse_cert($self->{'main'},
                $dn, $false);
          $title  = _("Certificate Information");
       } else {
          $parsed = $self->{'main'}->{'REQ'}->parse_req($self->{'main'}, $dn,
                $false);
          $title = _("Request Information");
       }

       defined($parsed) ||
          GUI::HELPERS::print_error(_("Can't read file"));

       # Stage 13: infobox / infowin are guaranteed to exist at this point
       # because add_list() pre-creates them for cert/req modes before any
       # selection signal can fire. The old fallback that created an
       # unparented Gtk3::VBox here was a no-op visually (it was never
       # packed into the widget tree) and is removed.
       $self->{'infowin'}->display($self->{'infobox'}, $parsed,
             $self->{'mode'}, $title);

    } else {
    # nothing selected
       $self->{'infowin'}->hide();
    }
}

#
# add infobox to the browser window
#
# Stage 13: infobox setup has moved into add_list() (it now happens BEFORE
# the initial update() runs, so the selection 'changed' signal fired by
# select_path can populate it). This routine is kept for API compatibility
# with GUI.pm and now just refreshes the panel for the current selection.
# It used to re-create the infobox and pack it into x509pane->pack2 here,
# which — combined with the lazy-create workaround that briefly lived in
# _fill_info — produced a duplicated pack2 child and left the cert/req
# top area looking empty after a CA switch.
#
sub add_info {
  my $self = shift;

  return unless (defined $self->{'infowin'} && defined $self->{'infobox'});
  update_info($self);
}

sub hide {
  my ($self) = @_;

  $self->{'window'}->hide();
  $self->{'dialog_shown'} = $false;
}

sub destroy {
  my ($self) = @_;

  $self->{'window'}->destroy();
  $self->{'dialog_shown'} = $false;
}

#
# signal handler for selected list items
# (updates the X509_infobox window)
#
sub _fill_info {
   my ($self) = @_;

   # Stage 13: infobox / infowin are pre-created in add_list before the
   # initial update() runs (see comment there), so this is just a thin
   # delegating wrapper for the selection 'changed' signal.
   update_info($self) if defined $self->{'infowin'};
}

sub selection_fname {
  my $self = shift;

  my ($selected, $row, $index, $dn, $status, $filename, $list);

  $row = $self->{'x509clist'}->get_selection->get_selected();

  return undef if (not defined $row);

  if ($self->{'mode'} eq 'req') {
     $index = ($self->{'x509store'}->get($row))[7];
     $list  = $self->{'main'}->{'REQ'}->{'reqlist'};
  } elsif ($self->{'mode'} eq 'cert') {
     $index = ($self->{'x509store'}->get($row))[8];
     $list  = $self->{'main'}->{'CERT'}->{'certlist'};
  } elsif ($self->{'mode'} eq 'key') {
     $index = ($self->{'x509store'}->get($row))[8];
     $list  = $self->{'main'}->{'KEY'}->{'certlist'};
  } else {
     GUI::HELPERS::print_error(
           _("Invalid browser mode for selection_fname():"." "
              .$self->{'mode'}));
  }


  if (defined $index) {
     ($dn, $status) = split(/\%/, $list->[$index]);
     $filename= HELPERS::enc_base64($dn);
     $filename=$self->{'actdir'}."/$filename".".pem";
  } else {
     $filename = undef;
  }

  return($filename);
}

sub selection_dn {
  my $self = shift;

  my ($selected, $row, $index, $dn, $status, $list);

  $row = $self->{'x509clist'}->get_selection->get_selected();

  return undef if (not defined $row);

  if ($self->{'mode'} eq 'req') {
     $index = ($self->{'x509store'}->get($row))[7];
     $list  = $self->{'main'}->{'REQ'}->{'reqlist'};
  } elsif ($self->{'mode'} eq 'cert') {
     $index = ($self->{'x509store'}->get($row))[8];
     $list  = $self->{'main'}->{'CERT'}->{'certlist'};
  } elsif ($self->{'mode'} eq 'key') {
     $index = ($self->{'x509store'}->get($row))[8];
     $list  = $self->{'main'}->{'KEY'}->{'keylist'};
  } else {
     GUI::HELPERS::print_error(
           _("Invalid browser mode for selection_dn():"." "
              .$self->{'mode'}));
  }

  if (defined $index) {
     ($dn, $status) = split(/\%/, $list->[$index]);
  } else {
     $dn = undef;
  }

  return($dn);
}

sub selection_cadir {
  my $self = shift;

  my $dir;

  $dir = $self->{'actdir'};
  # cut off the last directory name to provide the ca-directory
  $dir =~ s/(\/certs|\/req|\/keys)$//;
  return($dir);
}


sub selection_caname {
  my $self = shift;

  my ($selected, $caname);

  $caname   = $self->{'actca'};
  return($caname);
}

sub selection_cn {
  my $self = shift;

  my ($selected, $row, $index, $cn);

  $row = $self->{'x509clist'}->get_selection->get_selected();

  return undef if (not defined $row);

  if (($self->{'mode'} eq 'req') ||
      ($self->{'mode'} eq 'cert')||
      ($self->{'mode'} eq 'key')) {
     $cn = ($self->{'x509store'}->get($row))[0];
  } else {
     GUI::HELPERS::print_error(
           _("Invalid browser mode for selection_cn():"." "
              .$self->{'mode'}));
  }

  return($cn);
}

sub selection_email {
  my $self = shift;

  my ($selected, $row, $index, $email);

  $row = $self->{'x509clist'}->get_selection->get_selected();
  return undef if (not defined $row);

  if (($self->{'mode'} eq 'req') ||
      ($self->{'mode'} eq 'cert') ||
      ($self->{'mode'} eq 'key')) {
     $email = ($self->{'x509store'}->get($row))[1];
  } else {
     GUI::HELPERS::print_error(
           _("Invalid browser mode for selection_cn():"." "
              .$self->{'mode'}));
  }

  return($email);
}

sub selection_status {
  my $self = shift;

  my ($selected, $row, $index, $dn, $status, $list);

  $row = $self->{'x509clist'}->get_selection->get_selected();

  return undef if (not defined $row);

  if ($self->{'mode'} eq 'cert') {
     $index = ($self->{'x509store'}->get($row))[8];
     $list  = $self->{'main'}->{'CERT'}->{'certlist'};
  } else {
     GUI::HELPERS::print_error(
           _("Invalid browser mode for selection_status():"." "
              .$self->{'mode'}));
  }

  if (defined $index) {
     ($dn, $status) = split(/\%/, $list->[$index]);
  } else {
     $status = undef;
  }

  return($status);
}

sub selection_type {
  my $self = shift;

  my ($selected, $row, $index, $dn, $type, $list);

  $row = $self->{'x509clist'}->get_selection->get_selected();

  return undef if (not defined $row);

  if ($self->{'mode'} eq 'key') {
     $index = ($self->{'x509store'}->get($row))[8];
     $list  = $self->{'main'}->{'KEY'}->{'keylist'};
  } else {
     GUI::HELPERS::print_error(
           _("Invalid browser mode for selection_type():"." "
              .$self->{'mode'}));
  }

  if (defined $index) {
     ($dn, $type) = split(/\%/, $list->[$index]);
  } else {
     $type = undef;
  }

  return($type);
}


sub ok_function {
  my ($self) = @_;

  # is there a user defined ok_function?
  if (defined $self->{'User_OK_function'}) {
    $self->{'User_OK_function'}($self, selection_fname($self));
    }
  # otherwise do default
  else {
    printf STDOUT "%s\n", selection_fname($self);
    $self->hide();
    }
  return $true;

}

sub cancel_function {
  my ($self) = @_;

  # is there a user defined ok_function?
  if (defined $self->{'User_CANCEL_function'}) {
    $self->{'User_CANCEL_function'}($self, get_listselect($self));
    }
  # otherwise do default
  else {
    $self->{'window'}->hide();
    $self->{'dialog_shown'} = $false;
    }
  return $true;
}



#
# sort the table by the clicked column
#
sub _sort_clist {
   my ($clist, $col) = @_;

   $clist->set_sort_column($col);
   $clist->sort();

   return(1);
}


#
# called on mouseclick in certlist
#
sub _show_cert_menu {
   my ($clist, $self, $event) = @_;

   if ((defined($event->{'type'})) &&
         $event->{'button'} == 3) {
      $self->{'certmenu'}->popup(
            undef,
            undef,
            0,
            $event->{'button'},
            undef);

      return(1);
   }

   return(0);
}

$true;

__END__

=head1 NAME

GUI::X509_browser - Perl-Gtk3 browser for X.509 certificates and requests

=head1 SYNOPSIS

    use X509_browser;

    $browser=X509_browser->new($mode);
    $browser->create_window($title, $oktext, $canceltext,
                            \&okayfunction, \&cancelfunction);
    $browser->add_ca_select($cadir, @calist, $active-ca);
    $browser->add_list($active-ca, $X509dir, $crlfile, $indexfile);
    $browser->add_info();
    my $selection = $browser->selection_fname();
    $browser->hide();

=head1 DESCRIPTION

This displays a browser for X.509v3 certificates or certification
requests (CSR) from a CA managed by TinyCA2 (or some similar
structure).

Creation of an X509_browser is done by calling B<new()>,
the argument has to be 'cert' or 'req' to display certificates
or requests.

A window can be created for this purpose using
B<create_window($title, $oktext, $canceltext, \&okfunction, \&cancelfunction)>,
all arguments are optional.

=over 1

=item $title:

the existing Gtk3::VBox inside which the info will be
displayed.

=item $oktext:

The text to be displayed on the OK button of the dialog.

=item $canceltext:

The text to be displayed on the CANCEL button of the dialog.

=item \&okfunction:

Reference to a function that is executed on click on OK button.
This function should fetch the selected result (using
B<selection_fname()>) and also close the dialog using B<hide()>.

=item \&cancelfunction:

Reference to a function that is executed on click on CANCEL button.
This function should also close the dialog using B<hide()>.

=back

Further functions to get information about the selected item
exist, these are <B>selection_dn()</B>, <B>selection_status()</B>,
<B>selection_cadir()</B> and <B>selection_caname()</B>.

An existing infobox that already displays the content
of some directory can be modified by calling
<B>update()</B> with the same arguments that add_list().

An existing infobox is destroyed by calling B<destroy()>.

=cut
