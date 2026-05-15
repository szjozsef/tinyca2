# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: TCONFIG.pm,v 1.6 2006/06/28 21:50:42 sm Exp $
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
package GUI::TCONFIG;

use POSIX;
use UI::Stock;            # Stage 6: shims `new_from_stock` to themed icons
use I18N qw(_);           # Stage 12: formalised gettext wrapper

#
# main screen for configuration
#
sub show_configbox {
   my ($main, $name) = @_;

   my ($box, $vbox, $label, $table, $rows, @options, @options_ca, $entry,
         $key, $separator, $t, @combostrings, $button_cancel,
         $button_help, $buttonbox,
         $combonsCertType, $combosubjectAltName, $combokeyUsage,
         $comboextendedKeyUsage, $combonsSslServer, $combonsRevocationUrl,
         $combonsRenewalUrl,
         $combocnsCertType, $combocsubjectAltName, $combockeyUsage,
         $combocextendedKeyUsage, $combocnsSslServer, $combocnsRevocationUrl,
         $combocnsRenewalUrl,
         $combocansCertType, $combocasubjectAltName, $combocakeyUsage,
         $combocaextendedKeyUsage, $combocansSslServer, $combocansRevocationUrl,
         $combocansRenewalUrl);

   if(not defined($name)) {
      $name = $main->{'CA'}->{'actca'};
   }
   if(not defined($name)) {
      GUI::HELPERS::print_warning(_("Can't get CA name"));
      return;
   }

   $main->{'TCONFIG'}->init_config($main, $name);

   $box = Gtk3::Window->new("toplevel");
   $box->set_title("OpenSSL Configuration");
   $box->set_resizable(1);
   $box->set_default_size(800, 600);
   $box->signal_connect('delete_event' => sub { $box->destroy() });

   $box->{'button_ok'} = UI::Stock->button('gtk-ok');
   $box->{'button_ok'}->set_sensitive(0);
   $box->{'button_ok'}->signal_connect('clicked' =>
      sub { $main->{'TCONFIG'}->write_config($main, $name);
            $box->destroy() });


   $box->{'button_apply'} = UI::Stock->button('gtk-apply');
   $box->{'button_apply'}->set_sensitive(0);
   $box->{'button_apply'}->signal_connect('clicked' =>
      sub { $main->{'TCONFIG'}->write_config($main, $name) });

   $button_cancel = UI::Stock->button('gtk-cancel');
   $button_cancel->signal_connect( 'clicked' => sub { $box->destroy() });

   $t = _("All Settings are written unchanged to openssl.conf.\nSo please study the documentation of OpenSSL if you don't know exactly what to do.\nIf you are still unsure - keep the defaults and everything is expected to work fine.");
   $button_help = UI::Stock->button('gtk-help');
   $button_help->signal_connect('clicked' =>
      sub { GUI::HELPERS::print_info($t) });

   $box->{'vbox'} = Gtk3::Box->new('vertical', 0);

   $box->{'nb'} = Gtk3::Notebook->new();
   $box->{'nb'}->set_tab_pos('top');
   $box->{'nb'}->set_show_tabs(1);
   $box->{'nb'}->set_show_border(1);
   $box->{'nb'}->set_scrollable(0);

   $box->add($box->{'vbox'});

   $box->{'vbox'}->pack_start($box->{'nb'}, 1, 1, 0);

   $buttonbox = Gtk3::ButtonBox->new('horizontal');
   $buttonbox->set_layout('end');
   $buttonbox->set_spacing(3);
   $buttonbox->set_border_width(3);
   $buttonbox->add($button_help);
   $buttonbox->set_child_secondary($button_help, 1);

   $buttonbox->add($box->{'button_ok'});
   $buttonbox->add($box->{'button_apply'});
   $buttonbox->add($button_cancel);

   $box->{'vbox'}->pack_start($buttonbox, 0, 0, 0);

   # first page: vbox with warnings :-)
   $vbox = Gtk3::Box->new('vertical', 0);

   $label = GUI::HELPERS::create_label(
         _("OpenSSL Configuration"), 'center', 0,0);

   $box->{'nb'}->append_page($vbox, $label);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("OpenSSL Configuration"), 'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk3::Separator->new('horizontal');
   $vbox->pack_start($separator, 0, 0, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("Only change these options, if you really know, what you are doing!!"),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("You should be aware, that some options may break some crappy software!!"),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);


   $label = GUI::HELPERS::create_label(
         _("If you are unsure: leave the defaults untouched"),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   # second page: server settings
   @options = qw(
         nsComment
         crlDistributionPoints
         authorityKeyIdentifier
         issuerAltName
         nsBaseUrl
         nsCaPolicyUrl
         );

   my @special_options = qw(
         nsCertType
         nsSslServerName
         nsRevocationUrl
         nsRenewalUrl
         subjectAltName
         keyUsage
         extendedkeyUsage
         );

   @options_ca = qw(
         default_days
         );
   $vbox = Gtk3::Box->new('vertical', 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("These Settings are passed to OpenSSL for creating Server Certificates"),
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("Multiple Values can be separated by \",\""),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk3::Separator->new('horizontal');
   $vbox->pack_start($separator, 0, 0, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = GUI::HELPERS::create_grid();
   $vbox->pack_start($table, 1, 1, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(_("Server Certificate Settings"),
         'center', 0, 0);
   $label = Gtk3::Label->new(_("Server Certificate Settings"));

   $box->{'nb'}->append_page($vbox, $label);

   # special option subjectAltName
   $label = GUI::HELPERS::create_label(
         _("Subject alternative name (subjectAltName):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $main->{'radiobox'} = Gtk3::Box->new('horizontal', 0);
   $main->{'radio1'} = Gtk3::RadioButton->new_with_label(undef, _($main->{'words'}{'ip'}));
   $main->{'radio1'}->signal_connect('toggled' =>
        sub {GUI::CALLBACK::toggle_to_var_pref($main->{'radio1'},
           \$main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'}, 'ip',
           $box)});

   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk3::RadioButton->new_with_label_from_widget(
         $main->{'radio1'}, _($main->{'words'}{'dns'}));
   $main->{'radio2'}->signal_connect('toggled' =>
        sub {GUI::CALLBACK::toggle_to_var_pref($main->{'radio2'},
           \$main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'},
           'dns', $box)});

   $main->{'radiobox'}->add($main->{'radio2'});

   $main->{'radio3'} = Gtk3::RadioButton->new_with_label_from_widget($main->{'radio1'},
         _($main->{'words'}{'raw'}));

   $main->{'radio3'}->signal_connect('toggled' =>
        sub {GUI::CALLBACK::toggle_to_var_pref($main->{'radio3'},
           \$main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'},
           'raw', $box)});

   $main->{'radiobox'}->add($main->{'radio3'});

   if($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'}
         eq 'ip') {
      $main->{'radio1'}->set_active(1)
   }elsif($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'}
         eq 'dns') {
      $main->{'radio2'}->set_active(1)
   }elsif($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltNameType'}
         eq 'raw') {
      $main->{'radio3'}->set_active(1)
   }

   $combosubjectAltName = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = (
         $main->{'words'}{'none'},
         $main->{'words'}{'user'},
         $main->{'words'}{'emailcopy'});
   $combosubjectAltName->remove_all;
   $combosubjectAltName->append_text($_) for @combostrings;
   $combosubjectAltName->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'})) {
     if($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'}
        eq 'user') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);
        $main->{'radio3'}->set_sensitive(1);

        $combosubjectAltName->get_child->set_text($main->{'words'}{'user'});
     }elsif($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'}
        eq 'emailcopy') {
        $combosubjectAltName->get_child->set_text($main->{'words'}{'emailcopy'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
        $main->{'radio3'}->set_sensitive(0);
     }elsif($main->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'}
        eq 'none') {
        $combosubjectAltName->get_child->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
        $main->{'radio3'}->set_sensitive(0);
     }
   } else {
      $combosubjectAltName->get_child->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
      $main->{'radio3'}->set_sensitive(0);
   }
   $combosubjectAltName->get_child->signal_connect('changed' =>
         sub { GUI::CALLBACK::entry_to_var_san(
         $combosubjectAltName,
         $combosubjectAltName->get_child,
         \$main->{'TCONFIG'}->{'server_cert'}->{'subjectAltName'},
         $box,
         $main->{words},
         $main->{'radio1'},
         $main->{'radio2'},
         $main->{'radio3'})});
   $table->attach($combosubjectAltName, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   $table->attach($main->{'radiobox'}, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option keyUsage
   $label = GUI::HELPERS::create_label(
         _("Key Usage (keyUsage):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $main->{'radiobox'} = Gtk3::Box->new('horizontal', 0);

   $main->{'radio1'} = Gtk3::RadioButton->new_with_label(undef,
         _($main->{'words'}{'critical'}));
   if($main->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'} eq 'critical') {
      $main->{'radio1'}->set_active(1)
   }
   $main->{'radio1'}->signal_connect('toggled' =>
         sub {GUI::CALLBACK::toggle_to_var_pref($main->{'radio1'},
            \$main->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'},
            'critical', $box)});

   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk3::RadioButton->new_with_label_from_widget($main->{'radio1'},
         _($main->{'words'}{'noncritical'}));
   if($main->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'} eq 'noncritical') {
      $main->{'radio2'}->set_active(1)
   }
   $main->{'radio2'}->signal_connect('toggled' =>
         sub {GUI::CALLBACK::toggle_to_var_pref($main->{'radio2'},
            \$main->{'TCONFIG'}->{'server_cert'}->{'keyUsageType'},
            'noncritical', $box)});

   $main->{'radiobox'}->add($main->{'radio2'});

   $combokeyUsage = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = (
         $main->{'words'}{'none'},
         $main->{'words'}{'sig'},
         $main->{'words'}{'key'},
         $main->{'words'}{'keysig'});
   $combokeyUsage->remove_all;
   $combokeyUsage->append_text($_) for @combostrings;
   $combokeyUsage->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'})) {
     if($main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'}
        ne 'none') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        if($main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'} eq 'sig') {
           $combokeyUsage->get_child->set_text($main->{'words'}{'sig'});
        }elsif($main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'} eq 'key') {
           $combokeyUsage->get_child->set_text($main->{'words'}{'key'});
        }elsif($main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'} eq 'keysig') {
           $combokeyUsage->get_child->set_text($main->{'words'}{'keysig'});
        }else {
           $combokeyUsage->get_child->set_text($main->{'words'}{'none'});
           $main->{'radio1'}->set_sensitive(0);
           $main->{'radio2'}->set_sensitive(0);
        }
     }else {
        $combokeyUsage->get_child->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else {
      $combokeyUsage->get_child->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $combokeyUsage->get_child->signal_connect('changed' =>
         sub { GUI::CALLBACK::entry_to_var_key($combokeyUsage, $combokeyUsage->get_child,
            \$main->{'TCONFIG'}->{'server_cert'}->{'keyUsage'}, $box,
            $main->{words}, $main->{'radio1'},  $main->{'radio2'})});

   $table->attach($combokeyUsage, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   $table->attach($main->{'radiobox'}, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option extendedKeyUsage
   $label = GUI::HELPERS::create_label(
         _("Extended Key Usage (extendedKeyUsage):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $main->{'radiobox'} = Gtk3::Box->new('horizontal', 0);
   $main->{'radio1'} = Gtk3::RadioButton->new_with_label(undef,
         _($main->{'words'}{'critical'}));
   if($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsageType'} eq 'critical') {
      $main->{'radio1'}->set_active(1)
   }
   $main->{'radio1'}->signal_connect('toggled' =>
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio1'},
            \$main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsageType'},
            'critical', $box)});
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk3::RadioButton->new_with_label_from_widget($main->{'radio1'},
         _($main->{'words'}{'noncritical'}));
   if($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsageType'} eq 'noncritical') {
      $main->{'radio2'}->set_active(1)
   }
   $main->{'radio2'}->signal_connect('toggled' =>
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio2'},
            \$main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsageType'},
            'noncritical', $box)});
   $main->{'radiobox'}->add($main->{'radio2'});

   $comboextendedKeyUsage = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = (
         $main->{'words'}{'none'},
         $main->{'words'}{'user'});

   if((defined($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'})) &&
      ($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'} ne 'none') &&
      ($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'} ne '')) {
      push(@combostrings,
            $main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'});
   }

   $comboextendedKeyUsage->remove_all;

   $comboextendedKeyUsage->append_text($_) for @combostrings;

   $comboextendedKeyUsage->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'})) {
     if($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'}
        ne 'none') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        if($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'} eq 'user'){
           $comboextendedKeyUsage->get_child->set_text($main->{'words'}{'user'});
        } else {
           $comboextendedKeyUsage->get_child->set_text($main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'});
        }
     } else {
        $comboextendedKeyUsage->get_child->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else {
      $comboextendedKeyUsage->get_child->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $comboextendedKeyUsage->get_child->signal_connect('changed' =>
         sub { GUI::CALLBACK::entry_to_var_key($comboextendedKeyUsage, $comboextendedKeyUsage->get_child,
            \$main->{'TCONFIG'}->{'server_cert'}->{'extendedKeyUsage'}, $box,
            $main->{words}, $main->{'radio1'},  $main->{'radio2'}) });

   $table->attach($comboextendedKeyUsage, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   $table->attach($main->{'radiobox'}, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option nsCerttype
   $label = GUI::HELPERS::create_label(
         _("Netscape Certificate Type (nsCertType):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $combonsCertType = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = (
         $main->{'words'}{'none'},
         $main->{'words'}{'server'},
         $main->{'words'}{'server, client'});

   $combonsCertType->remove_all;

   $combonsCertType->append_text($_) for @combostrings;

   $combonsCertType->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'nsCertType'})) {
      $combonsCertType->get_child->set_text(
            $main->{'words'}{$main->{'TCONFIG'}->{'server_cert'}->{'nsCertType'}});
   } else {
      $combonsCertType->get_child->set_text($main->{'words'}{'none'});
   }
   $combonsCertType->get_child->signal_connect('changed' =>
         sub { GUI::CALLBACK::entry_to_var($combonsCertType, $combonsCertType->get_child,
            \$main->{'TCONFIG'}->{'server_cert'}->{'nsCertType'}, $box,
            $main->{words}) });

   $table->attach($combonsCertType, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option nsSslServer
   $label = GUI::HELPERS::create_label(
         _("Netscape SSL Server Name (nsSslServerName):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $combonsSslServer = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combonsSslServer->remove_all;
   $combonsSslServer->append_text($_) for @combostrings;
   $combonsSslServer->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'}) &&
         $main->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'}
         eq 'user') {
      $combonsSslServer->get_child->set_text($main->{'words'}{'user'});
   } else {
      $combonsSslServer->get_child->set_text($main->{'words'}{'none'});
   }
   $combonsSslServer->get_child->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combonsSslServer, $combonsSslServer->get_child,
           \$main->{'TCONFIG'}->{'server_cert'}->{'nsSslServerName'}, $box,
           $main->{words}) });

   $table->attach($combonsSslServer, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option nsRevocationUrl
   $label = GUI::HELPERS::create_label(
         _("Netscape Revocation URL (nsRevocationUrl):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $combonsRevocationUrl = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combonsRevocationUrl->remove_all;
   $combonsRevocationUrl->append_text($_) for @combostrings;
   $combonsRevocationUrl->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'}) &&
         $main->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'}
         eq 'user') {
      $combonsRevocationUrl->get_child->set_text($main->{'words'}{'user'});
   } else {
      $combonsRevocationUrl->get_child->set_text($main->{'words'}{'none'});
   }
   $combonsRevocationUrl->get_child->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combonsRevocationUrl, $combonsRevocationUrl->get_child,
           \$main->{'TCONFIG'}->{'server_cert'}->{'nsRevocationUrl'}, $box,
           $main->{words}) });

   $table->attach($combonsRevocationUrl, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option nsRenewalUrl
   $label = GUI::HELPERS::create_label(
         _("Netscape Renewal URL (nsRenewalUrl):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $combonsRenewalUrl = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combonsRenewalUrl->remove_all;
   $combonsRenewalUrl->append_text($_) for @combostrings;
   $combonsRenewalUrl->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'}) &&
         $main->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'}
         eq 'user') {
      $combonsRenewalUrl->get_child->set_text($main->{'words'}{'user'});
   } else {
      $combonsRenewalUrl->get_child->set_text($main->{'words'}{'none'});
   }
   $combonsRenewalUrl->get_child->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combonsRenewalUrl, $combonsRenewalUrl->get_child,
           \$main->{'TCONFIG'}->{'server_cert'}->{'nsRenewalUrl'}, $box,
           $main->{words}) });

   $table->attach($combonsRenewalUrl, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # standard options
   foreach $key (@options) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'server_cert'}->{$key},
            $table, $rows-1, 1, $box);

      $rows++;
   }

   foreach $key (@options_ca) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'server_ca'}->{$key},
            $table, $rows-1, 1, $box);

      $rows++;
   }

   # third page: client settings
   @options = qw(
         nsComment
         crlDistributionPoints
         authorityKeyIdentifier
         issuerAltName
         nsBaseUrl
         nsCaPolicyUrl
         );

   @options_ca = qw(
         default_days
         );
   $vbox = Gtk3::Box->new('vertical', 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("These Settings are passed to OpenSSL for creating Client Certificates"),
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("Multiple Values can be separated by \",\""),
         'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk3::Separator->new('horizontal');
   $vbox->pack_start($separator, 0, 0, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = GUI::HELPERS::create_grid();
   $vbox->pack_start($table, 1, 1, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(_("Client Certificate Settings"),
         'center', 0, 0);
   $box->{'nb'}->append_page($vbox, $label);

   # special option subjectAltName
   $label = GUI::HELPERS::create_label(
         _("Subject alternative name (subjectAltName):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $main->{'radiobox'} = Gtk3::Box->new('horizontal', 0);
   $main->{'radio1'} = Gtk3::RadioButton->new_with_label(undef,
         _($main->{'words'}{'ip'}));
   $main->{'radio1'}->signal_connect('toggled' =>
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio1'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'},
            'ip', $box) });
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk3::RadioButton->new_with_label_from_widget($main->{'radio1'},
         _($main->{'words'}{'dns'}));
   $main->{'radio2'}->signal_connect('toggled' =>
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio2'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'},
            'dns', $box) });
   $main->{'radiobox'}->add($main->{'radio2'});

   $main->{'radio3'} = Gtk3::RadioButton->new_with_label_from_widget($main->{'radio1'},
         _($main->{'words'}{'mail'}));
   $main->{'radio3'}->signal_connect('toggled' =>
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio3'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'},
            'mail', $box) });
   $main->{'radiobox'}->add($main->{'radio3'});

   $main->{'radio4'} = Gtk3::RadioButton->new_with_label_from_widget($main->{'radio1'},
         _($main->{'words'}{'raw'}));
   $main->{'radio4'}->signal_connect('toggled' =>
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio4'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'},
            'raw', $box) });
   $main->{'radiobox'}->add($main->{'radio4'});

   if($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'}
         eq 'ip') {
      $main->{'radio1'}->set_active(1)
   }elsif($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'}
         eq 'dns') {
      $main->{'radio2'}->set_active(1)
   }elsif($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'}
         eq 'mail') {
      $main->{'radio3'}->set_active(1)
   }elsif($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltNameType'}
         eq 'raw') {
      $main->{'radio4'}->set_active(1)
   }

   $combocsubjectAltName = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = (
         $main->{'words'}{'none'},
         $main->{'words'}{'user'},
         $main->{'words'}{'emailcopy'});
   $combocsubjectAltName->remove_all;
   $combocsubjectAltName->append_text($_) for @combostrings;
   $combocsubjectAltName->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'})) {
     if($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'}
        eq 'user') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);
        $main->{'radio3'}->set_sensitive(1);
        $main->{'radio4'}->set_sensitive(1);

        $combocsubjectAltName->get_child->set_text($main->{'words'}{'user'});
     }elsif($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'}
        eq 'emailcopy') {
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
        $main->{'radio3'}->set_sensitive(0);
        $main->{'radio4'}->set_sensitive(1);

        $combocsubjectAltName->get_child->set_text($main->{'words'}{'emailcopy'});
     }elsif($main->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'}
        eq 'none') {
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
        $main->{'radio3'}->set_sensitive(0);
        $main->{'radio4'}->set_sensitive(1);

        $combocsubjectAltName->get_child->set_text($main->{'words'}{'none'});
     }
   } else {
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
      $main->{'radio3'}->set_sensitive(0);
      $main->{'radio4'}->set_sensitive(1);

      $combocsubjectAltName->get_child->set_text($main->{'words'}{'none'});
   }
   $combocsubjectAltName->get_child->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var_san($combocsubjectAltName, $combocsubjectAltName->get_child,
           \$main->{'TCONFIG'}->{'client_cert'}->{'subjectAltName'}, $box,
           $main->{words}, $main->{'radio1'}, $main->{'radio2'},
           $main->{'radio3'}, $main->{'radio4'}) });
   $table->attach($combocsubjectAltName, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   $table->attach($main->{'radiobox'}, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option keyUsage
   $label = GUI::HELPERS::create_label(
         _("Key Usage (keyUsage):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $main->{'radiobox'} = Gtk3::Box->new('horizontal', 0);
   $main->{'radio1'} = Gtk3::RadioButton->new_with_label(undef,
         _($main->{'words'}{'critical'}));
   if($main->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'} eq 'critical') {
      $main->{'radio1'}->set_active(1)
   }
   $main->{'radio1'}->signal_connect('toggled' =>
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio1'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'},
            'critical', $box) });
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk3::RadioButton->new_with_label_from_widget($main->{'radio1'},
         _($main->{'words'}{'noncritical'}));
   if($main->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'} eq 'noncritical') {
      $main->{'radio2'}->set_active(1)
   }
   $main->{'radio2'}->signal_connect('toggled' =>
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio2'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'keyUsageType'},
            'noncritical', $box) });
   $main->{'radiobox'}->add($main->{'radio2'});

   $combockeyUsage = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = (
         $main->{'words'}{'none'},
         $main->{'words'}{'sig'},
         $main->{'words'}{'key'},
         $main->{'words'}{'keysig'});
   $combockeyUsage->remove_all;
   $combockeyUsage->append_text($_) for @combostrings;
   $combockeyUsage->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'})) {
     if($main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'}
        ne 'none') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        if($main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'} eq 'sig') {
           $combockeyUsage->get_child->set_text($main->{'words'}{'sig'});
        }elsif($main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'} eq 'key') {
           $combockeyUsage->get_child->set_text($main->{'words'}{'key'});
        }elsif($main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'} eq 'keysig') {
           $combockeyUsage->get_child->set_text($main->{'words'}{'keysig'});
        }else {
           $combockeyUsage->get_child->set_text($main->{'words'}{'none'});
           $main->{'radio1'}->set_sensitive(0);
           $main->{'radio2'}->set_sensitive(0);
        }
     }else {
        $combockeyUsage->get_child->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else {
      $combockeyUsage->get_child->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $combockeyUsage->get_child->signal_connect('changed' =>
         sub { GUI::CALLBACK::entry_to_var_key($combockeyUsage, $combockeyUsage->get_child,
            \$main->{'TCONFIG'}->{'client_cert'}->{'keyUsage'}, $box,
            $main->{words}, $main->{'radio1'},  $main->{'radio2'}) });
   $table->attach($combockeyUsage, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   $table->attach($main->{'radiobox'}, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option extendedKeyUsage
   $label = GUI::HELPERS::create_label(
         _("Extended Key Usage (extendedKeyUsage):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $main->{'radiobox'} = Gtk3::Box->new('horizontal', 0);
   $main->{'radio1'} = Gtk3::RadioButton->new_with_label(undef,
         _($main->{'words'}{'critical'}));
   if($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsageType'} eq 'critical') {
      $main->{'radio1'}->set_active(1)
   }
   $main->{'radio1'}->signal_connect('toggled' =>
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio1'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsageType'},
            'critical', $box) });
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk3::RadioButton->new_with_label_from_widget($main->{'radio1'},
         _($main->{'words'}{'noncritical'}));
   if($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsageType'} eq 'noncritical') {
      $main->{'radio2'}->set_active(1)
   }
   $main->{'radio2'}->signal_connect('toggled' =>
         sub { GUI::CALLBACK::toggle_to_var_pref( $main->{'radio2'},
            \$main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsageType'},
            'noncritical', $box) });
   $main->{'radiobox'}->add($main->{'radio2'});

   $combocextendedKeyUsage = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = (
         $main->{'words'}{'none'},
         $main->{'words'}{'user'});

   if((defined($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'})) &&
      ($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'} ne 'none') &&
      ($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'} ne '')) {
      push(@combostrings,
            $main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'});
   }

   $combocextendedKeyUsage->remove_all;

   $combocextendedKeyUsage->append_text($_) for @combostrings;

   $combocextendedKeyUsage->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'})) {
     if($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'}
        ne 'none') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        if($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'} eq 'user'){
           $combocextendedKeyUsage->get_child->set_text($main->{'words'}{'user'});
        } else {
           $combocextendedKeyUsage->get_child->set_text($main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'});
        }
     } else {
        $combocextendedKeyUsage->get_child->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else {
      $combocextendedKeyUsage->get_child->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $combocextendedKeyUsage->get_child->signal_connect('changed' =>
         sub { GUI::CALLBACK::entry_to_var_key($combocextendedKeyUsage, $combocextendedKeyUsage->get_child,
            \$main->{'TCONFIG'}->{'client_cert'}->{'extendedKeyUsage'}, $box,
            $main->{words}, $main->{'radio1'},  $main->{'radio2'}) });
   $table->attach($combocextendedKeyUsage, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   $table->attach($main->{'radiobox'}, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option nsCerttype
   $label = GUI::HELPERS::create_label(
         _("Netscape Certificate Type (nsCertType):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $combocnsCertType = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = (
         $main->{'words'}{'none'},
         $main->{'words'}{'objsign'},
         $main->{'words'}{'email'},
         $main->{'words'}{'client'},
         $main->{'words'}{'client, email'},
         $main->{'words'}{'client, objsign'},
         $main->{'words'}{'client, email, objsign'});
   $combocnsCertType->remove_all;
   $combocnsCertType->append_text($_) for @combostrings;
   $combocnsCertType->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'nsCertType'})) {
      $combocnsCertType->get_child->set_text(
            $main->{'words'}{$main->{'TCONFIG'}->{'client_cert'}->{'nsCertType'}});
   } else {
      $combocnsCertType->get_child->set_text($main->{'words'}{'none'});
   }
   $combocnsCertType->get_child->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combocnsCertType, $combocnsCertType->get_child,
           \$main->{'TCONFIG'}->{'client_cert'}->{'nsCertType'}, $box,
           $main->{words}) });
   $table->attach($combocnsCertType, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option nsRevocationUrl
   $label = GUI::HELPERS::create_label(
         _("Netscape Revocation URL (nsRevocationUrl):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $combocnsRevocationUrl = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combocnsRevocationUrl->remove_all;
   $combocnsRevocationUrl->append_text($_) for @combostrings;
   $combocnsRevocationUrl->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'}) &&
         $main->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'}
         eq 'user') {
      $combocnsRevocationUrl->get_child->set_text($main->{'words'}{'user'});
   } else {
      $combocnsRevocationUrl->get_child->set_text($main->{'words'}{'none'});
   }
   $combocnsRevocationUrl->get_child->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combocnsRevocationUrl, $combocnsRevocationUrl->get_child,
           \$main->{'TCONFIG'}->{'client_cert'}->{'nsRevocationUrl'}, $box,
           $main->{words}) });
   $table->attach($combocnsRevocationUrl, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option nsRenewalUrl
   $label = GUI::HELPERS::create_label(
         _("Netscape Renewal URL (nsRenewalUrl):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $combocnsRenewalUrl = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combocnsRenewalUrl->remove_all;
   $combocnsRenewalUrl->append_text($_) for @combostrings;
   $combocnsRenewalUrl->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'}) &&
         $main->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'}
         eq 'user') {
      $combocnsRenewalUrl->get_child->set_text($main->{'words'}{'user'});
   } else {
      $combocnsRenewalUrl->get_child->set_text($main->{'words'}{'none'});
   }
   $combocnsRenewalUrl->get_child->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combocnsRenewalUrl, $combocnsRenewalUrl->get_child,
           \$main->{'TCONFIG'}->{'client_cert'}->{'nsRenewalUrl'}, $box,
           $main->{words}) });
   $table->attach($combocnsRenewalUrl, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # standard options
   foreach $key (@options) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'client_cert'}->{$key},
            $table, $rows-1, 1, $box);

      $rows++;
   }

   foreach $key (@options_ca) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'client_ca'}->{$key},
            $table, $rows-1, 1, $box);

      $rows++;
   }

   # fourth page: ca settings
   @options = qw(
         nsComment
         crlDistributionPoints
         authorityKeyIdentifier
         issuerAltName
         nsBaseUrl
         nsCaPolicyUrl
         );

   @special_options = qw(
         nsCertType
         nsRevocationUrl
         subjectAltName
         );

   @options_ca = qw(
         default_days
         );
   $vbox = Gtk3::Box->new('vertical', 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("These Settings are passed to OpenSSL for creating CA Certificates"),
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("Multiple Values can be separated by \",\""),
         'center', 1, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk3::Separator->new('horizontal');
   $vbox->pack_start($separator, 0, 0, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = GUI::HELPERS::create_grid();
   $vbox->pack_start($table, 1, 1, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(_("CA Certificate Settings"),
         'center', 0, 0);
   $label = Gtk3::Label->new(_("CA Certificate Settings"));

   $box->{'nb'}->append_page($vbox, $label);

   # special option subjectAltName
   $label = GUI::HELPERS::create_label(
         _("Subject alternative name (subjectAltName):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $combocasubjectAltName = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'emailcopy'});
   $combocasubjectAltName->remove_all;
   $combocasubjectAltName->append_text($_) for @combostrings;
   $combocasubjectAltName->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'})) {
     if($main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'}
        eq 'emailcopy') {
        $combocasubjectAltName->get_child->set_text($main->{'words'}{'emailcopy'});
     }elsif($main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'}
        eq 'none') {
        $combocasubjectAltName->get_child->set_text($main->{'words'}{'none'});
     }
   } else {
      $combocasubjectAltName->get_child->set_text($main->{'words'}{'none'});
   }
   $combocasubjectAltName->get_child->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var_san($combocasubjectAltName,
         $combocasubjectAltName->get_child, \$main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'},
         $box, $main->{words}) });
   $table->attach($combocasubjectAltName, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option nsCerttype
   $label = GUI::HELPERS::create_label(
         _("Netscape Certificate Type (nsCertType):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $combocansCertType = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = ($main->{'words'}{'none'},
                    $main->{'words'}{'emailCA'},
                    $main->{'words'}{'sslCA'},
                    $main->{'words'}{'objCA'},
                    $main->{'words'}{'sslCA, emailCA'},
                    $main->{'words'}{'sslCA, objCA'},
                    $main->{'words'}{'emailCA, objCA'},
                    $main->{'words'}{'sslCA, emailCA, objCA'}
                    );
   $combocansCertType->remove_all;
   $combocansCertType->append_text($_) for @combostrings;
   $combocansCertType->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'})) {
      $combocansCertType->get_child->set_text(
            $main->{'words'}{$main->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'}});
   } else {
      $combocansCertType->get_child->set_text($main->{'words'}{'none'});
   }
   $combocansCertType->get_child->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combocansCertType, $combocansCertType->get_child,
           \$main->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'}, $box,
           $main->{words}) });
   $table->attach($combocansCertType, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option keyUsage
   $label = GUI::HELPERS::create_label(
         _("Key Usage (keyUsage):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $main->{'radiobox'} = Gtk3::Box->new('horizontal', 0);
   $main->{'radio1'} = Gtk3::RadioButton->new_with_label(undef,
         _($main->{'words'}{'critical'}));
   if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'} eq 'critical') {
      $main->{'radio1'}->set_active(1)
   }
   $main->{'radio1'}->signal_connect('toggled' =>
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio1'},
            \$main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'}, 'critical',
            $box) });
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk3::RadioButton->new_with_label_from_widget($main->{'radio1'},
         _($main->{'words'}{'noncritical'}));
   if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'} eq 'noncritical') {
      $main->{'radio2'}->set_active(1)
   }
   $main->{'radio2'}->signal_connect('toggled' =>
         sub { GUI::CALLBACK::toggle_to_var_pref($main->{'radio2'},
            \$main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'}, 'noncritical',
            $box) });
   $main->{'radiobox'}->add($main->{'radio2'});

   $combocakeyUsage = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = ($main->{'words'}{'none'},
                    $main->{'words'}{'keyCertSign'},
                    $main->{'words'}{'cRLSign'},
                    $main->{'words'}{'keyCertSign, cRLSign'});
   $combocakeyUsage->remove_all;
   $combocakeyUsage->append_text($_) for @combostrings;
   $combocakeyUsage->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'})) {
     if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'}
        ne 'none') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 'keyCertSign') {
           $combocakeyUsage->get_child->set_text($main->{'words'}{'keyCertSign'});
        }elsif($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 'cRLSign') {
           $combocakeyUsage->get_child->set_text($main->{'words'}{'cRLSign'});
        }elsif($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq
                                                 'keyCertSign, cRLSign') {
           $combocakeyUsage->get_child->set_text($main->{'words'}{'keyCertSign, cRLSign'});
        }else {
           $combocakeyUsage->get_child->set_text($main->{'words'}{'none'});
           $main->{'radio1'}->set_sensitive(0);
           $main->{'radio2'}->set_sensitive(0);
        }
     }else {
        $combocakeyUsage->get_child->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else {
      $combocakeyUsage->get_child->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $combocakeyUsage->get_child->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var_key($combocakeyUsage, $combocakeyUsage->get_child,
           \$main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'}, $box, $main->{words},
           $main->{'radio1'},  $main->{'radio2'}) });
   $table->attach($combocakeyUsage, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   $table->attach($main->{'radiobox'}, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option nsRevocationUrl
   $label = GUI::HELPERS::create_label(
         _("Netscape Revocation URL (nsRevocationUrl):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $combocansRevocationUrl = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'user'});
   $combocansRevocationUrl->remove_all;
   $combocansRevocationUrl->append_text($_) for @combostrings;
   $combocansRevocationUrl->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'nsRevocationUrl'}) &&
         $main->{'TCONFIG'}->{'v3_ca'}->{'nsRevocationUrl'}
         eq 'user') {
      $combocansRevocationUrl->get_child->set_text($main->{'words'}{'user'});
   } else {
      $combocansRevocationUrl->get_child->set_text($main->{'words'}{'none'});
   }
   $combocansRevocationUrl->get_child->signal_connect('changed' =>
        sub { GUI::CALLBACK::entry_to_var($combocansRevocationUrl, $combocansRevocationUrl->get_child,
           \$main->{'TCONFIG'}->{'v3_ca'}->{'nsRevocationUrl'}, $box,
           $main->{words}) });
   $table->attach($combocansRevocationUrl, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # standard options
   foreach $key (@options) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'v3_ca'}->{$key},
            $table, $rows-1, 1, $box);

      $rows++;
   }

   foreach $key (@options_ca) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'ca_ca'}->{$key},
            $table, $rows-1, 1, $box);

      $rows++;
   }

   # fifth page: crl settings
   @options = qw(
         default_crl_days
         );

   $vbox = Gtk3::Box->new('vertical', 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("These Settings are passed to OpenSSL for creating Certificate Revocation Lists"),
         'center', 0, 1);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("Multiple Values can be separated by \",\""),
         'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $separator = Gtk3::Separator->new('horizontal');
   $vbox->pack_start($separator, 0, 0, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = GUI::HELPERS::create_grid();
   $vbox->pack_start($table, 0, 0, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $vbox->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("Revocation List Settings"), 'center', 0, 0);
   $box->{'nb'}->append_page($vbox, $label);

   foreach $key (@options) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'server_ca'}->{$key},
            $table, $rows-1, 1, $box);

      $rows++;
   }

   $box->show_all();

   $box->{'button_ok'}->set_sensitive(0);
   $box->{'button_apply'}->set_sensitive(0);

   return;
}

#
# configuration for CA
#
sub show_config_ca {
   my ($main, $opts, $mode) = @_;

   my(@options, $key, $box, $button_ok, $button_cancel, $table, $label,
         $entry, $rows, @combostrings, $combonsCertType, $combosubjectAltName,
         $combokeyUsage);

   @options = qw(
         authorityKeyIdentifier
         basicConstraints
         issuerAltName
         nsComment
         nsCaRevocationUrl
         nsCaPolicyUrl
         nsRevocationUrl
         nsPolicyUrl
         );

   if(not defined($opts->{'name'})) {
      GUI::HELPERS::print_warning(_("Can't get CA name"));
      return;
   }

   $main->{'TCONFIG'}->init_config($main, $opts->{'name'});

   $button_ok = UI::Stock->button('gtk-ok');
   $button_ok->set_can_default(1);

   $button_ok->signal_connect('clicked',
         sub {
            $main->{'TCONFIG'}->write_config($main, $opts->{'name'});
            $opts->{'configured'} = 1;
            $main->{'CA'}->create_ca($main, $opts, $box, $mode) });


   $button_cancel = UI::Stock->button('gtk-cancel');
   $button_cancel->signal_connect('clicked', sub { $box->destroy() });

   $box = GUI::HELPERS::dialog_box(
         _("CA Configuration"), _("CA Configuration"),
         $button_ok, $button_cancel);


   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $box->get_content_area->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("These Settings are passed to OpenSSL for creating this CA Certificate"),
         'center', 0, 1);
   $box->get_content_area->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("and the CA Certificates of every SubCA, created with this CA."),
         'center', 0, 1);
   $box->get_content_area->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("Multiple Values can be separated by \",\""),
         'center', 0, 0);
   $box->get_content_area->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(' ', 'center', 0, 0);
   $box->get_content_area->pack_start($label, 0, 0, 0);

   $label = GUI::HELPERS::create_label(
         _("If you are unsure: leave the defaults untouched"),
         'center', 0, 0);
   $box->get_content_area->pack_start($label, 0, 0, 0);

   $rows = 1;
   $table = GUI::HELPERS::create_grid();
   $box->get_content_area->add($table);

   # special option keyUsage
   $label = GUI::HELPERS::create_label(
         _("Key Usage (keyUsage):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $main->{'radiobox'} = Gtk3::Box->new('horizontal', 0);
   $main->{'radio1'} = Gtk3::RadioButton->new_with_label(undef,
         _($main->{'words'}{'critical'}));
   if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'} eq 'critical') {
      $main->{'radio1'}->set_active(1)
   }
   $main->{'radio1'}->signal_connect('toggled' =>
         sub{ GUI::CALLBACK::toggle_to_var_pref( $main->{'radio1'},
            \$main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'}, 'critical')});
   $main->{'radiobox'}->add($main->{'radio1'});

   $main->{'radio2'} = Gtk3::RadioButton->new_with_label_from_widget($main->{'radio1'},
         _($main->{'words'}{'noncritical'}));
   if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'} eq 'noncritical') {
      $main->{'radio2'}->set_active(1)
   }
   $main->{'radio2'}->signal_connect('toggled' =>
         sub {GUI::CALLBACK::toggle_to_var_pref($main->{'radio2'},
         \$main->{'TCONFIG'}->{'v3_ca'}->{'keyUsageType'}, 'noncritical')});
   $main->{'radiobox'}->add($main->{'radio2'});

   $combokeyUsage = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = ($main->{'words'}{'none'},
                    $main->{'words'}{'keyCertSign'},
                    $main->{'words'}{'cRLSign'},
                    $main->{'words'}{'keyCertSign, cRLSign'});
   $combokeyUsage->remove_all;
   $combokeyUsage->append_text($_) for @combostrings;
   $combokeyUsage->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'})) {
     if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'}
        ne 'none') {
        $main->{'radio1'}->set_sensitive(1);
        $main->{'radio2'}->set_sensitive(1);

        if($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 'keyCertSign') {
           $combokeyUsage->get_child->set_text($main->{'words'}{'keyCertSign'});
        }elsif($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq 'cRLSign') {
           $combokeyUsage->get_child->set_text($main->{'words'}{'cRLSign'});
        }elsif($main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'} eq
                                                 'keyCertSign, cRLSign') {
           $combokeyUsage->get_child->set_text($main->{'words'}{'keyCertSign, cRLSign'});
        }else {
           $combokeyUsage->get_child->set_text($main->{'words'}{'none'});
           $main->{'radio1'}->set_sensitive(0);
           $main->{'radio2'}->set_sensitive(0);
        }
     }else {
        $combokeyUsage->get_child->set_text($main->{'words'}{'none'});
        $main->{'radio1'}->set_sensitive(0);
        $main->{'radio2'}->set_sensitive(0);
     }
   } else {
      $combokeyUsage->get_child->set_text($main->{'words'}{'none'});
      $main->{'radio1'}->set_sensitive(0);
      $main->{'radio2'}->set_sensitive(0);
   }
   $combokeyUsage->get_child->signal_connect('changed' =>
         sub{&GUI::CALLBACK::entry_to_var_key($combokeyUsage,
            $combokeyUsage->get_child, \$main->{'TCONFIG'}->{'v3_ca'}->{'keyUsage'},
         undef, $main->{words}, $main->{'radio1'},  $main->{'radio2'})});
   $table->attach($combokeyUsage, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   $table->attach($main->{'radiobox'}, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option nsCerttype
   $label = GUI::HELPERS::create_label(
         _("Netscape Certificate Type (nsCertType):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $combonsCertType = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = ($main->{'words'}{'none'},
                    $main->{'words'}{'emailCA'},
                    $main->{'words'}{'sslCA'},
                    $main->{'words'}{'objCA'},
                    $main->{'words'}{'sslCA, emailCA'},
                    $main->{'words'}{'sslCA, objCA'},
                    $main->{'words'}{'emailCA, objCA'},
                    $main->{'words'}{'sslCA, emailCA, objCA'}
                    );
   $combonsCertType->remove_all;
   $combonsCertType->append_text($_) for @combostrings;
   $combonsCertType->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'})) {
      $combonsCertType->get_child->set_text(
            $main->{'words'}{$main->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'}});
   } else {
      $combonsCertType->get_child->set_text($main->{'words'}{'none'});
   }
   $combonsCertType->get_child->signal_connect('changed' =>
         sub{GUI::CALLBACK::entry_to_var($combonsCertType,
         $combonsCertType->get_child, \$main->{'TCONFIG'}->{'v3_ca'}->{'nsCertType'},
         undef, $main->{words})});
   $table->attach($combonsCertType, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   # special option subjectAltName
   $label = GUI::HELPERS::create_label(
         _("Subject alternative name (subjectAltName):"), 'left', 0, 0);
   $table->attach($label, 0, $rows-1, 1, ($rows) - ($rows-1));

   $combosubjectAltName = Gtk3::ComboBoxText->new_with_entry;
   @combostrings = ($main->{'words'}{'none'}, $main->{'words'}{'emailcopy'});
   $combosubjectAltName->remove_all;
   $combosubjectAltName->append_text($_) for @combostrings;
   $combosubjectAltName->set_active(0) if @combostrings;
   if(defined($main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'})) {
     if($main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'}
        eq 'emailcopy') {
        $combosubjectAltName->get_child->set_text($main->{'words'}{'emailcopy'});
     }elsif($main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'}
        eq 'none') {
        $combosubjectAltName->get_child->set_text($main->{'words'}{'none'});
     }
   } else {
      $combosubjectAltName->get_child->set_text($main->{'words'}{'none'});
   }
   $combosubjectAltName->get_child->signal_connect('changed' =>
         sub{GUI::CALLBACK::entry_to_var_san($combosubjectAltName,
         $combosubjectAltName->get_child, \$main->{'TCONFIG'}->{'v3_ca'}->{'subjectAltName'},
         undef, $main->{words})});
   $table->attach($combosubjectAltName, 1, $rows-1, 1, ($rows) - ($rows-1));
   $rows++;

   foreach $key (@options) {
      $entry = GUI::HELPERS::entry_to_table("$key:",
            \$main->{'TCONFIG'}->{'v3_ca'}->{$key}, $table, $rows-1, 1);

      $rows++;
   }

   $box->show_all();

   return;
}

1
