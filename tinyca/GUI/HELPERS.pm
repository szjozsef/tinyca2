# Copyright (c) Stephan Martin <sm@sm-zone.net>
#
# $Id: HELPERS.pm,v 1.6 2006/06/28 21:50:42 sm Exp $
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
package GUI::HELPERS;

use POSIX;
use UI::Stock;            # Stage 6: shims `new_from_stock` to themed icons
use I18N qw(_);           # Stage 12: formalised gettext wrapper

#
# Stage 15: build a Gtk3::Grid pre-configured with the margins and
# spacings the legacy `Gtk3::Table` shim applied. Replaces the call
# pattern `Gtk3::Table->new($rows, $cols, $homogeneous)` — Grid grows
# dynamically so the row/col hints are no longer needed.
#
# Pass `homogeneous => 1` to make every column and row the same size
# (the legacy Table->new(.., 1) behaviour). The current codebase never
# uses that, but it's plumbed through for future call sites.
#
sub create_grid {
   my (%opt) = @_;
   my $grid = Gtk3::Grid->new;
   $grid->set_margin_start(10);
   $grid->set_margin_end(10);
   $grid->set_margin_top(5);
   $grid->set_margin_bottom(5);
   $grid->set_column_spacing(12);
   $grid->set_row_spacing(4);
   if ($opt{homogeneous}) {
      $grid->set_row_homogeneous(1);
      $grid->set_column_homogeneous(1);
   }
   return $grid;
}

#
# Stage 13: shared builder for the "Command Details" expander used by
# print_error / print_warning / print_info. Replaces three identical
# inline blocks. Improvements:
#   - monospace font for the openssl command (CSS via StyleContext)
#   - cursor visible + text selectable so Ctrl+C / right-click copy work
#   - both scrollbars allowed (long single-line commands are no longer
#     destructively word-wrapped)
#   - "Copy command" button beside the scrolled view
#   - expander starts open so users see the command immediately
#
sub _make_details_expander {
   my ($ext) = @_;

   my $buffer = Gtk3::TextBuffer->new();
   $buffer->set_text($ext);

   my $text = Gtk3::TextView->new_with_buffer($buffer);
   $text->set_editable(0);
   $text->set_cursor_visible(1);
   $text->set_wrap_mode('char');
   eval { $text->set_left_margin(6); $text->set_right_margin(6); };
   eval { $text->set_top_margin(4);  $text->set_bottom_margin(4);  };

   eval {
      my $css = Gtk3::CssProvider->new;
      $css->load_from_data(
         "textview, textview text { font-family: monospace; font-size: 10pt; }"
      );
      $text->get_style_context->add_provider(
         $css, Gtk3::STYLE_PROVIDER_PRIORITY_USER,
      );
      1;
   };

   my $scrolled = Gtk3::ScrolledWindow->new(undef, undef);
   $scrolled->set_policy('automatic', 'automatic');
   $scrolled->set_shadow_type('etched-in');
   $scrolled->set_min_content_height(120);
   $scrolled->set_min_content_width(500);
   $scrolled->add($text);

   my $copy = Gtk3::Button->new_with_label(_("Copy command"));
   $copy->signal_connect(clicked => sub {
      my $start = $buffer->get_start_iter;
      my $end   = $buffer->get_end_iter;
      my $s     = $buffer->get_text($start, $end, 0);

      # Write to BOTH X selections (CLIPBOARD + PRIMARY) so whichever
      # one the X-to-Windows bridge syncs picks up the text. VcXsrv,
      # X410 and similar may forward only one.
      for my $sel ('CLIPBOARD', 'PRIMARY') {
         my $clip;
         eval {
            my $atom = Gtk3::Gdk::Atom::intern($sel, 0);
            $clip = Gtk3::Clipboard::get($atom);
         };
         $clip->set_text($s, -1) if $clip;
      }

      # Stage 13: fallback escape hatches for users whose X-to-Windows
      # clipboard bridge is unreliable. Both run unconditionally:
      #   - echo the command to STDERR so it's visible in the terminal
      #     that launched tinyca (scroll up / select from there)
      #   - write it to /tmp/tinyca-last-command.txt so it can be
      #     scp'd or read via any other channel
      print STDERR "----- tinyca: Copy command -----\n$s\n",
                   "----- end tinyca command -----\n";
      eval {
         my $f = "/tmp/tinyca-last-command.txt";
         open(my $fh, '>', $f) or die $!;
         print $fh $s;
         close($fh);
      };
   });

   my $hb = Gtk3::Box->new('horizontal', 6);
   $hb->pack_end($copy, 0, 0, 0);

   my $vb = Gtk3::Box->new('vertical', 4);
   $vb->pack_start($scrolled, 1, 1, 0);
   $vb->pack_start($hb,       0, 0, 0);

   my $expander = Gtk3::Expander->new(_("Command Details"));
   $expander->set_expanded(1);
   $expander->add($vb);
   return $expander;
}

#
#  Error message box, kills application
#
sub print_error {
   my ($t, $ext) = @_;

   my ($box, $button, $dbutton, $expander, $text, $scrolled, $buffer);

   $button = UI::Stock->button('gtk-ok');
   $button->signal_connect('clicked', sub { HELPERS::exit_clean(1) });
   $button->set_can_default(1);

   $box = Gtk3::MessageDialog->new(
         undef, [qw/destroy-with-parent modal/], 'error', 'none', $t);
   $box->set_default_size(600, 0);
   $box->set_resizable(1);

   if(defined($ext)) {
      $expander = _make_details_expander($ext);
      $box->get_content_area->add($expander);
   }

   $box->add_action_widget($button, 0);

   $box->show_all();
}

#
#  Warning message box
#
sub print_warning {
   my ($t, $ext) = @_;

   my ($box, $button, $dbutton, $expander, $text, $scrolled, $buffer);

   $button = UI::Stock->button('gtk-ok');
   $button->signal_connect('clicked', sub { $box->destroy() });
   $button->set_can_default(1);

   $box = Gtk3::MessageDialog->new(
         undef, [qw/destroy-with-parent modal/], 'warning', 'none', $t);
   $box->set_default_size(600, 0);
   $box->set_resizable(1);

   if(defined($ext)) {
      $expander = _make_details_expander($ext);
      $box->get_content_area->add($expander);
   }
   $box->add_action_widget($button, 0);

   $box->show_all();

   return;
}

#
#  Info message box
#
sub print_info {
   my ($t, $ext) = @_;

   my ($box, $button, $dbutton, $buffer, $text, $scrolled, $expander);

   $button = UI::Stock->button('gtk-ok');
   $button->signal_connect('clicked', sub { $box->destroy() });
   $button->set_can_default(1);

   $box = Gtk3::MessageDialog->new(
         undef, [qw/destroy-with-parent modal/], 'info', 'none', $t);
   $box->set_default_size(600, 0);
   $box->set_resizable(1);

   if(defined($ext)) {
      $expander = _make_details_expander($ext);
      $box->get_content_area->add($expander);
   }
   $box->add_action_widget($button, 0);

   $box->show_all();

   return;
}

#
# create standard dialog box
#
sub dialog_box {
   my ($title, $text, $button1, $button2) = @_;

   my $box = Gtk3::Dialog->new($title, undef, ["destroy-with-parent"]);

   # Stage 13: on remote X servers (VcXsrv, X410, etc.) the window
   # manager doesn't always stack dialogs above the main window when
   # the parent is undef. Walk the toplevel list to find the main
   # window, set this dialog transient-for it, and mark it modal so
   # the WM is forced to keep it on top.
   eval {
      for my $tl (Gtk3::Window::list_toplevels()) {
         my $title_str = eval { $tl->get_title } // '';
         next unless $title_str =~ /Tiny\s*CA\s*Management/i;
         $box->set_transient_for($tl);
         last;
      }
      $box->set_modal(1);
      1;
   };

   $box->add_action_widget($button1, 0);

   if(defined($button2)) {
      $box->add_action_widget($button2, 0);
      $box->get_action_area->set_layout('spread');
   }

   if(defined($text)) {
      my $label = create_label($text, 'center', 0, 1);
      $box->get_content_area->pack_start($label, 0, 0, 0);
   }

   $box->signal_connect(response => sub { $box->destroy });

   return($box);
}

#
# create standard label
#
sub create_label {
   my ($text, $mode, $wrap, $bold) = @_;

   $text = "<b>$text</b>" if($bold);

   my $label = Gtk3::Label->new($text);

   $label->set_justify($mode);

   # Stage 13: use the modern Gtk3 set_xalign / set_yalign API. The
   # legacy `set_alignment($x, $y)` was deprecated in Gtk 3.14 and is
   # a no-op on some bindings (including libgtk3-perl 0.038 on Debian
   # 12), which left every "left" label visually centred in its cell.
   if($mode eq 'center') {
      $label->set_xalign(0.5);
      $label->set_yalign(0.5);
   } elsif($mode eq 'left') {
      $label->set_xalign(0);
      $label->set_yalign(0);
   } elsif($mode eq 'right') {
      $label->set_xalign(1);
      $label->set_yalign(0);
   }

   # Make labels expand horizontally to fill their cell so they all
   # start at the same x coordinate within Grid columns. Without
   # hexpand the label widget is only as wide as its text, which makes
   # them appear at varying horizontal positions when columns are
   # auto-sized.
   $label->set_hexpand(1);
   $label->set_halign('start') if $mode eq 'left';
   $label->set_halign('end')   if $mode eq 'right';
   $label->set_halign('center') if $mode eq 'center';

   $label->set_line_wrap($wrap);

   $label->set_markup($text) if($bold);

   return($label);
}

#
# write two labels to table
#
sub label_to_table {
   my ($key, $val, $table, $row, $mode, $wrap, $bold) = @_;

   my ($label, $entry);

   $label = create_label($key, $mode, $wrap, $bold);
   $label->set_padding(20, 0);
   $table->attach($label, 0, $row, 1, ($row+1) - ($row));

   $label = create_label($val, $mode, $wrap, $bold);
   $label->set_padding(20, 0);
   $table->attach($label, 1, $row, 1, ($row+1) - ($row));

   $row++;
   return($row);
}

#
# write label and entry to table
#
sub entry_to_table {
   my ($text, $var, $table, $row, $visibility, $box) = @_;

   my ($label, $entry);

   $label = create_label($text, 'left', 0, 0);
   $table->attach($label, 0, $row, 1, ($row+1) - ($row));

   $entry = Gtk3::Entry->new();
   $entry->set_text($$var) if(defined($$var));

   $table->attach($entry, 1, $row, 1, ($row+1) - ($row));
   $entry->signal_connect('changed' =>
         sub {GUI::CALLBACK::entry_to_var($entry, $entry, $var, $box)} );
   $entry->set_visibility($visibility);

   return($entry);
}

#
# sort the table by the clicked column
#
sub sort_clist {
   my ($clist, $col) = @_;

   $clist->set_sort_column($col);
   $clist->sort();

   return(1);
}

sub create_activity_bar {
   my ($t) = @_;

   my($box, $bar);

   $box = Gtk3::MessageDialog->new(
      undef, [qw/destroy-with-parent modal/], 'info', 'none', $t);

   $bar = Gtk3::ProgressBar->new();
   # Stage 13: push a per-widget CSS provider to bump the bar's
   # min-height — `set_size_request` is ignored because the theme
   # CSS pins it to ~3 px on modern Gtk3 themes.
   {
      my $css = Gtk3::CssProvider->new;
      eval {
         $css->load_from_data(
            "progressbar trough, progressbar progress { min-height: 22px; }"
         );
         $bar->get_style_context->add_provider(
            $css, Gtk3::STYLE_PROVIDER_PRIORITY_APPLICATION,
         );
      };
   }
   $bar->pulse();
   $bar->set_pulse_step(0.1);

   $box->get_content_area->add($bar);

   $box->show_all();

   return($box, $bar);
}

#
# set curser busy
#
sub set_cursor {
   my $main = shift;
   my $busy = shift;

   if($busy) {
      $main->{'rootwin'}->set_cursor($main->{'busycursor'});
   } else {
      $main->{'rootwin'}->set_cursor($main->{'cursor'});
   }
   # Stage 13: function-call form. See UI.pm::yield for rationale.
   while(Gtk3::events_pending()) {
      Gtk3::main_iteration();
   }
}

#
# call file chooser
#
sub browse_file {
   my($title, $entry, $mode) = @_;

   my($file_chooser, $filename, $filter);

   # Stage 6: Gtk3 FileChooserDialog wants plain button-text strings, not
   # the legacy 'gtk-cancel' / 'gtk-ok' stock IDs.
   $file_chooser = Gtk3::FileChooserDialog->new ($title, undef, $mode,
         _('_Cancel') => 'cancel',
         _('_OK')     => 'ok');

   $file_chooser->add_shortcut_folder ('/tmp');

   if($mode eq 'open') {
      $filter = Gtk3::FileFilter->new();
      $filter->set_name(_("Request Files (*.pem, *.der, *.req)"));
      $filter->add_pattern("*.pem");
      $filter->add_pattern("*.der");
      $filter->add_pattern("*.req");
      $file_chooser->add_filter($filter);

      $filter = Gtk3::FileFilter->new();
      $filter->set_name(_("All Files (*.*)"));
      $filter->add_pattern("*");
      $file_chooser->add_filter($filter);
   }

   if ('ok' eq $file_chooser->run) {
      $filename = $file_chooser->get_filename();
      $entry->set_text($filename);
   }

   $file_chooser->destroy();
}

#
# set text in statusbar
#
sub set_status {
   my ($main, $t) = @_;

   $main->{'bar'}->pop($main->{'lastid'}) if(defined($main->{'lastid'}));
   $main->{'lastid'} = $main->{'bar'}->get_context_id('gargs');
   $main->{'bar'}->push($main->{'lastid'}, $t);
}

1

__END__

=head1 NAME

GUI::HELPERS - helper functions for TinyCA, doing small jobs related to the
GUI

=head1 SYNOPSIS

 use GUI::HELPERS;

 GUI::HELPERS::print_info($text, $ext);
 GUI::HELPERS::print_warning($text, $ext);
 GUI::HELPERS::print_error($text, $ext);
 GUI::HELPERS::sort_clist($clist, $col);
 GUI::HELPERS::set_cursor($main, $busy);
 GUI::HELPERS::browse_file($main, $entry, $mode);
 GUI::HELPERS::set_status($main, $text);

 $box   = GUI::HELPERS::dialog_box(
       $title, $text, $button1, $button2);
 $label = GUI::HELPERS::create_label(
       $text, $mode, $wrap, $bold);
 $row   = GUI::HELPERS::label_to_table(
       $key, $val, $table, $row, $mode, $wrap, $bold);
 $entry = GUI::HELPERS::entry_to_table(
       $text, $var, $table, $row, $visibility, $box);

=head1 DESCRIPTION

GUI::HELPERS.pm is a library, containing some useful functions used by other
TinyCA2 modules. All functions are related to the GUI.

=head2 GUI::HELPERS::print_info($text, $ext);

=over 1

creates an Gtk3::MessageDialog of the type info. The string given in $text is
shown as message, the (multiline) string $ext is available through the
"Details" Button.

=back

=head2 GUI::HELPERS::print_warning($text, $ext);

=over 1

is identically with GUI::HELPERS::print_warning(), only the
Gtk3::MessageDialog is of type warning.

=back

=head2 GUI::HELPERS::print_error($text, $ext);

=over 1

is identically with GUI::HELPERS::print_info(), only the Gtk3::MessageDialogog
is of type error and the program will shut down after closing the message.

=back

=head2 GUI::HELPERS::sort_clist($clist, $col);

=over 1

sorts the clist with the values from the given column $col.

=back

=head2 GUI::HELPERS::dialog_box($title, $text, $button1, $button2);

=over 1

returns the reference to a new window of type Gtk3::Dialog. $title and
$button1 must be given.  $text and $button2 are optional arguments and can be
undef.

=back

=head2 GUI::HELPERS::create_label($text, $mode, $wrap, $bold);

=over 1

returns the reference to a new Gtk3::Label. $mode can be "center", "left" or
"right". $wrap and $bold are boolean values.

=back

=head2 GUI::HELPERS::label_to_table($key, $val, $table, $row, $mode, $wrap, $bold);

=over 1

adds a new row to $table. The new row is appended at $row and has two columns:
the first will contain a label with the content of string $k, the second the
content of string $v. $mode, $wrap, $bold are the arguments for
GUI::HELPERS::create_label(), mentioned above.
The function returns the number of the next free row in the table.

=back

=head2 GUI::HELPERS::entry_to_table($text, $var, $table, $row, $visibility, $box);

=over 1

adds a new row to $table. The new row is appended at $row and has two columns:
the first will contain a label with the content of the string $text, the
second one will contain a textentry Gtk3::Entry, associated with the variable
$var. $visibility controls, if the entered text will be displayed or not
(passwords).
The function returns the reference to the new created entry.

=back

=head2 GUI::HELPERS::set_cursor($main, $busy);

=over 1

sets the actual cursor to busy or back to normal. The value of $busy is
boolean.
This functions returns nothing;

=back

=head2 GUI::HELPERS::browse_file($main, $entry, $mode);

=over 1

opens a FileChooser dialog to select files or directories. $entry is a
reference to the variable, where the selected path shall be stored. If $mode
is set to "open", then only files with appropriate suffixes are displyed.

=back

=head2 GUI::HELPERS::set_status($main, $text);

=over 1

sets the text in $text to the statusbar at the bottom of the window.

=back

=cut
