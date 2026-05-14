package MockGtk;

# Minimal Gtk2 / Gtk3 stub used by the non-GUI test suite.
#
# Several business-logic modules (CA.pm, CERT.pm, REQ.pm, OpenSSL.pm) call
# `Gtk2->events_pending` / `Gtk2->main_iteration` to keep the UI responsive
# during long-running openssl invocations. Loading them in a test process
# would normally require libgtk2-perl AND an X display.
#
# This shim:
#
#   * registers fake `Gtk2`, `Gtk2::Gdk`, `Gtk2::Gdk::Cursor` packages whose
#     methods are no-ops, so `use Gtk2;` succeeds without the real binding;
#   * does the same for `Gtk3` so Stage 5+ source files can also be loaded;
#   * is *only* loaded explicitly by tests — it has no effect on a normal
#     run of `bin/tinyca2`.
#
# Call `MockGtk->install` exactly once, before any business module loads.

use strict;
use warnings;

my $installed = 0;

sub install {
    return if $installed;
    $installed = 1;

    # Prevent the real Gtk2/Gtk3 from being loaded later by claiming the
    # %INC slots.
    $INC{'Gtk2.pm'}             ||= __FILE__;
    $INC{'Gtk3.pm'}             ||= __FILE__;
    $INC{'Gtk2/Pango.pm'}       ||= __FILE__;
    $INC{'Gtk2/SimpleMenu.pm'}  ||= __FILE__;
    $INC{'Pango.pm'}            ||= __FILE__;
    $INC{'Glib.pm'}             ||= __FILE__;

    # No-op import for `use Gtk2 '-init'` / `use Gtk3 -init`.
    no strict 'refs';
    for my $pkg (qw(Gtk2 Gtk3 Gtk2::Pango Gtk2::SimpleMenu Pango Glib)) {
        *{"${pkg}::import"} = sub { };
    }

    # The handful of class methods business modules actually call.
    *Gtk2::events_pending      = sub { 0 };
    *Gtk2::main_iteration      = sub { 0 };
    *Gtk2::main                = sub { 0 };
    *Gtk2::main_quit           = sub { 0 };

    *Gtk3::events_pending      = sub { 0 };
    *Gtk3::main_iteration      = sub { 0 };
    *Gtk3::main                = sub { 0 };
    *Gtk3::main_quit           = sub { 0 };

    # Root-window cursor manipulation (HELPERS::exit_clean,
    # GUI::HELPERS::set_cursor).
    *Gtk2::Gdk::get_default_root_window = sub { bless {}, 'MockGtk::Window' };
    *Gtk2::Gdk::Cursor::new             = sub { bless {}, 'MockGtk::Cursor' };
    *Gtk3::Gdk::get_default_root_window = sub { bless {}, 'MockGtk::Window' };
    *Gtk3::Gdk::Cursor::new             = sub { bless {}, 'MockGtk::Cursor' };
    *MockGtk::Window::set_cursor        = sub { };

    # Font description — used by GUI.pm and GUI/X509_browser.pm but not
    # by business modules. Provide a constructor that returns an opaque
    # object so the symbol exists.
    *Gtk2::Pango::FontDescription::from_string = sub { bless {}, 'MockGtk::Font' };
    *Pango::FontDescription::from_string       = sub { bless {}, 'MockGtk::Font' };

    return 1;
}

1;
