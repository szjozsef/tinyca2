package UI;

# UI seam — single entry point that business modules use to talk to the
# graphical layer. Introduced in Stage 4 of the GTK3 port.
#
# Goal:
#
#   * Business modules (CA, CERT, REQ, KEY, OpenSSL, HELPERS, TCONFIG)
#     should not name `Gtk3`, `Gtk3`, or any concrete GUI binding.
#   * They call `UI->warning(...)`, `UI->info(...)`, `UI->yield`, etc.,
#     and this module is the ONLY non-GUI file that names Gtk3 / Gtk3.
#
# Why:
#
#   * Stage 5 of the port replaces every `Gtk3::*` / `Gtk3->*` with
#     `Gtk3::*` / `Gtk3->*`. If only this file references Gtk3
#     directly, that's a one-file change — drastically lower risk than
#     touching every business module.
#   * Tests can override individual class methods (e.g.
#     `*UI::warning = sub { ... }`) to capture calls without needing to
#     stub the entire GUI::HELPERS module.
#
# Backwards compatibility:
#
#   * Each method delegates to the existing `GUI::HELPERS` function or
#     to a Gtk3 class method. Production behaviour is unchanged.
#   * Pre-existing `MockGUIHelpers` test fixture continues to work,
#     because UI's defaults route through `GUI::HELPERS::*` which the
#     fixture has hooked.

use strict;
use warnings;

# Note: this file deliberately does NOT `use Gtk3;` — bin/tinyca2 does
# the `use Gtk3 -init;` and tests install a `Gtk3.pm` stub via
# MockGtk. Either way, `Gtk3.pm` is in %INC by the time UI's methods
# are called.

#
# Modal-ish output. The first two are non-fatal; error() is fatal in
# production (GUI::HELPERS::print_error pops a dialog and calls
# HELPERS::exit_clean).
#
sub warning {
    my ($class, @rest) = @_;
    GUI::HELPERS::print_warning(@rest);
}

sub info {
    my ($class, @rest) = @_;
    GUI::HELPERS::print_info(@rest);
}

sub error {
    my ($class, @rest) = @_;
    GUI::HELPERS::print_error(@rest);
}

#
# Status-bar text and busy-cursor toggle. Both take $main as their
# first arg in the GUI::HELPERS signatures.
#
sub status {
    my ($class, @rest) = @_;
    GUI::HELPERS::set_status(@rest);
}

sub cursor {
    my ($class, @rest) = @_;
    GUI::HELPERS::set_cursor(@rest);
}

#
# Pulsing activity-bar dialog used by OpenSSL::newkey. Returns
# ($box, $bar) — the dialog and its embedded ProgressBar.
#
sub activity_bar {
    my ($class, @rest) = @_;
    return GUI::HELPERS::create_activity_bar(@rest);
}

#
# Pump the GUI event queue. Replaces the
#     while (Gtk3->events_pending) { Gtk3->main_iteration }
# idiom sprinkled through business modules.
#
sub yield {
    # Function-call form, NOT method-call. The XS Gtk3 binding rejects a
    # class invocant on these module-level main-loop functions —
    # `Gtk3->events_pending` warns "passed too many parameters" and the
    # return value is unreliable, which leaves the busy-wait spinning
    # forever or returning prematurely.
    while (Gtk3::events_pending()) {
        Gtk3::main_iteration();
    }
}

#
# Pump bytes off a filehandle until EOF, calling $on_data->($chunk) for
# each chunk read. Used by OpenSSL::newkey to feed the activity-bar's
# pulse while openssl generates an RSA/DSA key, without blocking the
# GUI main loop.
#
# Implementation strategy (Stage 11):
#
#   * Production / real Gtk3 binding: use Glib::IO->add_watch on the
#     file descriptor plus a nested Glib::MainLoop. The main loop
#     processes pending GUI events while waiting for openssl's output;
#     the activity-bar dialog stays responsive.
#
#   * Headless / test environment (Glib::IO::add_watch not present):
#     fall back to a plain sysread loop that drains the pipe. This
#     keeps the test suite working under MockGtk and is functionally
#     equivalent for non-interactive callers — the only thing it skips
#     is GUI event processing, which there isn't any of.
#
# Returns the concatenated bytes that were read.
#
sub pump_until_eof {
    my ($class, $fh, $on_data) = @_;

    if (Glib::IO->can('add_watch') && Glib::MainLoop->can('new')) {
        return $class->_pump_glib($fh, $on_data);
    }
    return $class->_pump_sync($fh, $on_data);
}

sub _pump_sync {
    my ($class, $fh, $on_data) = @_;
    my $accum = '';
    while (1) {
        my $bytes = sysread($fh, my $chunk, 4096);
        last unless defined $bytes && $bytes > 0;
        $accum .= $chunk;
        $on_data->($chunk) if $on_data;
    }
    return $accum;
}

sub _pump_glib {
    my ($class, $fh, $on_data) = @_;
    my $loop  = Glib::MainLoop->new;
    my $accum = '';

    Glib::IO->add_watch(
        fileno($fh),
        [ 'in', 'hup', 'err' ],
        sub {
            my $bytes = sysread($fh, my $chunk, 4096);
            if (!defined $bytes || $bytes == 0) {
                $loop->quit;
                return 0;   # remove watch
            }
            $accum .= $chunk;
            $on_data->($chunk) if $on_data;
            return 1;       # keep watching
        },
    );

    $loop->run;
    return $accum;
}

#
# Quit the main loop. Used by HELPERS::exit_clean.
#
sub main_quit { Gtk3::main_quit() }

#
# Set the root-window cursor shape. Used by HELPERS::exit_clean to
# clear the busy cursor before exit.
#
sub root_window_cursor {
    my ($class, $shape) = @_;
    # NOTE: function-call form for `get_default_root_window`, NOT method-
    # call. The XS Gtk3 binding rejects a class invocant on Gdk
    # module-level functions; `Gtk3::Gdk->get_default_root_window()`
    # warns "passed too many parameters" and returns garbage.
    # The cursor shape change is cosmetic — wrap in eval so the app
    # keeps running if the binding has trouble with deprecated APIs
    # like the cursor-name lookup.
    eval {
        my $w = Gtk3::Gdk::get_default_root_window();
        my $c = Gtk3::Gdk::Cursor->new($shape);
        $w->set_cursor($c) if $w;
        1;
    };
}

1;
