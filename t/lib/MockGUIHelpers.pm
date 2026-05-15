package MockGUIHelpers;

# In-memory replacement for the GUI::HELPERS module.
#
# Business modules call GUI::HELPERS::print_warning / print_info / print_error
# / set_cursor / set_status / create_activity_bar from many paths. The real
# module pops up Gtk dialogs and spins the main loop — useless in a headless
# test process.
#
# This shim:
#
#   * registers the GUI::HELPERS package with the same exported function
#     names that the source tree expects;
#   * stores every call in @MockGUIHelpers::calls so tests can inspect what
#     happened ($call->{kind} eq 'warning', $call->{args} => [...]);
#   * makes create_activity_bar / set_cursor / set_status into harmless
#     no-ops that return enough of a hash to satisfy callers.
#
# To use:
#
#     use lib 't/lib';
#     use MockGUIHelpers;        # also `use`d before any business module
#     MockGUIHelpers->install;
#
# Then later in a test:
#
#     MockGUIHelpers->reset;
#     ... call business code ...
#     my @warnings = MockGUIHelpers->calls('warning');

use strict;
use warnings;

our @calls;
my $installed = 0;

sub install {
    return if $installed;
    $installed = 1;

    $INC{'GUI/HELPERS.pm'} ||= __FILE__;

    no strict 'refs';
    *GUI::HELPERS::print_warning      = sub { _record(warning => @_) };
    *GUI::HELPERS::print_info         = sub { _record(info    => @_) };
    *GUI::HELPERS::print_error        = sub { _record(error   => @_); die "MockGUIHelpers::error: $_[0]\n" };
    *GUI::HELPERS::set_cursor         = sub { _record(cursor  => @_) };
    *GUI::HELPERS::set_status         = sub { _record(status  => @_) };
    *GUI::HELPERS::dialog_box         = sub { _record(dialog  => @_); return 1 };
    *GUI::HELPERS::create_label       = sub { _record(label   => @_); return bless {}, 'MockGUIHelpers::Widget' };
    *GUI::HELPERS::label_to_table     = sub { _record(l2t     => @_) };
    *GUI::HELPERS::entry_to_table     = sub { _record(e2t     => @_); return bless {}, 'MockGUIHelpers::Widget' };
    *GUI::HELPERS::sort_clist         = sub { _record(sort    => @_) };
    *GUI::HELPERS::browse_file        = sub { _record(browse  => @_); return undef };
    # Real GUI::HELPERS::create_activity_bar returns ($box, $bar) — a
    # MessageDialog plus the embedded Gtk2::ProgressBar. Callers do:
    #     ($box, $bar) = GUI::HELPERS::create_activity_bar(...);
    #     $bar->pulse(); ... $box->destroy();
    # Honour that two-value contract here.
    *GUI::HELPERS::create_activity_bar = sub {
        _record(activitybar => @_);
        my $box = bless {}, 'MockGUIHelpers::Box';
        my $bar = bless {}, 'MockGUIHelpers::Bar';
        return ($box, $bar);
    };

    *MockGUIHelpers::Bar::pulse      = sub { };
    *MockGUIHelpers::Bar::destroy    = sub { };
    *MockGUIHelpers::Box::destroy    = sub { };
    *MockGUIHelpers::Widget::destroy = sub { };

    return 1;
}

sub _record {
    my ($kind, @args) = @_;
    push @calls, { kind => $kind, args => [ @args ] };
}

sub reset {
    @calls = ();
}

sub calls {
    my ($class, $kind) = @_;
    return @calls unless defined $kind;
    return grep { $_->{kind} eq $kind } @calls;
}

1;
