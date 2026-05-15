#!/usr/bin/perl
#
# Stage 14+: headless Gtk3 smoke test.
#
# Runs under Xvfb (or any real X11 display) and verifies that:
#   - all GUI-side modules load without syntax / runtime errors
#   - the native Gtk3 widget API the modernization refactor relies on
#     still works (Box / Grid / Separator / ButtonBox / MenuItem / etc.)
#   - any remaining UI::Compat shims still behave consistently
#
# Run with:
#   xvfb-run -a prove -lr -Itinyca t/40-gtk3-smoke.t
# or set DISPLAY=:0 (or whatever your local X is) and run prove directly.
#
# Skipped automatically if no DISPLAY is set, or if Gtk3 / Glib::Object::Introspection
# isn't installed. Both conditions are typical of CI shards that don't
# have Xvfb running and shouldn't fail the suite.

use strict;
use warnings;

use Test::More;
use File::Temp qw(tempdir);

BEGIN {
    plan skip_all => "no DISPLAY set (run under xvfb-run or with a live X server)"
        unless $ENV{DISPLAY};
}

eval { require Gtk3; Gtk3->import('-init'); 1 }
    or plan skip_all => "Gtk3 not available: $@";

# ---------------------------------------------------------------------------
# Module load coverage. If any of these fail to compile or `use` something
# missing, the refactor broke a dependency.
# ---------------------------------------------------------------------------
my @load = qw(
    UI
    UI::Compat
    UI::Stock
    HELPERS
    I18N
    GUI::HELPERS
    GUI::WORDS
    GUI::CALLBACK
    GUI::X509_infobox
    GUI::X509_browser
    GUI::TCONFIG
    OpenSSL
    CA
    CERT
    REQ
    KEY
    TCONFIG
    GUI
);

for my $mod (@load) {
    use_ok($mod) or BAIL_OUT("module load failed: $mod");
}

# ---------------------------------------------------------------------------
# Native Gtk3 widget creation. These should always succeed on Gtk3.x —
# if any fails after a refactor stage, we've broken the native API path.
# ---------------------------------------------------------------------------
ok( Gtk3::Box->new('horizontal', 0),         'native Gtk3::Box horizontal' );
ok( Gtk3::Box->new('vertical',   6),         'native Gtk3::Box vertical' );
ok( Gtk3::Separator->new('horizontal'),      'native Gtk3::Separator horizontal' );
ok( Gtk3::Separator->new('vertical'),        'native Gtk3::Separator vertical' );
ok( Gtk3::ButtonBox->new('horizontal'),      'native Gtk3::ButtonBox horizontal' );
ok( Gtk3::Grid->new,                         'native Gtk3::Grid' );
ok( Gtk3::Label->new('x'),                   'Gtk3::Label' );
ok( Gtk3::Button->new_with_label('OK'),      'Gtk3::Button new_with_label' );
ok( Gtk3::Entry->new,                        'Gtk3::Entry' );
ok( Gtk3::TextBuffer->new,                   'Gtk3::TextBuffer' );
ok( Gtk3::ComboBoxText->new,                 'Gtk3::ComboBoxText' );
ok( Gtk3::MenuItem->new_with_label('m'),     'Gtk3::MenuItem new_with_label' );
ok( Gtk3::Menu->new,                         'Gtk3::Menu' );
ok( Gtk3::MenuBar->new,                      'Gtk3::MenuBar' );
ok( Gtk3::Window->new('toplevel'),           'Gtk3::Window toplevel' );

# Grid attach (the post-Table API): col 0 row 0 width 1 height 1.
{
    my $g = Gtk3::Grid->new;
    my $l = Gtk3::Label->new('cell');
    eval { $g->attach($l, 0, 0, 1, 1); 1 };
    ok( !$@, "Gtk3::Grid::attach(widget, col, row, w, h)" ) or diag $@;
}

# Image from themed icon name (post-stock-item API).
{
    my $img = eval { Gtk3::Image->new_from_icon_name('document-new', 'menu') };
    ok( defined $img, 'Gtk3::Image::new_from_icon_name' );
}

# Dialog content_area / action_area accessors (modern names).
{
    my $d = Gtk3::Dialog->new();
    ok( $d->get_content_area, 'Gtk3::Dialog::get_content_area' );
    ok( $d->get_action_area,  'Gtk3::Dialog::get_action_area'  );
    $d->destroy;
}

# Widget set_can_default (replaces the can_default shim).
{
    my $b = Gtk3::Button->new_with_label('x');
    eval { $b->set_can_default(1); 1 };
    ok( !$@, 'Gtk3::Widget::set_can_default' ) or diag $@;
}

# RadioButton new_with_label_from_widget — the modern grouping API.
{
    my $r1 = Gtk3::RadioButton->new_with_label(undef, 'one');
    my $r2 = eval { Gtk3::RadioButton->new_with_label_from_widget($r1, 'two') };
    ok( defined $r2, 'Gtk3::RadioButton::new_with_label_from_widget' );
}

# CssProvider + StyleContext add_provider (modern way to set fonts/colors).
{
    my $css = Gtk3::CssProvider->new;
    eval {
        $css->load_from_data("label { font-family: monospace; font-size: 10pt; }");
        1;
    };
    ok( !$@, 'CssProvider load_from_data' ) or diag $@;
}

done_testing();
