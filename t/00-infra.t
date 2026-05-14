#!perl
# Smoke test: the test infrastructure itself (Stage 0).
#
# Confirms that:
#   * required test modules load,
#   * the test helpers (MockGtk, MockGUIHelpers, TestCA) load,
#   * MockGtk really keeps `use Gtk2` from blowing up in a headless process,
#   * MockGUIHelpers really intercepts GUI::HELPERS calls,
#   * TestCA can stand up a temp CA root and copy the openssl.cnf template.
#
# This file does NOT touch any tinyca/ source module — it only validates the
# scaffolding. Stage-1 tests start exercising the real code.

use strict;
use warnings;
use Test::More;
use Test::Deep;
use Test::Exception;

use FindBin ();
use lib "$FindBin::Bin/lib";
use lib "$FindBin::Bin/../tinyca";

use_ok('MockGtk')          or BAIL_OUT('MockGtk failed to load');
use_ok('MockGUIHelpers')   or BAIL_OUT('MockGUIHelpers failed to load');
use_ok('TestCA')           or BAIL_OUT('TestCA failed to load');

MockGtk->install;
MockGUIHelpers->install;

# After install, `use Gtk2;` must not require the real binding.
lives_ok( sub { eval 'use Gtk2; 1' or die $@ }, 'use Gtk2 after MockGtk install' );
is( Gtk2->events_pending, 0, 'Gtk2->events_pending stub returns 0' );

# GUI::HELPERS hooks intercept calls.
MockGUIHelpers->reset;
GUI::HELPERS::print_warning('hello world');
my @warnings = MockGUIHelpers->calls('warning');
is( scalar @warnings, 1, 'one warning recorded' );
is( $warnings[0]->{args}[0], 'hello world', 'warning text round-trips' );

# print_error dies (mimics the real module's fatal behaviour).
throws_ok( sub { GUI::HELPERS::print_error('boom') }, qr/boom/, 'print_error dies' );

# TestCA stands up a real tempdir with the openssl.cnf template installed.
my $ca = TestCA->new;
ok( -d $ca->root,                                  'TestCA root exists' );
ok( -d $ca->export_dir,                            'export_dir exists' );
ok( -d $ca->template_dir,                          'template_dir exists' );
ok( -f "${\$ca->template_dir}/openssl.cnf",        'template/openssl.cnf was copied in' );

my $init = $ca->init_hash;
is( $init->{opensslbin}, '/usr/bin/openssl', 'init_hash has opensslbin' );
is( $init->{basedir},    $ca->root,          'init_hash basedir matches root' );

# round-trip read/write
my $f = "${\$ca->root}/scratch.txt";
$ca->writefile($f, "hello\n");
is( $ca->readfile($f), "hello\n", 'TestCA write/read round-trip' );

done_testing();
