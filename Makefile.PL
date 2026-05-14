use strict;
use warnings;
use ExtUtils::MakeMaker 6.64;

WriteMakefile(
    NAME            => 'tinyca2',
    ABSTRACT        => 'TinyCA2 — graphical OpenSSL certificate-authority manager',
    AUTHOR          => 'Stephan Martin <sm@sm-zone.net> and contributors',
    LICENSE         => 'gpl_2',
    VERSION         => '0.8.0',
    MIN_PERL_VERSION => '5.014',

    EXE_FILES       => [ 'bin/tinyca2' ],

    # Runtime requirements. Gtk3 is mandatory once the port is complete;
    # during the staged port, Gtk2 must still resolve until Stage 5 lands.
    PREREQ_PM => {
        'MIME::Base64'      => 0,
        'POSIX'             => 0,
        'Locale::gettext'   => 0,
        'Time::Local'       => 0,
        'IPC::Open3'        => 0,
        'IO::Select'        => 0,
        'Symbol'            => 0,
        # GUI runtime (Gtk3 target):
        'Gtk3'              => 0,
        'Glib'              => 0,
        'Pango'             => 0,
        'Cairo'             => 0,
    },

    TEST_REQUIRES => {
        'Test::More'       => '0.98',
        'Test::Deep'       => '1.120',
        'Test::Exception'  => '0.43',
        'File::Temp'       => 0,
        'File::Path'       => 0,
        'File::Copy'       => 0,
    },

    test => { TESTS => 't/*.t' },

    META_MERGE => {
        'meta-spec' => { version => 2 },
        resources => {
            repository => {
                type => 'git',
                url  => 'https://github.com/szjozsef/tinyca2.git',
                web  => 'https://github.com/szjozsef/tinyca2',
            },
        },
        no_index => { directory => [ 'xt', 't/lib', '.claude' ] },
    },
);
