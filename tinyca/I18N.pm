package I18N;

# Gettext wrapper, formalised in Stage 12.
#
# Before this module existed, bin/tinyca2 defined `sub _ { ... }` in
# the main:: namespace and relied on Perl's bareword-fallback to make
# `_("...")` calls in every business / GUI module resolve there. That
# was fragile (no explicit import, no compile-time check, and broken
# under stricter compilers / packagers).
#
# I18N.pm exports `_` as an Exporter symbol. Every module that wants
# `_("...")` should add:
#
#     use I18N qw(_);
#
# The function itself wraps Locale::gettext::gettext() and runs the
# result through utf8::decode() so that UTF-8 strings from .mo files
# end up as proper Perl character data.
#
# Behaviour when gettext is not initialised (test contexts, headless
# runs without an installed locale): gettext() returns the input
# unchanged, utf8::decode() is a no-op on ASCII, and the function
# safely degrades to an identity function.

use strict;
use warnings;
use Exporter qw(import);
use Locale::gettext;

our @EXPORT_OK = qw(_);
our @EXPORT    = qw(_);

{
    # Some Locale::gettext versions pre-define a `_` symbol in the
    # importing package (notably as an alias for gettext). Silence the
    # `Subroutine _ redefined` warning when our explicit definition
    # lands on top of it.
    no warnings 'redefine';
    sub _ {
        my $s = Locale::gettext::gettext(@_);
        utf8::decode($s) if defined $s;
        return $s;
    }
}

#
# `setup_textdomain($domain, $localedir)` — call once early in
# bin/tinyca2 to point gettext at the .mo files. Equivalent to:
#
#     bindtextdomain($domain, $localedir);
#     textdomain($domain);
#
# Centralised here so callers don't have to import Locale::gettext.
#
sub setup_textdomain {
    my (undef, $domain, $localedir) = @_;
    Locale::gettext::bindtextdomain($domain, $localedir) if defined $localedir;
    Locale::gettext::textdomain($domain) if defined $domain;
    return;
}

1;
