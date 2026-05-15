package UI::Stock;

# Stock-item shim — Gtk3 removed the GtkStock API (deprecated 3.10,
# fully gone). The upstream codebase has ~100 call sites that read like:
#
#     Gtk2::Button->new_from_stock('gtk-ok')
#     Gtk2::ToolButton->new_from_stock('gtk-quit')
#     Gtk2::Image->new_from_stock('gtk-save', 'menu')
#
# After Stage 5 those names became Gtk3::*, but the methods don't exist
# on Gtk3, so every such call would die at runtime.
#
# This module installs `new_from_stock` shims on `Gtk3::Button`,
# `Gtk3::ToolButton`, and `Gtk3::Image` that translate the legacy
# `'gtk-foo'` IDs to a mnemonic label plus a themed icon name (Freedesktop
# icon-naming-spec). Call sites need no edits — they keep reading
# `new_from_stock('gtk-quit')` and silently get a properly-themed Gtk3
# widget.
#
# Stage 9 will rewrite the menu and popup-menu code; this module is the
# right place to keep adding any "stock-id -> modern" mapping helpers.

use strict;
use warnings;

#
# Map: legacy stock id => [ mnemonic label, themed-icon name or undef ]
#
my %STOCK = (
    'gtk-ok'               => [ '_OK',                undef                 ],
    'gtk-cancel'           => [ '_Cancel',            undef                 ],
    'gtk-save'             => [ '_Save',              'document-save'       ],
    'gtk-apply'            => [ '_Apply',             undef                 ],
    'gtk-help'             => [ '_Help',              'help-browser'        ],
    'gtk-quit'             => [ '_Quit',              'application-exit'    ],
    'gtk-open'             => [ '_Open',              'document-open'       ],
    'gtk-new'              => [ '_New',               'document-new'        ],
    'gtk-close'            => [ '_Close',             'window-close'        ],
    'gtk-delete'           => [ '_Delete',            'edit-delete'         ],
    'gtk-find'             => [ '_Find',              'edit-find'           ],
    'gtk-find-and-replace' => [ 'Find and _Replace',  'edit-find-replace'   ],
    'gtk-stop'             => [ '_Stop',              'process-stop'        ],
    'gtk-refresh'          => [ '_Refresh',           'view-refresh'        ],
    'gtk-revert-to-saved'  => [ '_Revert',            'document-revert'     ],
    'gtk-properties'       => [ '_Properties',        'document-properties' ],
    'gtk-convert'          => [ 'Convert',            'go-jump'             ],
    'gtk-yes'              => [ '_Yes',               undef                 ],
    'gtk-no'               => [ '_No',                undef                 ],
);

# Class accessors — return label / icon name for a given stock id (or
# the id itself if unknown).
sub label {
    my ($class, $id) = @_;
    return ($STOCK{$id}                  // [ $id, undef ])->[0];
}

sub icon_name {
    my ($class, $id) = @_;
    return ($STOCK{$id} // [ undef, undef ])->[1];
}

#
# Factory helpers — used by the shim methods below; also callable
# directly from code that needs a stock-styled widget.
#
sub button {
    my ($class, $id) = @_;
    my $btn = Gtk3::Button->new_with_mnemonic($class->label($id));
    if (my $icon = $class->icon_name($id)) {
        $btn->set_image(Gtk3::Image->new_from_icon_name($icon, 'button'));
        $btn->set_always_show_image(1);
    }
    return $btn;
}

sub tool_button {
    my ($class, $id) = @_;
    my $btn = Gtk3::ToolButton->new(undef, $class->label($id));
    # Enable mnemonic interpretation of the label so "_Quit" renders as
    # an underlined Q (Alt+Q) instead of the literal underscore.
    $btn->set_use_underline(1);
    if (my $icon = $class->icon_name($id)) {
        $btn->set_icon_name($icon);
    }
    return $btn;
}

sub image {
    my ($class, $id, $size) = @_;
    $size //= 'button';
    my $icon = $class->icon_name($id) // 'image-missing';
    return Gtk3::Image->new_from_icon_name($icon, $size);
}

#
# Stage 16: the auto-installed `new_from_stock` monkey-patches were
# removed. Call the factory methods (`UI::Stock->button(...)` etc.)
# directly instead. This module is now a plain helper, not a shim.

1;
