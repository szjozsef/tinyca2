package UI::Compat;

# Stage 7: container-class compatibility shims for Gtk2 -> Gtk3.
#
# Several container classes were deprecated or removed in Gtk3:
#
#   Gtk2::HBox          -> Gtk3::Box('horizontal', ...)        (HBox deprecated 3.2)
#   Gtk2::VBox          -> Gtk3::Box('vertical',   ...)        (VBox deprecated 3.2)
#   Gtk2::HSeparator    -> Gtk3::Separator('horizontal')       (HSeparator deprecated 3.10)
#   Gtk2::VSeparator    -> Gtk3::Separator('vertical')         (VSeparator deprecated 3.10)
#   Gtk2::HButtonBox    -> Gtk3::ButtonBox('horizontal')       (HButtonBox deprecated 3.20)
#   Gtk2::VButtonBox    -> Gtk3::ButtonBox('vertical')         (VButtonBox deprecated 3.20)
#   Gtk2::Table         -> Gtk3::Grid                          (Table deprecated 3.4 —
#                                                               different attach API)
#
# The upstream code calls these constructors in ~100 places. Rather than
# edit every call site, this module installs shim `new` methods on the
# old class names that route to the modern Gtk3 equivalents, plus
# translates Table's `attach_defaults` / `set_col_spacing` legacy methods
# into the Grid API.
#
# Use:   `use UI::Compat;`  (the module auto-installs on load).

use strict;
use warnings;

my $installed = 0;

sub install {
    my $class = shift;
    return if $installed;
    $installed = 1;

    no strict 'refs';
    no warnings 'redefine';

    # --- Boxes ------------------------------------------------------
    # Gtk2::HBox->new($homogeneous, $spacing) -> horizontal Gtk3::Box
    *{'Gtk3::HBox::new'} = sub {
        my (undef, $homogeneous, $spacing) = @_;
        my $box = Gtk3::Box->new('horizontal', $spacing // 0);
        $box->set_homogeneous($homogeneous ? 1 : 0);
        return $box;
    };
    *{'Gtk3::VBox::new'} = sub {
        my (undef, $homogeneous, $spacing) = @_;
        my $box = Gtk3::Box->new('vertical', $spacing // 0);
        $box->set_homogeneous($homogeneous ? 1 : 0);
        return $box;
    };

    # --- Separators -------------------------------------------------
    *{'Gtk3::HSeparator::new'} = sub { Gtk3::Separator->new('horizontal') };
    *{'Gtk3::VSeparator::new'} = sub { Gtk3::Separator->new('vertical')   };

    # --- ButtonBoxes ------------------------------------------------
    *{'Gtk3::HButtonBox::new'} = sub { Gtk3::ButtonBox->new('horizontal') };
    *{'Gtk3::VButtonBox::new'} = sub { Gtk3::ButtonBox->new('vertical')   };

    # --- Table -> Grid ---------------------------------------------
    # Gtk2::Table->new($rows, $cols, $homogeneous): returns a Gtk3::Grid
    # configured as homogeneous if requested. The ($rows, $cols) sizing
    # is a no-op under Grid (which auto-sizes).
    *{'Gtk3::Table::new'} = sub {
        my (undef, $rows, $cols, $homogeneous) = @_;
        my $grid = Gtk3::Grid->new;
        if ($homogeneous) {
            $grid->set_row_homogeneous(1);
            $grid->set_column_homogeneous(1);
        }
        return $grid;
    };

    # Graft Gtk2::Table's legacy methods onto every Gtk3::Grid:
    #
    #   attach_defaults($w, $left, $right, $top, $bottom)
    #     -> attach($w, $left, $top, $right - $left, $bottom - $top)
    #
    #   set_col_spacing($col, $spacing)
    #     Gtk2's Table allowed per-column spacing; Gtk3::Grid only
    #     supports a uniform value. We apply the *max* spacing requested
    #     so calls like
    #         $table->set_col_spacing(0, 8)
    #         $table->set_col_spacing(1, 4)
    #     don't accidentally squash the wider gap.
    #
    #   resize($rows, $cols) — no-op under Grid.
    *{'Gtk3::Grid::attach_defaults'} = sub {
        my ($self, $w, $l, $r, $t, $b) = @_;
        $self->attach($w, $l, $t, $r - $l, $b - $t);
    };
    *{'Gtk3::Grid::set_col_spacing'} = sub {
        my ($self, $col, $spacing) = @_;
        my $cur = $self->get_column_spacing;
        if (!defined $cur || $spacing > $cur) {
            $self->set_column_spacing($spacing);
        }
    };
    *{'Gtk3::Grid::resize'} = sub { };

    # --- Combo -> ComboBoxText (Stage 8) ----------------------------
    #
    # Gtk2::Combo (deprecated since 2.4, removed in Gtk3) has been
    # called via Gtk3::Combo->new() in ~20 places. Route those to
    # Gtk3::ComboBoxText->new_with_entry() so the upstream "combo with
    # an editable entry" idiom keeps working.
    #
    # The upstream code uses four legacy methods on the returned object:
    #
    #   $combo->set_popdown_strings(@strs)   -- repopulate the list
    #   $combo->set_use_arrows(1)            -- arrow-key list nav
    #   $combo->set_value_in_list(1, 0)      -- restrict to listed values
    #   $combo->entry                        -- access the inner Entry
    #
    # ComboBoxText doesn't expose any of these. Graft them on:
    *{'Gtk3::Combo::new'} = sub {
        return Gtk3::ComboBoxText->new_with_entry;
    };

    # entry()        : the inner Gtk3::Entry (provided by `new_with_entry`)
    # set_popdown_strings(@strs): rebuild the dropdown list
    # set_use_arrows / set_value_in_list: no-ops under ComboBoxText
    #                  (arrow-key navigation is on by default; list-only
    #                  restriction would need a 'changed' validator we
    #                  intentionally don't add here).
    *{'Gtk3::ComboBoxText::entry'} = sub { $_[0]->get_child };

    *{'Gtk3::ComboBoxText::set_popdown_strings'} = sub {
        my ($self, @strings) = @_;
        $self->remove_all;
        $self->append_text($_) for @strings;
        $self->set_active(0) if @strings;
        return;
    };

    *{'Gtk3::ComboBoxText::set_use_arrows'}    = sub { };
    *{'Gtk3::ComboBoxText::set_value_in_list'} = sub { };

    # --- ImageMenuItem -> MenuItem (Stage 9) ------------------------
    #
    # Gtk3 removed ImageMenuItem (deprecated 3.10). Modern themes
    # generally don't render menu icons anyway, so the simplest faithful
    # shim is: return a plain Gtk3::MenuItem with the same label, and
    # silently accept (but ignore) the set_image() call that follows.
    *{'Gtk3::ImageMenuItem::new'} = sub {
        my (undef, $label) = @_;
        return Gtk3::MenuItem->new_with_mnemonic($label // '');
    };
    *{'Gtk3::MenuItem::set_image'} = sub { };   # no-op under Gtk3

    # --- TextView::modify_font (Stage 10) ---------------------------
    #
    # Deprecated since Gtk3 3.0 in favour of CSS providers + StyleContext.
    # Re-implement as a thin wrapper that loads a per-widget CSS provider.
    # The Pango::FontDescription->to_string output ("Courier 10") doubles
    # as a valid CSS font shorthand.
    *{'Gtk3::TextView::modify_font'} = sub {
        my ($view, $font_desc) = @_;
        return unless defined $font_desc;
        my $css_font;
        eval { $css_font = $font_desc->to_string; 1 } or return;
        return unless defined $css_font && length $css_font;
        my $provider = Gtk3::CssProvider->new;
        eval {
            $provider->load_from_data("textview { font: $css_font; }");
            $view->get_style_context->add_provider(
                $provider,
                Gtk3::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
            1;
        };
    };

    return 1;
}

# ====================================================================
# Gtk3::SimpleMenu — full reconstruction (Stage 9).
#
# Gtk2::SimpleMenu was a convenience class that turned a tree-shaped
# Perl data structure into a populated menubar. The Gtk3 binding has no
# equivalent, but the upstream GUI.pm relies on the data structure being
# usable as-is. Provide the same constructor surface here.
#
# Expected shape of `menu_tree`:
#
#   [
#      "_Label" => {
#          item_type => '<Branch>',
#          children  => [
#              "Sub label" => {
#                  callback   => sub { ... },
#                  item_type  => '<StockItem>',   # ignored under Gtk3
#                  extra_data => 'gtk-foo',       # ignored under Gtk3
#              },
#              "Separator" => { item_type => '<Separator>' },
#              ...
#          ],
#      },
#      ...
#   ]
#
# Returned object exposes `$obj->{widget}` — a populated Gtk3::MenuBar
# ready to pack into the application's outer VBox.
# ====================================================================
package Gtk3::SimpleMenu;

sub new {
    my ($class, %args) = @_;
    my $tree = $args{menu_tree} || [];

    my $self = bless { widget => Gtk3::MenuBar->new }, $class;

    for (my $i = 0; $i + 1 < @$tree; $i += 2) {
        my $label = $tree->[$i];
        my $spec  = $tree->[$i + 1] || {};

        my $item = Gtk3::MenuItem->new_with_mnemonic($label);
        $self->{widget}->append($item);

        if (($spec->{item_type} // '') eq '<Branch>') {
            my $sub = Gtk3::Menu->new;
            $item->set_submenu($sub);
            _populate($sub, $spec->{children} || []);
        }
        elsif ($spec->{callback}) {
            $item->signal_connect(activate => $spec->{callback});
        }
    }

    $self->{widget}->show_all;
    return $self;
}

sub _populate {
    my ($menu, $children) = @_;
    for (my $i = 0; $i + 1 < @$children; $i += 2) {
        my $label = $children->[$i];
        my $spec  = $children->[$i + 1] || {};
        my $type  = $spec->{item_type} // '';

        if ($type eq '<Separator>') {
            $menu->append(Gtk3::SeparatorMenuItem->new);
            next;
        }

        my $item = Gtk3::MenuItem->new_with_mnemonic($label);
        if ($type eq '<Branch>') {
            my $sub = Gtk3::Menu->new;
            $item->set_submenu($sub);
            _populate($sub, $spec->{children} || []);
        }
        elsif ($spec->{callback}) {
            $item->signal_connect(activate => $spec->{callback});
        }
        $menu->append($item);
    }
}

__PACKAGE__->install;

1;
