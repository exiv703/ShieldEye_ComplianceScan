
from gi.repository import Gtk

class MetricCard(Gtk.Box):

    def __init__(self, label, value="0", subtitle=""):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.add_css_class("metric-card")
        self.set_size_request(200, 120)
        self.set_hexpand(True)
        
        self.set_tooltip_text(f"{label}: {subtitle}")
        
        self.label_widget = Gtk.Label()
        self.label_widget.set_markup(f'<span size="9500" weight="600" letter_spacing="150" color="#64748B">{label}</span>')
        self.label_widget.set_halign(Gtk.Align.START)
        self.append(self.label_widget)
        
        spacer = Gtk.Box()
        spacer.set_vexpand(True)
        self.append(spacer)
        
        self.value_widget = Gtk.Label()
        self.value_widget.set_markup(f'<span size="32000" weight="800" letter_spacing="-500" color="#60A5FA">{value}</span>')
        self.value_widget.set_halign(Gtk.Align.START)
        self.append(self.value_widget)
        
        subtitle_box = Gtk.Box(spacing=6)
        subtitle_box.set_halign(Gtk.Align.START)
        
        self.subtitle_widget = Gtk.Label()
        self.subtitle_widget.set_markup(f'<span size="10500" color="#9CA3AF">{subtitle}</span>')
        subtitle_box.append(self.subtitle_widget)

        self.info_button = Gtk.Button()
        self.info_button.add_css_class("flat")
        self.info_button.set_can_focus(False)
        self.info_button.set_valign(Gtk.Align.CENTER)

        info_label = Gtk.Label()
        info_label.set_markup('<span size="9000" color="#64748B">ⓘ</span>')
        self.info_button.set_child(info_label)
        self.info_button.set_visible(False)
        subtitle_box.append(self.info_button)
        
        self.append(subtitle_box)
    
    def update(self, value, subtitle=None, color="#60A5FA"):

        self.value_widget.set_markup(f'<span size="32000" weight="800" letter_spacing="-500" color="{color}">{value}</span>')
        if subtitle:
            self.subtitle_widget.set_markup(f'<span size="10500" color="#9CA3AF">{subtitle}</span>')
            self.set_tooltip_text(f"{subtitle}")

    def set_info(self, tooltip_text: str) -> None:

        from gi.repository import Gtk as _Gtk

        popover = _Gtk.Popover()
        popover.set_has_arrow(True)
        popover.set_parent(self.info_button)
        popover.set_autohide(True)

        box = _Gtk.Box(orientation=_Gtk.Orientation.VERTICAL, spacing=6)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        box.set_margin_start(10)
        box.set_margin_end(10)

        label = _Gtk.Label(label=tooltip_text)
        label.set_wrap(True)
        label.set_xalign(0.0)
        box.append(label)

        popover.set_child(box)

        def _on_info_clicked(_button, this_popover=popover):
            this_popover.popup()

        self.info_button.connect("clicked", _on_info_clicked)
        self.info_button.set_visible(True)
