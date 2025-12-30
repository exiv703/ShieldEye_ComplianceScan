
from gi.repository import Gtk, Pango

class Sidebar(Gtk.Box):

    def __init__(self, on_page_changed=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add_css_class("sidebar")
        self.set_size_request(220, -1)
        self.set_hexpand(False)
        
        self.on_page_changed = on_page_changed
        self.active_button = None
        
        self._build_ui()
    
    def _build_ui(self):

        header = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        header.set_margin_top(20)
        header.set_margin_bottom(20)
        header.set_margin_start(16)
        header.set_margin_end(16)
        
        logo_label = Gtk.Label()
        logo_label.set_markup('<span size="12000" weight="800" letter_spacing="100">ShieldEye</span>')
        logo_label.set_halign(Gtk.Align.START)
        logo_label.set_ellipsize(Pango.EllipsizeMode.END)
        header.append(logo_label)
        
        subtitle = Gtk.Label(label="ComplianceScan")
        subtitle.set_halign(Gtk.Align.START)
        subtitle.add_css_class("sidebar-subtitle")
        subtitle.set_ellipsize(Pango.EllipsizeMode.END)
        subtitle.set_opacity(0.65)
        header.append(subtitle)
        
        self.append(header)
        
        nav_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        nav_box.set_margin_start(12)
        nav_box.set_margin_end(12)
        nav_box.set_margin_top(8)
        
        self.dashboard_btn = self._create_nav_button("Dashboard", "dashboard", True)
        nav_box.append(self.dashboard_btn)
        
        self.scan_btn = self._create_nav_button("Scan", "scan")
        nav_box.append(self.scan_btn)
        
        self.history_btn = self._create_nav_button("History", "history")
        nav_box.append(self.history_btn)
        
        self.append(nav_box)
        
        spacer = Gtk.Box()
        spacer.set_vexpand(True)
        self.append(spacer)
        
        self.stats_box = self._create_quick_stats()
        self.stats_box.set_margin_top(8)
        self.append(self.stats_box)
        
        self.status_box = self._create_system_status()
        self.append(self.status_box)
    
    def _create_nav_button(self, label_text, page_name, active=False):

        btn = Gtk.Button()
        btn.add_css_class("flat")
        
        label = Gtk.Label(label=label_text)
        label.set_halign(Gtk.Align.START)
        label.set_ellipsize(Pango.EllipsizeMode.END)
        label.set_max_width_chars(10)
        label.set_hexpand(True)
        btn.set_child(label)
        
        btn.add_css_class("sidebar-item")
        if active:
            btn.add_css_class("active")
            self.active_button = btn
        
        btn.connect("clicked", lambda b: self._on_nav_clicked(b, page_name))
        return btn
    
    def _on_nav_clicked(self, button, page_name):

        if self.active_button:
            self.active_button.remove_css_class("active")
        
        button.add_css_class("active")
        self.active_button = button
        
        if self.on_page_changed:
            self.on_page_changed(page_name)
    
    def _create_quick_stats(self):

        stats_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        stats_box.set_margin_start(16)
        stats_box.set_margin_end(16)
        stats_box.set_margin_bottom(20)
        
        title = Gtk.Label(label="Quick Stats")
        title.set_halign(Gtk.Align.START)
        title.add_css_class("sidebar-section-title")
        title.set_margin_bottom(4)
        stats_box.append(title)
        
        self.total_scans_label = Gtk.Label()
        self.total_scans_label.set_markup('<span size="13000" weight="bold">0</span>')
        self.total_scans_label.set_halign(Gtk.Align.START)
        stats_box.append(self.total_scans_label)
        
        scans_label = Gtk.Label(label="Scans")
        scans_label.set_halign(Gtk.Align.START)
        scans_label.add_css_class("sidebar-stat-label")
        scans_label.set_margin_bottom(8)
        stats_box.append(scans_label)
        
        self.threats_label = Gtk.Label()
        self.threats_label.set_markup('<span size="13000" weight="bold" color="#9CA3AF">0</span>')
        self.threats_label.set_halign(Gtk.Align.START)
        stats_box.append(self.threats_label)
        
        threats_row = Gtk.Box(spacing=4)
        threats_row.set_halign(Gtk.Align.START)

        threats_label = Gtk.Label(label="Threats")
        threats_label.set_halign(Gtk.Align.START)
        threats_label.add_css_class("sidebar-stat-label")
        threats_row.append(threats_label)

        threats_button = Gtk.Button()
        threats_button.add_css_class("flat")
        threats_button.set_can_focus(False)
        threats_button.set_valign(Gtk.Align.CENTER)

        threats_info_label = Gtk.Label()
        threats_info_label.set_markup('<span size="9000" color="#64748B">ⓘ</span>')
        threats_button.set_child(threats_info_label)

        popover = Gtk.Popover()
        popover.set_has_arrow(True)
        popover.set_parent(threats_button)
        popover.set_autohide(True)

        pop_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        pop_box.set_margin_top(8)
        pop_box.set_margin_bottom(8)
        pop_box.set_margin_start(10)
        pop_box.set_margin_end(10)

        pop_text = Gtk.Label(label=(
            "Total number of findings (critical, high, medium and low) "
            "across all stored scans."
        ))
        pop_text.set_wrap(True)
        pop_text.set_xalign(0.0)
        pop_box.append(pop_text)

        popover.set_child(pop_box)

        def _on_threats_info_clicked(_button, this_popover=popover):
            this_popover.popup()

        threats_button.connect("clicked", _on_threats_info_clicked)
        threats_row.append(threats_button)

        stats_box.append(threats_row)
        
        return stats_box
    
    def _create_system_status(self):

        status_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        status_box.set_margin_start(16)
        status_box.set_margin_end(16)
        status_box.set_margin_bottom(20)
        
        title = Gtk.Label(label="System Status")
        title.set_halign(Gtk.Align.START)
        title.add_css_class("sidebar-section-title")
        title.set_margin_bottom(4)
        status_box.append(title)
        
        scanner_box = Gtk.Box(spacing=8)
        scanner_label = Gtk.Label(label="Scanner")
        scanner_label.set_halign(Gtk.Align.START)
        scanner_label.set_hexpand(True)
        scanner_label.add_css_class("sidebar-stat-label")
        scanner_box.append(scanner_label)
        
        self.scanner_status_label = Gtk.Label()
        self.scanner_status_label.set_markup('<span color="#10B981">●</span> Healthy')
        self.scanner_status_label.add_css_class("sidebar-stat-label")
        self.scanner_status_label.add_css_class("status-indicator")
        scanner_box.append(self.scanner_status_label)
        
        status_box.append(scanner_box)
        
        db_box = Gtk.Box(spacing=8)
        db_label = Gtk.Label(label="Database")
        db_label.set_halign(Gtk.Align.START)
        db_label.set_hexpand(True)
        db_label.add_css_class("sidebar-stat-label")
        db_box.append(db_label)
        
        self.db_status_label = Gtk.Label()
        self.db_status_label.set_markup('<span color="#10B981">●</span> Ready')
        self.db_status_label.add_css_class("sidebar-stat-label")
        db_box.append(self.db_status_label)
        
        status_box.append(db_box)
        
        return status_box
    
    def update_stats(self, total_scans, threats_found):

        self.total_scans_label.set_markup(f'<span size="13000" weight="bold">{total_scans}</span>')
        self.threats_label.set_markup(f'<span size="13000" weight="bold" color="#9CA3AF">{threats_found}</span>')

    def update_system_status(self, scanner_ok: bool, db_ok: bool) -> None:

        if scanner_ok:
            scanner_text = '<span color="#10B981">●</span> Healthy'
        else:
            scanner_text = '<span color="#9CA3AF">●</span> Degraded'
        self.scanner_status_label.set_markup(scanner_text)

        if db_ok:
            db_text = '<span color="#10B981">●</span> Ready'
        else:
            db_text = '<span color="#9CA3AF">●</span> Error'
        self.db_status_label.set_markup(db_text)
