
from gi.repository import Gtk

class ScanItem(Gtk.Box):

    def __init__(self, scan_data):
        super().__init__(spacing=16)
        self.add_css_class("scan-item")
        self.set_margin_top(0)
        self.set_margin_bottom(0)
        
        self.scan_data = scan_data
        self._build_ui()
    
    def _build_ui(self):

        icon_box = Gtk.Box()
        icon_box.set_valign(Gtk.Align.CENTER)
        icon = Gtk.Label(label="📄")
        icon.set_markup('<span size="16000">📄</span>')
        icon_box.append(icon)
        self.append(icon_box)
        
        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        info_box.set_hexpand(True)
        info_box.set_valign(Gtk.Align.CENTER)
        
        url_label = Gtk.Label(label=self.scan_data.get('url', 'Unknown'))
        url_label.set_halign(Gtk.Align.START)
        url_label.set_ellipsize(3)
        url_label.set_markup(f"<b>{self.scan_data.get('url', 'Unknown')}</b>")
        info_box.append(url_label)
        
        time_label = Gtk.Label(label=self.scan_data.get('start_time', ''))
        time_label.set_halign(Gtk.Align.START)
        time_label.add_css_class("metric-label")
        info_box.append(time_label)
        
        self.append(info_box)
        
        status_box = Gtk.Box()
        status_box.set_valign(Gtk.Align.CENTER)
        
        status = self.scan_data.get('status', 'unknown')
        status_label = Gtk.Label(label=status.upper())
        status_label.set_margin_start(12)
        
        if status == "completed":
            status_label.add_css_class("severity-low")
        elif status == "failed":
            status_label.add_css_class("severity-critical")
        elif status == "running":
            status_label.add_css_class("severity-medium")
        else:
             status_label.add_css_class("metric-label")
        
        status_box.append(status_label)
        self.append(status_box)
