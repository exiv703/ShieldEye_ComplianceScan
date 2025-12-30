
from gi.repository import Gtk
from ..components import ScanItem

class HistoryView(Gtk.ScrolledWindow):

    def __init__(self, db):
        super().__init__()
        self.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        
        self.db = db
        self._build_ui()
    
    def _build_ui(self):

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        main_box.set_margin_top(32)
        main_box.set_margin_bottom(32)
        main_box.set_margin_start(32)
        main_box.set_margin_end(32)
        
        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        title = Gtk.Label()
        title.set_markup('<span size="28000" weight="800">Scan History</span>')
        title.set_halign(Gtk.Align.START)
        title_box.append(title)
        
        subtitle = Gtk.Label(label="View and manage previous security scans")
        subtitle.set_halign(Gtk.Align.START)
        subtitle.add_css_class("dashboard-subtitle")
        title_box.append(subtitle)
        
        main_box.append(title_box)
        
        self.history_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.history_box.set_margin_top(8)
        main_box.append(self.history_box)
        
        self.set_child(main_box)
    
    def refresh_data(self):

        try:
            scans = self.db.get_scans(limit=50)

            while child := self.history_box.get_first_child():
                self.history_box.remove(child)

            if not scans:
                no_scans = Gtk.Label(label="No scans in history yet.")
                no_scans.add_css_class("metric-label")
                self.history_box.append(no_scans)
                return

            for scan in scans:
                scan_data = {
                    'url': scan.get('url', 'Unknown'),
                    'start_time': scan.get('start_time', 'Unknown'),
                    'status': scan.get('status', 'unknown'),
                    'score': scan.get('score', 0),
                    'pages_scanned': scan.get('pages_scanned', 0)
                }
                scan_item = ScanItem(scan_data)
                self.history_box.append(scan_item)

        except Exception as e:
            print(f"Error loading history: {e}")
            import traceback
            traceback.print_exc()
