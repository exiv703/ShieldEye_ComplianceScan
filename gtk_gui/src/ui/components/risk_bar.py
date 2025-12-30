
from gi.repository import Gtk

class RiskBar(Gtk.Box):

    def __init__(self, label, count=0, color="#38BDF8"):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.set_margin_top(8)
        self.set_margin_bottom(8)
        
        self.label_text = label
        self.color = color
        
        header = Gtk.Box(spacing=8)
        
        self.label_widget = Gtk.Label(label=label)
        self.label_widget.set_halign(Gtk.Align.START)
        self.label_widget.set_hexpand(True)
        self.label_widget.set_markup(f"<b>{label}</b>")
        header.append(self.label_widget)
        
        self.count_label = Gtk.Label(label=str(count))
        self.count_label.add_css_class("metric-label")
        self.count_label.set_markup(f"<b>{count}</b>")
        header.append(self.count_label)
        
        self.append(header)
        
        progress_container = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        progress_container.set_size_request(-1, 6)
        
        self.progress = Gtk.ProgressBar()
        self.progress.set_fraction(0.0)
        self.progress.set_show_text(False)
        self.progress.set_hexpand(True)
        self.progress.set_valign(Gtk.Align.CENTER)
        
        if "Critical" in label:
            self.progress.add_css_class("progress-critical")
        elif "High" in label:
            self.progress.add_css_class("progress-high")
        elif "Medium" in label:
            self.progress.add_css_class("progress-medium")
        elif "Low" in label:
            self.progress.add_css_class("progress-low")
        
        progress_container.append(self.progress)
        self.append(progress_container)
    
    def update(self, count, total=100):

        self.count_label.set_text(str(count))
        
        if total > 0:
            fraction = min(count / total, 1.0)
        else:
            fraction = 0.0
        
        self.progress.set_fraction(fraction)
