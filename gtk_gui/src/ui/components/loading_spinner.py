
from gi.repository import Gtk, GLib

class LoadingSpinner(Gtk.Box):

    def __init__(self, text="Loading..."):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.set_halign(Gtk.Align.CENTER)
        self.set_valign(Gtk.Align.CENTER)
        self.set_vexpand(True)
        
        self.spinner = Gtk.Spinner()
        self.spinner.set_size_request(48, 48)
        self.append(self.spinner)
        
        self.label = Gtk.Label()
        self.label.set_markup(f'<span size="12000" weight="500" color="#94A3B8">{text}</span>')
        self.append(self.label)
        
        self.add_css_class("pulse")
    
    def start(self, text=None):

        if text:
            self.label.set_markup(f'<span size="12000" weight="500" color="#94A3B8">{text}</span>')
        self.spinner.start()
        self.set_visible(True)
    
    def stop(self):

        self.spinner.stop()
        self.set_visible(False)
    
    def update_text(self, text):

        self.label.set_markup(f'<span size="12000" weight="500" color="#94A3B8">{text}</span>')
