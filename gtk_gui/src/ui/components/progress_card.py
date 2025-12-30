
from gi.repository import Gtk, GLib

class ProgressCard(Gtk.Box):

    def __init__(self, title="Processing..."):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.add_css_class("card")
        self.add_css_class("progress-card")
        self.set_size_request(-1, 160)
        
        self.title_label = Gtk.Label()
        self.title_label.set_markup(f'<span size="13000" weight="600" color="#E2E8F0">{title}</span>')
        self.title_label.set_halign(Gtk.Align.START)
        self.append(self.title_label)
        
        info_box = Gtk.Box(spacing=12)
        
        self.percentage_label = Gtk.Label()
        self.percentage_label.set_markup('<span size="32000" weight="800" color="#3B82F6">0%</span>')
        info_box.append(self.percentage_label)
        
        separator = Gtk.Separator(orientation=Gtk.Orientation.VERTICAL)
        separator.set_margin_top(8)
        separator.set_margin_bottom(8)
        info_box.append(separator)
        
        self.status_label = Gtk.Label()
        self.status_label.set_markup('<span size="11000" color="#94A3B8">Initializing...</span>')
        self.status_label.set_halign(Gtk.Align.START)
        self.status_label.set_hexpand(True)
        self.status_label.set_wrap(True)
        info_box.append(self.status_label)
        
        self.append(info_box)
        
        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_show_text(False)
        self.progress_bar.add_css_class("compliance-progress")
        self.append(self.progress_bar)
        
        self.time_label = Gtk.Label()
        self.time_label.set_markup('<span size="9500" color="#64748B">Estimated time remaining: calculating...</span>')
        self.time_label.set_halign(Gtk.Align.START)
        self.append(self.time_label)
    
    def update(self, percentage, status_text=None, time_remaining=None):

        fraction = min(max(percentage / 100.0, 0.0), 1.0)
        self.progress_bar.set_fraction(fraction)
        
        if percentage < 30:
            color = "#3B82F6"
        elif percentage < 70:
            color = "#60A5FA"
        else:
            color = "#10B981"
        
        self.percentage_label.set_markup(f'<span size="32000" weight="800" color="{color}">{int(percentage)}%</span>')
        
        if status_text:
            self.status_label.set_markup(f'<span size="11000" color="#94A3B8">{status_text}</span>')
        
        if time_remaining is not None:
            if time_remaining < 60:
                time_str = f"{int(time_remaining)}s"
            else:
                mins = int(time_remaining / 60)
                secs = int(time_remaining % 60)
                time_str = f"{mins}m {secs}s"
            
            self.time_label.set_markup(f'<span size="9500" color="#64748B">Time remaining: ~{time_str}</span>')
    
    def set_title(self, title):

        self.title_label.set_markup(f'<span size="13000" weight="600" color="#E2E8F0">{title}</span>')
    
    def pulse(self):

        self.progress_bar.pulse()
    
    def complete(self, message="Complete!"):

        self.progress_bar.set_fraction(1.0)
        self.percentage_label.set_markup('<span size="32000" weight="800" color="#10B981">100%</span>')
        self.status_label.set_markup(f'<span size="11000" color="#10B981">✓ {message}</span>')
        self.time_label.set_markup('<span size="9500" color="#10B981">Completed successfully</span>')
    
    def error(self, message="An error occurred"):

        self.percentage_label.set_markup('<span size="32000" weight="800" color="#EF4444">✗</span>')
        self.status_label.set_markup(f'<span size="11000" color="#EF4444">{message}</span>')
        self.time_label.set_markup('<span size="9500" color="#EF4444">Scan failed</span>')
