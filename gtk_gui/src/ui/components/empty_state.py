
from gi.repository import Gtk

class EmptyState(Gtk.Box):

    def __init__(self, icon="📭", title="No data yet", description="", action_label=None, action_callback=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        self.set_halign(Gtk.Align.CENTER)
        self.set_valign(Gtk.Align.CENTER)
        self.set_vexpand(True)
        self.add_css_class("empty-state")
        
        icon_label = Gtk.Label()
        icon_label.set_markup(f'<span size="48000">{icon}</span>')
        self.append(icon_label)
        
        title_label = Gtk.Label()
        title_label.set_markup(f'<span size="14000" weight="600" color="#E2E8F0">{title}</span>')
        self.append(title_label)
        
        if description:
            desc_label = Gtk.Label()
            desc_label.set_markup(f'<span size="11000" color="#64748B">{description}</span>')
            desc_label.set_wrap(True)
            desc_label.set_max_width_chars(40)
            desc_label.set_justify(Gtk.Justification.CENTER)
            self.append(desc_label)
        
        if action_label and action_callback:
            button = Gtk.Button(label=action_label)
            button.add_css_class("btn-primary")
            button.set_margin_top(8)
            button.connect("clicked", action_callback)
            self.append(button)

class EmptyStatePresets:

    @staticmethod
    def no_scans():
        return EmptyState(
            icon="🔍",
            title="No scans yet",
            description="Start your first security scan to see compliance results here"
        )
    
    @staticmethod
    def no_history():
        return EmptyState(
            icon="📊",
            title="No scan history",
            description="Your scan history will appear here after running scans"
        )
    
    @staticmethod
    def no_results():
        return EmptyState(
            icon="✨",
            title="No results found",
            description="Try adjusting your filters or running a new scan"
        )
    
    @staticmethod
    def no_vulnerabilities():
        return EmptyState(
            icon="🛡️",
            title="All clear!",
            description="No vulnerabilities detected in your latest scan"
        )
    
    @staticmethod
    def error_state():
        return EmptyState(
            icon="⚠️",
            title="Something went wrong",
            description="We couldn't load the data. Please try again later."
        )
