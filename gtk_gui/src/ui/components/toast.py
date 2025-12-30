
from gi.repository import Gtk, GLib, Adw

class Toast:

    def __init__(self, title, timeout=3):
        self._toast = Adw.Toast(title=title)
        self._toast.set_timeout(timeout)
    
    def show(self, overlay):
        overlay.add_toast(self._toast)
    
    @staticmethod
    def success(overlay, message, timeout=3):

        toast = Adw.Toast(title=f"✓ {message}")
        toast.set_timeout(timeout)
        overlay.add_toast(toast)
    
    @staticmethod
    def error(overlay, message, timeout=5):

        toast = Adw.Toast(title=f"✗ {message}")
        toast.set_timeout(timeout)
        overlay.add_toast(toast)
    
    @staticmethod
    def info(overlay, message, timeout=3):

        toast = Adw.Toast(title=f"ⓘ {message}")
        toast.set_timeout(timeout)
        overlay.add_toast(toast)
    
    @staticmethod
    def warning(overlay, message, timeout=4):

        toast = Adw.Toast(title=f"⚠ {message}")
        toast.set_timeout(timeout)
        overlay.add_toast(toast)
    
    @staticmethod
    def with_action(overlay, message, action_label, callback, timeout=5):

        toast = Adw.Toast(title=message)
        toast.set_button_label(action_label)
        toast.set_timeout(timeout)
        toast.connect("button-clicked", callback)
        overlay.add_toast(toast)

class InlineNotification(Gtk.Box):

    def __init__(self, message, notification_type="info", dismissible=True):
        super().__init__(spacing=12)
        self.add_css_class("inline-notification")
        self.add_css_class(f"notification-{notification_type}")
        self.set_margin_top(8)
        self.set_margin_bottom(8)
        self.set_margin_start(8)
        self.set_margin_end(8)
        
        icons = {
            "success": "✓",
            "error": "✗",
            "warning": "⚠",
            "info": "ⓘ"
        }
        
        colors = {
            "success": "#10B981",
            "error": "#EF4444",
            "warning": "#F59E0B",
            "info": "#3B82F6"
        }
        
        icon = icons.get(notification_type, "ⓘ")
        color = colors.get(notification_type, "#3B82F6")
        
        icon_label = Gtk.Label()
        icon_label.set_markup(f'<span size="13000" weight="700" color="{color}">{icon}</span>')
        self.append(icon_label)
        
        message_label = Gtk.Label(label=message)
        message_label.set_halign(Gtk.Align.START)
        message_label.set_wrap(True)
        message_label.set_hexpand(True)
        self.append(message_label)
        
        if dismissible:
            dismiss_btn = Gtk.Button()
            dismiss_btn.set_icon_name("window-close-symbolic")
            dismiss_btn.add_css_class("flat")
            dismiss_btn.set_tooltip_text("Dismiss")
            dismiss_btn.connect("clicked", lambda b: self.get_parent().remove(self))
            self.append(dismiss_btn)
