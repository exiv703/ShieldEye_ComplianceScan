
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Adw, Gio
from .ui.window import MainWindow

class ShieldEyeApplication(Adw.Application):

    def __init__(self):
        super().__init__(
            application_id="com.shieldeye.compliancescan",
            flags=Gio.ApplicationFlags.FLAGS_NONE
        )

        from gi.repository import Adw
        style_manager = Adw.StyleManager.get_default()
        style_manager.set_color_scheme(Adw.ColorScheme.FORCE_DARK)

    def do_activate(self):

        win = self.props.active_window
        if not win:
            win = MainWindow(application=self)
        win.present()
