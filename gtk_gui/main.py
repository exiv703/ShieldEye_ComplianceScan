
import sys
import os
import gi

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.app import ShieldEyeApplication

def main():

    app = ShieldEyeApplication()
    return app.run(sys.argv)

if __name__ == "__main__":
    sys.exit(main())
