
import sys

if sys.version_info < (3, 10):
    print("ERROR: Python 3.10 or higher is required.")
    print(f"Current version: {sys.version}")
    sys.exit(1)

from gtk_gui.main import main

if __name__ == "__main__":
    sys.exit(main())
