#!/bin/bash

set -Eeuo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

ICON_INFO="ℹ️"
ICON_SUCCESS="✅"
ICON_WARNING="⚠️"
ICON_ERROR="❌"
ICON_ROCKET="🚀"
ICON_GUI="🖥️"
ICON_SHIELD="🛡️"
ICON_DB="🗄️"
ICON_INSTALL="📦"
ICON_CLEAN="🧹"
ICON_EXIT="👋"

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [[ "$SOURCE" != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"

print_info() {
    echo -e "${BLUE}${ICON_INFO} [INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}${ICON_SUCCESS} [SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}${ICON_WARNING} [WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}${ICON_ERROR} [ERROR]${NC} $1"
}

print_banner() {
    cat <<'EOF'



  .--.--.     ,---,                         ,--,                  ,---,.                     
 /  /    '. ,--.' |      ,--,             ,--.'|         ,---,  ,'  .' |                     
|  :  /`. / |  |  :    ,--.'|             |  | :       ,---.'|,---.'   |                     
;  |  |--`  :  :  :    |  |,              :  : '       |   | :|   |   .'                     
|  :  ;_    :  |  |,--.`--'_       ,---.  |  ' |       |   | |:   :  |-,      .--,   ,---.   
 \  \    `. |  :  '   |,' ,'|     /     \ '  | |     ,--.__| |:   |  ;/|    /_ ./|  /     \  
  `----.   \|  |   /' :'  | |    /    /  ||  | :    /   ,'   ||   :   .' , ' , ' : /    /  | 
  __ \  \  |'  :  | | ||  | :   .    ' / |'  : |__ .   '  /  ||   |  |-,/___/ \: |.    ' / | 
 /  /`--'  /|  |  ' | :'  : |__ '   ;   /||  | '.'|'   ; |:  |'   :  ;/| .  \  ' |'   ;   /| 
'--'.     / |  :  :_:,'|  | '.'|'   |  / |;  :    ;|   | '/  '|   |    \  \  ;   :'   |  / | 
  `--'---'  |  | ,'    ;  :    ;|   :    ||  ,   / |   :    :||   :   .'   \  \  ;|   :    | 
            `--''      |  ,   /  \   \  /  ---`-'   \   \  /  |   | ,'      :  \  \\   \  /  
                        ---`-'    `----'             `----'   `----'         \  ' ; `----'   
                                                                              `--`           



 ShieldEye ComplianceScan Launcher
--------------------------------
EOF
}

check_python() {
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        return 1
    fi
    print_success "Python 3 found: $(python3 --version)"
    return 0
}

check_gtk() {
    if ! python3 -c "import gi; gi.require_version('Gtk', '4.0'); from gi.repository import Gtk" 2>/dev/null; then
        print_warning "GTK 4 not found, checking GTK 3..."
        if ! python3 -c "import gi; gi.require_version('Gtk', '3.0'); from gi.repository import Gtk" 2>/dev/null; then
            print_error "PyGObject (GTK bindings) not found"
            print_info "Install with: sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-4.0"
            print_info "Or: sudo pacman -S python-gobject gtk4"
            return 1
        fi
        print_success "GTK 3 found"
    else
        print_success "GTK 4 found"
    fi
    return 0
}

create_venv() {
    # Why: --system-site-packages lets the venv see system PyGObject/gi. Without it,
    # `import gi` fails at runtime even though the system GTK check passed.
    print_info "Creating virtual environment (.venv with --system-site-packages)..."
    python3 -m venv --system-site-packages "${SCRIPT_DIR}/.venv"
}

# Set to 1 by ensure_venv_can_import_gi when it wipes and recreates .venv, so
# callers know the venv is empty and Python deps must be reinstalled.
VENV_WAS_REBUILT=0

ensure_venv_can_import_gi() {
    # Activate then verify gi is reachable from the venv's interpreter.
    # If a previous .venv was created without --system-site-packages, recreate it.
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/.venv/bin/activate"
    if ! python3 -c "import gi" 2>/dev/null; then
        print_warning ".venv cannot import 'gi' - rebuilding with --system-site-packages..."
        deactivate
        rm -rf "${SCRIPT_DIR}/.venv"
        create_venv
        # shellcheck source=/dev/null
        source "${SCRIPT_DIR}/.venv/bin/activate"
        # Why: rm wiped every pip-installed package - callers must reinstall or
        # the app launches against an empty venv and loses networkx/matplotlib/etc.
        VENV_WAS_REBUILT=1
    fi
}

install_dependencies() {
    print_info "Installing all dependencies..."
    echo ""

    check_python || exit 1

    cd "${SCRIPT_DIR}"

    if [ ! -d ".venv" ]; then
        create_venv
    fi
    ensure_venv_can_import_gi

    pip install --upgrade pip setuptools wheel

    if [ -f "${SCRIPT_DIR}/requirements.txt" ]; then
        print_info "Installing Python dependencies from requirements.txt..."
        pip install -r "${SCRIPT_DIR}/requirements.txt"
        print_success "Python dependencies installed into .venv"
    else
        print_warning "requirements.txt not found"
    fi

    if [ -f "${SCRIPT_DIR}/install_deps.py" ]; then
        print_info "Running system dependency installer..."
        python3 "${SCRIPT_DIR}/install_deps.py"
    fi

    check_gtk

    echo ""
    print_success "All dependencies installed successfully!"
    echo ""
    read -p "Press Enter to continue..."
}

reset_data() {
    print_warning "This will delete all scan history and database data!"
    echo ""
    read -rp "Are you sure you want to reset all data? [y/N]: " confirm
    
    case "$confirm" in
        y|Y|yes|YES)
            print_info "Resetting database..."
            # Database path: use SHIELDEYE_DB_PATH if set, otherwise default to ~/.shieldeye/scans.db
            DB_PATH="${SHIELDEYE_DB_PATH:-$HOME/.shieldeye/scans.db}"

            if [ -f "$DB_PATH" ]; then
                rm -f "$DB_PATH"
                print_success "Database deleted: $DB_PATH"
            else
                print_info "Database file not found (already clean): $DB_PATH"
            fi

            # Cache directory (on-disk cache, if used)
            # We clear both the global ~/.shieldeye/cache and any local ./cache directory.
            CACHE_DIR_GLOBAL="$HOME/.shieldeye/cache"
            if [ -d "$CACHE_DIR_GLOBAL" ]; then
                rm -rf "$CACHE_DIR_GLOBAL"
                print_success "Cache directory cleared: $CACHE_DIR_GLOBAL"
            fi

            CACHE_DIR_LOCAL="${SCRIPT_DIR}/cache"
            if [ -d "$CACHE_DIR_LOCAL" ]; then
                rm -rf "$CACHE_DIR_LOCAL"
                print_success "Cache directory cleared: $CACHE_DIR_LOCAL"
            fi

            # Logs directory: use SHIELDEYE_LOG_DIR if set, otherwise default to ~/.shieldeye/logs
            LOGS_DIR="${SHIELDEYE_LOG_DIR:-$HOME/.shieldeye/logs}"
            if [ -d "$LOGS_DIR" ]; then
                rm -rf "${LOGS_DIR}"/*.log 2>/dev/null || true
                print_success "Log files cleared in: $LOGS_DIR"
            fi

            # Reports directory (optional cleanup)
            REPORTS_DIR="${SHIELDEYE_REPORTS_DIR:-$HOME/.shieldeye/reports}"
            if [ -d "$REPORTS_DIR" ]; then
                rm -rf "${REPORTS_DIR}"/* 2>/dev/null || true
                print_success "Reports directory cleared: $REPORTS_DIR"
            fi
            
            echo ""
            print_success "All data has been reset!"
            ;;
        *)
            print_info "Reset cancelled"
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
}

run_application() {
    print_info "Starting ShieldEye ComplianceScan..."
    echo ""

    check_python || exit 1

    cd "${SCRIPT_DIR}"

    # Ensure the app runs inside .venv (where requirements.txt is installed),
    # not against system Python which lacks networkx/matplotlib/etc.
    if [ ! -d ".venv" ]; then
        print_warning "Virtualenv .venv not found. Installing dependencies first..."
        install_dependencies
    fi
    ensure_venv_can_import_gi
    if [ "${VENV_WAS_REBUILT}" = "1" ]; then
        print_warning "venv was rebuilt empty - reinstalling dependencies first..."
        install_dependencies
    fi
    if ! python3 -c "import networkx" 2>/dev/null; then
        print_warning "Python dependencies missing in .venv - installing..."
        install_dependencies
    fi

    export PYTHONPATH="${SCRIPT_DIR}:${PYTHONPATH:-}"

    if [ -f "${SCRIPT_DIR}/main_gtk.py" ]; then
        print_success "Launching GTK GUI..."
        cd "${SCRIPT_DIR}"
        python3 main_gtk.py
    elif [ -f "${SCRIPT_DIR}/gtk_gui/main.py" ]; then
        print_success "Launching GTK GUI..."
        cd "${SCRIPT_DIR}"
        python3 gtk_gui/main.py
    elif [ -f "${SCRIPT_DIR}/main.py" ]; then
        print_success "Launching application..."
        cd "${SCRIPT_DIR}"
        python3 main.py
    else
        print_error "No main application file found!"
        print_info "Looking for: main_gtk.py, gtk_gui/main.py, or main.py"
        exit 1
    fi
}

show_menu() {
    clear
    print_banner
    echo ""
    echo "Choose launch mode:"
    echo "  1) ${ICON_ROCKET} Run ShieldEye ComplianceScan"
    echo "  2) ${ICON_DB} Reset history & local data"
    echo "  3) ${ICON_INFO} Install dependencies (Python + system)"
    echo "  4) ${ICON_EXIT} Exit"
    echo ""
    echo -ne "Enter choice [1-4]: "
}

handle_ctrl_c() {
    echo ""
    echo ""
    print_info "Interrupted by user"
    exit 130
}

main() {
    trap handle_ctrl_c SIGINT
    
    while true; do
        show_menu
        read -r choice
        
        case $choice in
            1)
                clear
                run_application
                ;;
            2)
                clear
                print_banner
                echo ""
                reset_data
                ;;
            3)
                clear
                print_banner
                echo ""
                install_dependencies
                ;;
            4)
                clear
                print_banner
                echo ""
                print_success "Thank you for using ShieldEye ComplianceScan!"
                echo -e "${CYAN}${ICON_EXIT} Goodbye!${NC}"
                echo ""
                exit 0
                ;;
            *)
                print_error "Invalid option. Please select 1-4."
                sleep 2
                ;;
        esac
    done
}

main
