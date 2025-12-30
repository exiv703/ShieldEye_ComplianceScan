
import sys
import subprocess
import os

if sys.version_info < (3, 10):
    print("ERROR: Python 3.10 or higher is required.")
    print(f"Current version: {sys.version}")
    sys.exit(1)

from distro_utils import detect_distro, get_distro_name

def run_command(cmd, check=True):

    try:
        if isinstance(cmd, str):
            cmd = cmd.split()
        result = subprocess.run(
            cmd,
            shell=False,
            check=check,
            capture_output=True,
            text=True
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return False, e.stdout, e.stderr

def install_pip_requirements(files):

    print(f"\n📦 Installing Python dependencies...")
    
    for req_file in files:
        if not os.path.exists(req_file):
            print(f"⚠️  Warning: {req_file} not found, skipping...")
            continue
        
        print(f"   Installing from {req_file}...")
        success, stdout, stderr = run_command(
            f"{sys.executable} -m pip install -r {req_file}",
            check=False
        )
        
        if not success:
            print(f"⚠️  Some packages from {req_file} failed to install.")
            print(f"   This is normal for system packages on Fedora/RHEL.")
            print(f"   Error details: {stderr[:200]}")
        else:
            print(f"✅ Successfully installed from {req_file}")

def install_arch_system_deps():

    print("\n🔧 Installing Arch Linux system dependencies...")
    
    packages = [
        'python-pyqt6',
        'python-beautifulsoup4',
        'python-requests',
        'python-networkx',
        'python-matplotlib',
        'python-numpy',
        'python-pandas',
        'wkhtmltopdf',
    ]
    
    print(f"   Recommended packages: {', '.join(packages)}")
    print(f"   Run: sudo pacman -S {' '.join(packages)}")
    print(f"   (Skipping automatic installation - requires sudo)")

def install_fedora_system_deps():

    print("\n🔧 Installing Fedora/RHEL system dependencies...")
    
    packages = [
        'python3-blivet',
        'python3-blivet-gui',
        'python3-pyqt6',
        'python3-beautifulsoup4',
        'python3-requests',
        'python3-networkx',
        'python3-matplotlib',
        'python3-numpy',
        'python3-pandas',
        'wkhtmltopdf',
    ]
    
    print(f"   Recommended packages: {', '.join(packages)}")
    print(f"   Run: sudo dnf install {' '.join(packages)}")
    print(f"   (Skipping automatic installation - requires sudo)")

def main():
    print("=" * 70)
    print("ShieldEye ComplianceScan - Dependency Installer")
    print("=" * 70)
    
    print(f"\n✓ Python version: {sys.version.split()[0]}")
    
    distro = detect_distro()
    distro_name = get_distro_name()
    print(f"✓ Detected distribution: {distro_name}")
    
    if distro == 'unknown':
        print("\n⚠️  Warning: Unknown Linux distribution detected.")
        print("   Proceeding with base requirements only.")
        print("   Some features may not work correctly.\n")
    
    req_files = ['requirements.txt']

    print("\n📋 Installing Python dependencies from requirements.txt ...")
    install_pip_requirements(req_files)

    if distro in ('fedora', 'rhel'):
        print(f"\n📋 Detected Fedora/RHEL-based system...")
        install_fedora_system_deps()

    elif distro == 'arch':
        print(f"\n📋 Detected Arch Linux...")
        install_arch_system_deps()

    else:
        print(f"\n📋 No specific distro integration. Installed base Python requirements only.")
    
    print("\n" + "=" * 70)
    print("✅ Installation complete!")
    print("=" * 70)
    
    print("\n📝 Next steps:")
    print("   1. Install system packages using your package manager (see above)")
    print("   2. Run the application: python main.py")
    print("\n💡 Note: Some pip packages may fail on Fedora/RHEL - this is normal.")
    print("   These packages should be installed via dnf/yum instead.\n")

if __name__ == '__main__':
    main()
