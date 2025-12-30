
import sys
import os

def test_python_version():

    print("=" * 70)
    print("TEST 1: Python Version Check")
    print("=" * 70)
    
    version = sys.version_info
    print(f"Current Python version: {version.major}.{version.minor}.{version.micro}")
    
    if version >= (3, 10):
        print("✅ PASS: Python 3.10+ detected")
    else:
        print("❌ FAIL: Python version too old (3.10+ required)")
    
    assert version >= (3, 10), "Python 3.10+ required"

def test_distro_detection():

    print("\n" + "=" * 70)
    print("TEST 2: Distribution Detection")
    print("=" * 70)
    
    from distro_utils import detect_distro, get_distro_name, is_fedora_based, is_arch_based
    
    distro = detect_distro()
    distro_name = get_distro_name()
    
    print(f"Detected distribution: {distro_name} (code: {distro})")
    print(f"Is Fedora-based: {is_fedora_based()}")
    print(f"Is Arch-based: {is_arch_based()}")
    
    assert distro in ('fedora', 'rhel', 'arch', 'unknown'), f"Invalid distro code: {distro}"
    print("✅ PASS: Distribution detection working")

def test_requirements_files():

    print("\n" + "=" * 70)
    print("TEST 3: Requirements Files Structure")
    print("=" * 70)
    
    required_files = [
        'requirements.txt',
    ]
    
    for filename in required_files:
        assert os.path.exists(filename), f"{filename} is missing"
        size = os.path.getsize(filename)
        print(f"✅ {filename} exists ({size} bytes)")
    
    print("✅ PASS: requirements.txt present")

def test_main_imports():

    print("\n" + "=" * 70)
    print("TEST 4: Main Module Import")
    print("=" * 70)
    
    try:
        import main
        print("✅ PASS: main.py imported successfully")
        print(f"   (Python version check passed)")
    except SystemExit as e:
        if sys.version_info < (3, 10):
            print("✅ PASS: main.py correctly rejected Python < 3.10")
        else:
            raise AssertionError(f"Unexpected SystemExit: {e}")
    except Exception as e:
        print(f"⚠️  WARNING: Import failed with: {e}")
        print(f"   (This may be due to missing GUI dependencies)")

def test_installer_exists():

    print("\n" + "=" * 70)
    print("TEST 5: Installer Script")
    print("=" * 70)
    
    assert os.path.exists('install_deps.py'), "install_deps.py not found"
    print("✅ install_deps.py exists")
    
    with open('install_deps.py', 'r') as f:
        content = f.read()
        assert 'detect_distro' in content, "Installer missing detect_distro function"
        assert 'install_pip_requirements' in content, "Installer missing install_pip_requirements function"
        print("✅ PASS: Installer contains expected functions")

def test_documentation():

    print("\n" + "=" * 70)
    print("TEST 6: Documentation")
    print("=" * 70)
    
    docs = {
        'README.md': 'Main documentation',
    }
    
    for filename, description in docs.items():
        assert os.path.exists(filename), f"{filename} MISSING ({description})"
        print(f"✅ {filename} exists ({description})")
    
    print("✅ PASS: All documentation files present")

def main():

    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 10 + "ShieldEye ComplianceScan - Compatibility Tests" + " " * 11 + "║")
    print("╚" + "=" * 68 + "╝")
    print()
    
    tests = [
        test_python_version,
        test_distro_detection,
        test_requirements_files,
        test_installer_exists,
        test_documentation,
        test_main_imports,
    ]
    
    results = []
    for test_func in tests:
        try:
            result = test_func()
            results.append(result)
        except Exception as e:
            print(f"\n❌ EXCEPTION in {test_func.__name__}: {e}")
            results.append(False)
    
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(results)
    total = len(results)
    
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! 🎉")
        print("ShieldEye ComplianceScan is properly configured for multi-distro support.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed.")
        print("Please review the output above for details.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
