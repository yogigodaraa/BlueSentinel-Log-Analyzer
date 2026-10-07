#!/usr/bin/env python3
"""
Quick test runner to verify backend tests are working
"""
import sys
import subprocess

def run_command(cmd, description):
    """Run a command and print results"""
    print(f"\n{'='*60}")
    print(f"🔍 {description}")
    print(f"{'='*60}")
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print(f"✅ {description} - SUCCESS")
            if result.stdout:
                print(result.stdout[:500])
        else:
            print(f"❌ {description} - FAILED")
            if result.stderr:
                print(result.stderr[:500])
        
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print(f"⏱️  {description} - TIMEOUT")
        return False
    except Exception as e:
        print(f"❌ {description} - ERROR: {e}")
        return False

def main():
    """Main test runner"""
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║       🧪 SOCShield Backend Test Suite Verifier          ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    tests = [
        ("python3 -m pytest --version", "Check pytest installation"),
        ("python3 -m pytest tests/ --collect-only -q", "Collect tests"),
        ("python3 -m pytest tests/test_config.py::TestSettings::test_default_settings -v", "Run sample test"),
    ]
    
    results = []
    for cmd, desc in tests:
        success = run_command(cmd, desc)
        results.append((desc, success))
    
    # Summary
    print(f"\n{'='*60}")
    print("📊 TEST SUMMARY")
    print(f"{'='*60}")
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for desc, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {desc}")
    
    print(f"\n📈 Results: {passed}/{total} checks passed")
    
    if passed == total:
        print("\n🎉 All checks passed! Test suite is ready!")
        return 0
    else:
        print("\n⚠️  Some checks failed. Please review the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
