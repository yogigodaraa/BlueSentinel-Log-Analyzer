#!/usr/bin/env python3
"""Quick test runner to see status"""
import subprocess
import sys

tests = [
    "tests/test_ioc_extractor.py",
    "tests/test_config.py",
    "tests/test_phishing_detector.py",
]

print("=" * 60)
print("🧪 Running Backend Tests")
print("=" * 60)

for test_file in tests:
    print(f"\n📝 Running {test_file}...")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", test_file, "-v", "--tb=no", "-q"],
        capture_output=True,
        text=True
    )
    
    # Print summary line
    if "passed" in result.stdout:
        print(result.stdout.split('\n')[-2])
    else:
        print(result.stdout)
        print(result.stderr)

print("\n" + "=" * 60)
print("✅ Test Summary Complete")
print("=" * 60)
