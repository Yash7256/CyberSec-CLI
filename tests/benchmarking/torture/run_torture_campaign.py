import os
import subprocess
import sys
import time

# Add tests directory to python path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

TORTURE_DIR = "tests/benchmarking/torture"
TORTURE_TESTS = [
    "test_network_warfare.py",
    "test_resource_annihilation.py",
    "test_chaos_byzantine.py",
    "test_malicious_battery.py",
    "test_extreme_limits.py",
    "test_final_boss.py",
]

def run_torture_test(test_file):
    print("\n" + "🔥" * 30)
    print(f"🚀 Running Torture Test: {os.path.join(TORTURE_DIR, test_file)}")
    print("🔥" * 30 + "\n")
    
    start_time = time.time()
    try:
        # Run with current python interpreter and env
        env = os.environ.copy()
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
        env["PYTHONPATH"] = f"{root_dir}:{root_dir}/src:" + env.get("PYTHONPATH", "")
        
        res = subprocess.run([sys.executable, os.path.join(TORTURE_DIR, test_file)], check=True, env=env)
        duration = time.time() - start_time
        print(f"\n✅ Test {test_file} COMPLETED in {duration:.2f}s")
        return True
    except subprocess.CalledProcessError as e:
        duration = time.time() - start_time
        print(f"\n❌ Test {test_file} FAILED after {duration:.2f}s with exit code {e.returncode}")
        return False

def main():
    print("\n" + "🔥" * 30)
    print("CYBERSEC-CLI EXTREME TORTURE CAMPAIGN")
    print("🔥" * 30 + "\n")

    overall_start = time.time()
    results = []

    for test in TORTURE_TESTS:
        success = run_torture_test(test)
        results.append((test, success))

    total_duration = time.time() - overall_start

    print("\n" + "🔥" * 30)
    print("TORTURE CAMPAIGN COMPLETE")
    print("🔥" * 30 + "\n")

    passed = [t for t, s in results if s]
    failed = [t for t, s in results if not s]

    print(f"Total Duration: {total_duration:.2f}s")
    print(f"Passed: {len(passed)}/{len(results)}")
    
    if failed:
        print("Failed Tests:")
        for f in failed:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("ALL TORTURE TESTS PASSED! SOFTWARE IS BULLETPROOF.")
        sys.exit(0)

if __name__ == "__main__":
    main()
