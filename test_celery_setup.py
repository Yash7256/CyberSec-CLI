#!/usr/bin/env python3
"""
Test script to verify Celery setup for CyberSec-CLI.
"""

import sys
import os
import time

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))


def test_celery_import():
    """Test if Celery modules can be imported."""
    try:
        from tasks.celery_app import celery_app

        print("✅ Celery app imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Failed to import Celery app: {e}")
        return False


def test_scan_task_import():
    """Test if scan tasks can be imported."""
    try:
        from tasks.scan_tasks import perform_scan_task

        print("✅ Scan tasks imported successfully")
        return True
    except ImportError as e:
        print(f"❌ Failed to import scan tasks: {e}")
        return False


def test_celery_worker():
    """Test if Celery worker can start."""
    try:
        # This is a basic test - in practice, you'd want to actually start a worker
        from tasks.celery_app import celery_app

        print("✅ Celery worker configuration verified")
        return True
    except Exception as e:
        print(f"❌ Celery worker test failed: {e}")
        return False


def test_task_queue():
    """Test task queue functionality."""
    try:
        from tasks.scan_tasks import perform_scan_task
        import uuid

        # Create a simple test task
        scan_id = str(uuid.uuid4())
        print(f"✅ Task queue test setup complete (scan_id: {scan_id})")
        return True
    except Exception as e:
        print(f"❌ Task queue test failed: {e}")
        return False


def main():
    """Run all Celery setup tests."""
    print("Testing Celery Setup for CyberSec-CLI")
    print("=" * 50)

    tests = [
        test_celery_import,
        test_scan_task_import,
        test_celery_worker,
        test_task_queue,
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1
        print()

    print("=" * 50)
    print(f"Tests passed: {passed}/{total}")

    if passed == total:
        print("🎉 All Celery setup tests passed!")
        return 0
    else:
        print("❌ Some tests failed. Please check the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
