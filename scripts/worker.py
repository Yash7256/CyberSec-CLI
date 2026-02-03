#!/usr/bin/env python3
"""
Celery worker entry point for CyberSec-CLI.
"""

import logging
import os
import sys

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)


def main():
    """Start the Celery worker."""
    try:
        # Import the Celery app
        from tasks.celery_app import celery_app

        logger.info("Starting Celery worker for CyberSec-CLI")

        # Start the worker
        celery_app.worker_main(
            [
                "worker",
                "--loglevel=info",
                "--queues=scans",
                "--hostname=cybersec-worker@%h",
                "--concurrency=4",
                "--prefetch-multiplier=1",
            ]
        )

    except KeyboardInterrupt:
        logger.info("Worker stopped by user")
    except Exception as e:
        logger.error(f"Worker failed to start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
