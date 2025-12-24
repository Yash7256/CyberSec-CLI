"""
Celery application configuration for CyberSec-CLI.
"""

import os
from celery import Celery

# Create Celery app instance
celery_app = Celery("cybersec_cli")

# Configure Celery with Redis as broker and result backend
celery_app.conf.update(
    broker_url=os.getenv("REDIS_URL", "redis://localhost:6379"),
    result_backend=os.getenv("REDIS_URL", "redis://localhost:6379"),
    # Task serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Task routing and queues
    task_routes={
        "tasks.scan_tasks.perform_scan_task": {"queue": "scans"},
    },
    # Worker configuration
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    # Result expiration (24 hours)
    result_expires=86400,
)

# Auto-discover tasks
celery_app.autodiscover_tasks(["tasks"])

if __name__ == "__main__":
    celery_app.start()
