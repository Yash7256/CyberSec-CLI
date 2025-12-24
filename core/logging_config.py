"""Structured logging configuration for CyberSec CLI"""
import logging
import json
import sys
from datetime import datetime
from pathlib import Path
import uuid
from logging.handlers import RotatingFileHandler
import gzip
import os
from typing import Dict, Any, Optional

# Global request ID context
_local = __import__('threading').local()

class JsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "component": getattr(record, 'component', 'unknown'),
            "message": record.getMessage(),
            "context": getattr(record, 'context', {}),
            "trace_id": getattr(record, 'trace_id', getattr(_local, 'request_id', str(uuid.uuid4())))
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, 'scan_id'):
            log_entry["context"]["scan_id"] = record.scan_id
        if hasattr(record, 'target'):
            log_entry["context"]["target"] = record.target
        if hasattr(record, 'user_id'):
            log_entry["context"]["user_id"] = record.user_id
        
        return json.dumps(log_entry)


class CompressedRotatingFileHandler(RotatingFileHandler):
    """Custom handler that compresses old log files"""
    
    def doRollover(self):
        """Override rollover to compress old log files"""
        if self.stream:
            self.stream.close()
            self.stream = None
        
        if self.backupCount > 0:
            for i in range(self.backupCount - 1, 0, -1):
                sfn = f"{self.baseFilename}.{i}"
                dfn = f"{self.baseFilename}.{i + 1}"
                if os.path.exists(sfn):
                    if os.path.exists(dfn):
                        os.remove(dfn)
                    os.rename(sfn, dfn)
            
            dfn = f"{self.baseFilename}.1"
            if os.path.exists(dfn):
                os.remove(dfn)
            
            # Compress the current log file before rotating
            with open(self.baseFilename, 'rb') as f_in:
                with gzip.open(f"{self.baseFilename}.1.gz", 'wb') as f_out:
                    f_out.writelines(f_in)
            
            os.remove(self.baseFilename)
        
        # Open new log file
        self.stream = self._open()


class AuditLogHandler(logging.Handler):
    """Handler for audit logs that never rotates"""
    
    def __init__(self, filename: str):
        super().__init__()
        self.filename = filename
        # Ensure directory exists
        Path(self.filename).parent.mkdir(parents=True, exist_ok=True)
    
    def emit(self, record):
        """Write audit log entry to file"""
        try:
            log_entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level": record.levelname,
                "component": getattr(record, 'component', 'audit'),
                "message": record.getMessage(),
                "context": getattr(record, 'context', {}),
                "trace_id": getattr(record, 'trace_id', getattr(_local, 'request_id', str(uuid.uuid4())))
            }
            
            # Add exception info if present
            if record.exc_info:
                log_entry["exception"] = self.formatException(record.exc_info)
            
            with open(self.filename, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception:
            self.handleError(record)


def setup_logging(log_dir: str = "logs", audit_log_file: str = "monitoring/audit.log"):
    """Set up structured logging with different levels per component"""
    
    # Create log directory
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    # Create audit log directory if needed
    Path(audit_log_file).parent.mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Root logger captures all levels
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler for development
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(JsonFormatter())
    console_handler.setLevel(logging.INFO)
    root_logger.addHandler(console_handler)
    
    try:
        # Scanner component logger
        scanner_logger = logging.getLogger('scanner')
        scanner_log_path = Path(log_dir) / "scanner.log"
        scanner_log_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
        scanner_handler = CompressedRotatingFileHandler(
            str(scanner_log_path),
            maxBytes=100*1024*1024,  # 100MB
            backupCount=30
        )
        scanner_handler.setFormatter(JsonFormatter())
        scanner_handler.setLevel(logging.INFO)
        scanner_logger.addHandler(scanner_handler)
        scanner_logger.setLevel(logging.INFO)
    except PermissionError:
        print(f"Warning: Cannot create scanner log file at {scanner_log_path}. Using console only.")
    
    try:
        # API component logger
        api_logger = logging.getLogger('api')
        api_log_path = Path(log_dir) / "api.log"
        api_log_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
        api_handler = CompressedRotatingFileHandler(
            str(api_log_path),
            maxBytes=100*1024*1024,  # 100MB
            backupCount=30
        )
        api_handler.setFormatter(JsonFormatter())
        api_handler.setLevel(logging.INFO)
        api_logger.addHandler(api_handler)
        api_logger.setLevel(logging.INFO)
    except PermissionError:
        print(f"Warning: Cannot create API log file at {api_log_path}. Using console only.")
    
    try:
        # Celery component logger
        celery_logger = logging.getLogger('celery')
        celery_log_path = Path(log_dir) / "celery.log"
        celery_log_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
        celery_handler = CompressedRotatingFileHandler(
            str(celery_log_path),
            maxBytes=100*1024*1024,  # 100MB
            backupCount=30
        )
        celery_handler.setFormatter(JsonFormatter())
        celery_handler.setLevel(logging.WARNING)
        celery_logger.addHandler(celery_handler)
        celery_logger.setLevel(logging.WARNING)
    except PermissionError:
        print(f"Warning: Cannot create Celery log file at {celery_log_path}. Using console only.")
    
    try:
        # Database component logger
        db_logger = logging.getLogger('database')
        db_log_path = Path(log_dir) / "database.log"
        db_log_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
        db_handler = CompressedRotatingFileHandler(
            str(db_log_path),
            maxBytes=100*1024*1024,  # 100MB
            backupCount=30
        )
        db_handler.setFormatter(JsonFormatter())
        db_handler.setLevel(logging.ERROR)
        db_logger.addHandler(db_handler)
        db_logger.setLevel(logging.ERROR)
    except PermissionError:
        print(f"Warning: Cannot create Database log file at {db_log_path}. Using console only.")
    
    # Audit logger (always try to create this one)
    try:
        audit_logger = logging.getLogger('audit')
        audit_handler = AuditLogHandler(audit_log_file)
        audit_handler.setFormatter(JsonFormatter())
        audit_handler.setLevel(logging.INFO)
        audit_logger.addHandler(audit_handler)
        audit_logger.setLevel(logging.INFO)
    except PermissionError:
        print(f"Warning: Cannot create audit log file at {audit_log_file}. Using console only.")
        # Fallback: create a basic file handler for audit without rotation
        audit_logger = logging.getLogger('audit')
        audit_handler = logging.FileHandler(audit_log_file, mode='a')
        audit_handler.setFormatter(JsonFormatter())
        audit_handler.setLevel(logging.INFO)
        audit_logger.addHandler(audit_handler)
        audit_logger.setLevel(logging.INFO)
    
    return root_logger


def get_logger(component: str, **context) -> logging.Logger:
    """Get a logger with component name and optional context"""
    logger = logging.getLogger(component)
    
    # Create a logger adapter that adds context
    class ContextLoggerAdapter(logging.LoggerAdapter):
        def process(self, msg, kwargs):
            # Add context to the extra data
            extra = kwargs.get('extra', {})
            extra.update(self.extra)
            kwargs['extra'] = extra
            return msg, kwargs
    
    adapter = ContextLoggerAdapter(logger, context)
    return adapter


def set_request_id(request_id: Optional[str] = None):
    """Set the request ID for the current thread"""
    if request_id is None:
        request_id = str(uuid.uuid4())
    _local.request_id = request_id


def get_request_id() -> Optional[str]:
    """Get the request ID for the current thread"""
    return getattr(_local, 'request_id', None)


def clear_request_id():
    """Clear the request ID for the current thread"""
    if hasattr(_local, 'request_id'):
        delattr(_local, 'request_id')


def log_audit_event(event_type: str, message: str, **context):
    """Log an audit event to the audit log"""
    audit_logger = logging.getLogger('audit')
    audit_logger.info(
        message,
        extra={
            'component': 'audit',
            'context': {
                'event_type': event_type,
                **context
            }
        }
    )


def get_current_trace_id():
    """Get the current trace ID for the thread"""
    return getattr(_local, 'request_id', None)


def add_request_context(**context):
    """Add context to the current request for logging"""
    current_trace_id = getattr(_local, 'request_id', None)
    if current_trace_id is None:
        current_trace_id = str(uuid.uuid4())
        _local.request_id = current_trace_id
    return {
        'trace_id': current_trace_id,
        **context
    }