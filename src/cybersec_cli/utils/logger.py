"""
Logging configuration for the Cybersec CLI.
"""
import logging
import sys
from pathlib import Path
from typing import Optional

def setup_logger(
    name: str,
    log_level: int = logging.INFO,
    log_file: Optional[Path] = None,
    console: bool = True
) -> logging.Logger:
    """
    Set up and configure a logger with the given name.
    
    Args:
        name: Name of the logger
        log_level: Logging level (e.g., logging.INFO, logging.DEBUG)
        log_file: Optional file to log to
        console: Whether to log to console
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    
    # Clear any existing handlers to avoid duplicate logs
    logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Add console handler if requested
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # Add file handler if log file is specified
    if log_file:
        # Ensure log directory exists
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the given name, configured with default settings.
    
    Args:
        name: Name of the logger
        
    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)
