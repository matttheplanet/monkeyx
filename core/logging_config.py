"""Centralized logging configuration for MonkeyX."""

import logging
import sys
from pathlib import Path


def setup_logging(output_prefix, verbose=False, output_dir=None):
    """Configure logging for MonkeyX.
    
    Sets up dual logging:
    - Console: INFO level (or DEBUG if verbose)
    - File: DEBUG level always
    - Error file: ERROR level and above
    
    Args:
        output_prefix: Output file prefix for log files
        verbose: If True, set console to DEBUG level
        output_dir: Directory for log files (default: './logs')
        
    Returns:
        logging.Logger: Configured logger instance
    """
    # Determine log directory
    if output_dir:
        log_dir = Path(output_dir)
    else:
        log_dir = Path('logs')
    
    # Create log directory if it doesn't exist
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Define log file paths
    main_log = log_dir / f'{output_prefix}-monkeyx.log'
    error_log = log_dir / f'{output_prefix}-errors.log'
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_formatter = logging.Formatter(
        '%(levelname)s - %(message)s'
    )
    
    # Create handlers
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(console_formatter)
    
    # Main file handler (all logs)
    file_handler = logging.FileHandler(main_log, mode='a')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    
    # Error file handler (errors only)
    error_handler = logging.FileHandler(error_log, mode='a')
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    # Remove any existing handlers
    root_logger.handlers.clear()
    
    # Add handlers
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(error_handler)
    
    # Create MonkeyX logger
    logger = logging.getLogger('monkeyx')
    
    # Log initial setup
    logger.info("="*60)
    logger.info(f"MonkeyX Logging Initialized")
    logger.info(f"Output Prefix: {output_prefix}")
    logger.info(f"Main Log: {main_log}")
    logger.info(f"Error Log: {error_log}")
    logger.info(f"Verbose Mode: {'ON' if verbose else 'OFF'}")
    logger.info("="*60)
    
    return logger


def get_logger(name):
    """Get a logger for a specific module.
    
    Args:
        name: Name of the module/component
        
    Returns:
        logging.Logger: Logger instance
    """
    return logging.getLogger(f'monkeyx.{name}')