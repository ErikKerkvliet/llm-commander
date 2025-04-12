# --- START OF FILE llm-commander/log_setup.py ---

# llm-commander/log_setup.py
import logging
import os
from datetime import datetime

LOGS_DIR = 'logs'

def setup_loggers():
    """Configures the base logs directory and the main error logger."""

    # --- Create Base Logs Directory ---
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
    except OSError as e:
        print(f"CRITICAL ERROR: Could not create log directory '{LOGS_DIR}': {e}")
        # Fallback or exit might be needed here depending on requirements
        # For now, we let the logger setup fail below if the dir is needed.
        pass # Continue attempt to setup loggers

    # --- Standard Error Logging ---
    error_logger = logging.getLogger('ErrorLogger')
    # Prevent duplicate handlers if setup is called multiple times
    if not error_logger.handlers:
        error_logger.setLevel(logging.ERROR)
        error_logger.propagate = False # Prevent propagation to root logger
        try:
            error_log_path = os.path.join(LOGS_DIR, 'error.log')
            err_handler = logging.FileHandler(error_log_path, encoding='utf-8')
            err_handler.setLevel(logging.ERROR)
            err_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s [%(filename)s:%(lineno)d]')
            err_handler.setFormatter(err_formatter)
            error_logger.addHandler(err_handler)
            # Also log critical errors to console
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.ERROR) # Or CRITICAL
            console_handler.setFormatter(err_formatter)
            error_logger.addHandler(console_handler)

            error_logger.info(f"Error logger configured. Log file: {error_log_path}") # Use info level for setup message
        except Exception as e:
            # Fallback to basic console logging if file setup fails
            logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
            logging.critical(f"CRITICAL: Failed to set up file error logging: {e}", exc_info=True)
            error_logger = logging.getLogger() # Use root logger as fallback

    # Conversation logging is now handled dynamically in LLMCommanderApp
    # We only return the configured error logger here.
    return error_logger

# Configure loggers when module is imported
error_logger = setup_loggers()

# --- END OF FILE llm-commander/log_setup.py ---