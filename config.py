# llm-commander/config.py
import os
import logging
from dotenv import load_dotenv

# Use the logger configured in log_setup for config loading issues
# Note: This logger might not have file handler if log_setup fails early
# BasicConfig will be used by setup_error_logger as fallback
logger = logging.getLogger(__name__)

def load_configuration():
    """Loads configuration from environment variables."""
    load_dotenv()

    config = {}
    config['GEMINI_API_KEY'] = os.getenv("GEMINI_API_KEY")
    config['LLM_MODEL'] = os.getenv("LLM_MODEL", "models/gemini-1.5-flash-latest")
    config['SUDO_PASSWORD'] = os.getenv("SUDO_PASSWORD") # SECURITY RISK! Keep warning
    # Allow SUDO_USERNAME override, though not strictly needed by pexpect currently
    config['SUDO_USERNAME'] = os.getenv("SUDO_USERNAME") # Optional

    config['REQUIRE_CONFIRMATION'] = os.getenv("REQUIRE_CONFIRMATION", "False").strip().lower() == 'true'

    try:
        filter_success_lines_str = os.getenv("FILTER_SUCCESS_LINES", "20")
        config['FILTER_SUCCESS_LINES'] = int(filter_success_lines_str)
    except ValueError:
        logger.warning(f"Invalid FILTER_SUCCESS_LINES value '{filter_success_lines_str}', using default 20.")
        config['FILTER_SUCCESS_LINES'] = 20

    try:
        config['MAX_LLM_CALLS_PER_MINUTE'] = int(os.getenv("MAX_LLM_CALLS_PER_MINUTE", 15))
    except ValueError:
        logger.warning("Invalid MAX_LLM_CALLS_PER_MINUTE, using default 15.")
        config['MAX_LLM_CALLS_PER_MINUTE'] = 15

    try:
        config['MAX_LLM_CALLS_PER_DAY'] = int(os.getenv("MAX_LLM_CALLS_PER_DAY", 100))
    except ValueError:
        logger.warning("Invalid MAX_LLM_CALLS_PER_DAY, using default 100.")
        config['MAX_LLM_CALLS_PER_DAY'] = 100

    config['WEB_USERNAME'] = os.getenv("WEB_USERNAME")
    config['WEB_PASSWORD'] = os.getenv("WEB_PASSWORD") # Raw password for hashing
    config['FLASK_SECRET_KEY'] = os.getenv("SECRET_KEY") # Renamed from FLASK_SECRET_KEY in .env example

    # --- Validations ---
    if not config['GEMINI_API_KEY']:
        raise ValueError("CRITICAL: GEMINI_API_KEY not found in environment variables.")
    if not config['FLASK_SECRET_KEY']:
        # Match the key name used in web_server.py and expected in .env
        raise ValueError("CRITICAL: SECRET_KEY not set for Flask application in .env.")
    if not config['WEB_USERNAME'] or not config['WEB_PASSWORD']:
        raise ValueError("CRITICAL: WEB_USERNAME and/or WEB_PASSWORD not set in .env for web UI.")

    # Log loaded config (excluding sensitive parts)
    logger.info("Configuration loaded.")
    logger.info(f"LLM Model: {config['LLM_MODEL']}")
    logger.info(f"Require Confirmation: {config['REQUIRE_CONFIRMATION']}")
    logger.info(f"Filter Success Lines: {config['FILTER_SUCCESS_LINES']}")
    logger.info(f"Rate Limits: {config['MAX_LLM_CALLS_PER_MINUTE']}/min, {config['MAX_LLM_CALLS_PER_DAY']}/day")
    logger.info(f"Web UI User: {config['WEB_USERNAME']}")
    if config['SUDO_PASSWORD']:
        logger.warning("SUDO_PASSWORD is set in environment variables - SECURITY RISK.")
    if config['SUDO_USERNAME']:
        logger.info(f"SUDO Username (optional): {config['SUDO_USERNAME']}")


    return config

# Load configuration when the module is imported
try:
    settings = load_configuration()
except ValueError as e:
    # Use basic config here because full log setup might not be complete yet
    logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.critical(f"Configuration Error: {e}")
    print(f"FATAL CONFIGURATION ERROR: {e}")
    print("Ensure all required variables are set in your .env file (or environment).")
    exit(1)