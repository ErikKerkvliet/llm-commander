# llm-commander/log_setup.py
import logging

def setup_loggers():
    """Configures and returns the error and conversation loggers."""

    # --- Standard Error Logging ---
    try:
        logging.basicConfig(filename='error.log', level=logging.ERROR,
                            format='%(asctime)s - %(levelname)s - %(message)s [%(filename)s:%(lineno)d]')
        logging.info("Basic error logger configured.")
    except Exception as e:
        print(f"ERROR: Failed to set up basic error logger: {e}")
        # Fallback to console if file logging fails?
        logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')
        logging.error(f"Failed to set up file error logger: {e}", exc_info=True)


    # --- Conversation Logging Setup ---
    conversation_logger = logging.getLogger('ConversationLogger')
    # Prevent duplicate logs if setup is called multiple times (e.g., in testing)
    if not conversation_logger.handlers:
        conversation_logger.setLevel(logging.INFO)
        conversation_logger.propagate = False # Prevent propagation to root logger
        try:
            conv_handler = logging.FileHandler('conversation.log', encoding='utf-8')
            conv_handler.setLevel(logging.INFO)
            # Include conv_id in the format string
            conv_formatter = logging.Formatter('%(asctime)s - CONV_ID:%(conv_id)s - %(levelname)s - %(message)s')
            conv_handler.setFormatter(conv_formatter)
            conversation_logger.addHandler(conv_handler)
            logging.info("Conversation logger configured.")
        except Exception as log_setup_err:
            print(f"ERROR: Failed to set up conversation logger: {log_setup_err}")
            logging.error(f"Failed to set up conversation logger: {log_setup_err}", exc_info=True)
            # Consider setting conversation_logger to None or a dummy logger if it fails
            # conversation_logger = logging.getLogger('DummyConvLogger') # Or handle appropriately
    else:
        logging.info("Conversation logger already configured.")

    return logging.getLogger(), conversation_logger # Return root logger (for errors) and conversation logger

# Configure loggers when module is imported
error_logger, conversation_logger = setup_loggers()