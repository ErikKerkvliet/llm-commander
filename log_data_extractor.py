# llm-commander/log_data_extractor.py

import ast
import datetime
import re
import os
import logging # Import logging

from log_setup import LOGS_TASKS, error_logger # Import error_logger

logger = logging.getLogger(__name__) # Use a local logger for info/warnings

def extract_log_data(log_folder_name: str) -> dict | None: # Return None on failure
    """
    Extracts key information from a specific task's log file.

    Args:
        log_folder_name: The name of the folder within LOGS_TASKS.

    Returns:
        A dictionary containing task details, or None if extraction fails.
    """
    request = None
    commands_list = None
    status = "Unknown"  # <-- Initialize status to prevent UnboundLocalError
    timestamp = None    # <-- Initialize timestamp

    log_file_path = os.path.join(LOGS_TASKS, log_folder_name, 'task.log')

    # Try to create timestamp first from folder name
    timestamp = create_timestamp_from_string(log_folder_name)

    if not os.path.exists(log_file_path):
        logger.warning(f"Task log file not found: {log_file_path}")
        # Return minimal info based on folder name if file missing
        return {
            'id': log_folder_name,
            'prompt': 'Log file missing',
            'commands': [],
            'status': 'Incomplete (No Log)',
            'timestamp': timestamp # Use timestamp from folder name if possible
        }

    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            # Define patterns
            request_pattern = r"INFO - Initial Web Prompt: (.*)"
            commands_pattern = r"INFO - LLM Parsed Commands: (\[.*\])"
            # Updated pattern to be more flexible with log levels and spacing
            status_pattern = r"---\s*TASK END\s*\((.*?)\)\s*---"

            for line in f: # Read line by line for efficiency
                # Check for request
                if request is None: # Only find the first one
                    request_match = re.search(request_pattern, line)
                    if request_match:
                        request = request_match.group(1).strip()

                # Check for commands
                if commands_list is None: # Only find the first one
                    commands_match = re.search(commands_pattern, line)
                    if commands_match:
                        commands_str = commands_match.group(1).strip()
                        try:
                            # Safely evaluate the string representation of the list
                            parsed_commands = ast.literal_eval(commands_str)
                            # Basic validation
                            if isinstance(parsed_commands, list) and \
                               all(isinstance(item, str) for item in parsed_commands):
                                commands_list = parsed_commands
                            else:
                                logger.warning(f"Parsed commands are not a list of strings in {log_file_path}: {parsed_commands}")
                                commands_list = ['Error: Invalid command format'] # Indicate format error
                        except (ValueError, SyntaxError) as e:
                            logger.error(f"Error parsing commands string in {log_file_path} ('{commands_str}'): {e}")
                            commands_list = ['Error: Could not parse commands'] # Indicate parsing error

                # Check for status (keep checking, take the last one found)
                status_match = re.search(status_pattern, line, re.IGNORECASE) # Ignore case for INFO/WARN/ERROR
                if status_match:
                    found_status = status_match.group(1).strip()
                    if found_status: # Ensure status is not empty
                        status = found_status # Update with the latest found status

    except FileNotFoundError:
        # This case is handled by the os.path.exists check above, but good practice
        logger.error(f"File not found during processing (should not happen): {log_file_path}")
        return None # Indicate failure
    except Exception as e:
        logger.error(f"Error reading or processing log file {log_file_path}: {e}", exc_info=True)
        error_logger.error(f"Error reading log file {log_file_path}: {e}", exc_info=True) # Log to main error log too
        # Return partial data if possible, marking status as error
        return {
            'id': log_folder_name,
            'prompt': request or 'Error reading log',
            'commands': commands_list or ['Error reading log'],
            'status': 'Error Processing Log',
            'timestamp': timestamp
        }

    # Prepare final status string safely
    final_status_str = "Unknown"
    if isinstance(status, str) and status:
        final_status_str = status.replace("_", " ").capitalize() # Lowercase/Capitalize only if valid string
    elif status: # If status is not None/empty but not string (unlikely)
         final_status_str = str(status)

    return {
        'id': log_folder_name,
        'prompt': request if request is not None else 'Prompt not found',
        'commands': commands_list if commands_list is not None else [], # Return empty list if not found
        'status': final_status_str,
        'timestamp': timestamp # Already extracted or None
    }


def create_timestamp_from_string(log_string):
    """
    Extracts the date and time parts from a string formatted like
    'YYYYMMDD_HHMMSS_...' and creates a datetime object.

    Args:
        log_string: The input string containing the date and time.

    Returns:
        A datetime.datetime object representing the timestamp,
        or None if parsing fails.
    """
    try:
        match = re.match(r"(\d{8})_(\d{6})", log_string)
        if match:
            date_part, time_part = match.groups()
            datetime_str_part = date_part + time_part
            format_code = "%Y%m%d%H%M%S"
            timestamp_obj = datetime.datetime.strptime(datetime_str_part, format_code)
            return timestamp_obj
        else:
            logger.warning(f"Could not parse timestamp from folder name: '{log_string}'. Expected YYYYMMDD_HHMMSS_...")
            return None
    except ValueError as e:
        logger.error(f"Error parsing date/time from '{log_string}': {e}")
        return None
    except Exception as e: # Catch broader errors just in case
        logger.error(f"Unexpected error parsing timestamp from '{log_string}': {e}", exc_info=True)
        return None