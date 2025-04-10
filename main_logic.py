# llm-commander/main_logic.py
import os
import subprocess
import logging
import json
import time
import re
import uuid # To generate unique IDs for conversation logging
from datetime import datetime, timedelta
from collections import deque

# Try importing pexpect, handle import error for non-Unix systems
try:
    import pexpect
    PEXPECT_AVAILABLE = True
except ImportError:
    PEXPECT_AVAILABLE = False
    print("WARNING: 'pexpect' library not found. Interactive command execution will not be available.")
    print("         On Windows, consider using WSL or alternative libraries like 'weexpect'.")


import google.generativeai as genai
from dotenv import load_dotenv

# --- NEW: Import the filter ---
try:
    from output_filter import OutputFilter
except ImportError:
    print("ERROR: Could not import OutputFilter from output_filter.py. Make sure the file exists.")
    # Define a dummy filter if import fails to avoid NameError, but filtering won't work
    class OutputFilter:
        def filter(self, output_data: str, success: bool) -> str:
            print("WARNING: OutputFilter not loaded. Returning raw output.")
            return output_data
    # Potentially exit if filtering is critical? For now, just warn.
    # exit(1)


# --- Configuration & Initialization ---
load_dotenv()

# --- Standard Error Logging ---
# Basic setup, consider more robust configuration for production
logging.basicConfig(filename='error.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s [%(filename)s:%(lineno)d]')

# --- Conversation Logging Setup ---
conversation_logger = logging.getLogger('ConversationLogger')
conversation_logger.setLevel(logging.INFO)
conversation_logger.propagate = False
try:
    conv_handler = logging.FileHandler('conversation.log', encoding='utf-8')
    conv_handler.setLevel(logging.INFO)
    conv_formatter = logging.Formatter('%(asctime)s - CONV_ID:%(conv_id)s - %(levelname)s - %(message)s')
    conv_handler.setFormatter(conv_formatter)
    if not conversation_logger.handlers:
        conversation_logger.addHandler(conv_handler)
except Exception as log_setup_err:
    print(f"ERROR: Failed to set up conversation logger: {log_setup_err}")
    logging.error(f"Failed to set up conversation logger: {log_setup_err}", exc_info=True)


# --- Read Environment Variables ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
LLM_MODEL = os.getenv("LLM_MODEL", "gemini-2.0-flash-thinking-exp-01-21")
SUDO_USERNAME = os.getenv("SUDO_USERNAME")
SUDO_PASSWORD = os.getenv("SUDO_PASSWORD") # SECURITY RISK
REQUIRE_CONFIRMATION_STR = os.getenv("REQUIRE_CONFIRMATION", "False")
REQUIRE_CONFIRMATION = REQUIRE_CONFIRMATION_STR.strip().lower() == 'true'
SUCCESS_LINES_STR = os.getenv("FILTER_SUCCESS_LINES", "20") # Optional env var for filter
try:
    FILTER_SUCCESS_LINES = int(SUCCESS_LINES_STR)
except ValueError:
    print(f"Warning: Invalid FILTER_SUCCESS_LINES value '{SUCCESS_LINES_STR}', using default 20.")
    FILTER_SUCCESS_LINES = 20

print(f"--- Command execution confirmation required: {REQUIRE_CONFIRMATION} ---")
print(f"--- Output filter will keep last {FILTER_SUCCESS_LINES} lines on success ---")

# --- Instantiate the filter ---
output_filter = OutputFilter(success_lines=FILTER_SUCCESS_LINES)

# --- Rate Limiting State ---
MAX_CALLS_PER_MINUTE = int(os.getenv("MAX_LLM_CALLS_PER_MINUTE", 15))
MAX_CALLS_PER_DAY = int(os.getenv("MAX_LLM_CALLS_PER_DAY", 100))
api_call_times_minute = deque()
api_call_times_day = deque()

# --- Configure Gemini client ---
try:
    if not GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY not found in environment variables.")
    genai.configure(api_key=GEMINI_API_KEY)
    # Add generation_config or safety_settings if needed
    model = genai.GenerativeModel(LLM_MODEL)
    print(f"Successfully configured Gemini model: {LLM_MODEL}")
except Exception as e:
    logging.error(f"Fatal: Failed to configure Gemini: {e}", exc_info=True)
    print(f"FATAL ERROR: Failed to configure Gemini. Check API Key and model name in .env. Error: {e}")
    exit(1) # Exit if LLM cannot be configured


# --- Rate Limiting Functions ---
def check_rate_limit():
    """Checks if an API call is allowed based on rate limits."""
    now = datetime.now()
    one_minute_ago = now - timedelta(minutes=1)
    while api_call_times_minute and api_call_times_minute[0] < one_minute_ago:
        api_call_times_minute.popleft()
    one_day_ago = now - timedelta(days=1)
    while api_call_times_day and api_call_times_day[0] < one_day_ago:
        api_call_times_day.popleft()
    if len(api_call_times_minute) >= MAX_CALLS_PER_MINUTE:
        logging.warning("Rate limit per minute exceeded.")
        return False, "Rate limit per minute exceeded."
    if len(api_call_times_day) >= MAX_CALLS_PER_DAY:
        logging.warning("Rate limit per day exceeded.")
        return False, "Rate limit per day exceeded."
    return True, "OK"

def record_api_call():
    """Records the timestamp of an API call."""
    now = datetime.now()
    api_call_times_minute.append(now)
    api_call_times_day.append(now)

# --- LLM Command Generation ---
def get_llm_commands(prompt_text, conv_id):
    """Gets commands from the LLM, logs interaction to conversation log."""
    log_extra = {'conv_id': conv_id}

    allowed, message = check_rate_limit()
    if not allowed:
        logging.error(f"Rate limit hit: {message}", extra=log_extra)
        conversation_logger.error(f"LLM Call Aborted (Command Gen): Rate limit hit: {message}", extra=log_extra)
        raise Exception(f"Rate limit exceeded: {message}")

    system_prompt = """
You are an expert system administrator AI assistant. Your ONLY task is to translate user requests or error messages into a sequence of shell commands runnable on a Linux-based system.
Respond ONLY with a valid JSON object containing a single key "commands". The value of "commands" MUST be a list of strings. Each string is a single shell command to be executed in sequence.
Do NOT include any explanations, apologies, conversational text, markdown formatting, or anything other than the JSON object.
If you cannot determine appropriate commands or the request is unclear/unsafe, respond with: {"commands": []}
"""
    full_prompt = f"{system_prompt}\n\nUser Request/Error:\n{prompt_text}"

    conversation_logger.info(f"LLM Prompt (Command Gen):\n{full_prompt}", extra=log_extra)
    print(f"Sending command generation prompt to LLM (ConvID: {conv_id})...")

    try:
        record_api_call()
        response = model.generate_content(full_prompt)
        raw_response_text = response.text.strip()

        conversation_logger.info(f"LLM Raw Response (Command Gen):\n{raw_response_text}", extra=log_extra)

        # Handle potential markdown code block wrappers
        if raw_response_text.startswith("```json"): raw_response_text = raw_response_text[7:]
        if raw_response_text.endswith("```"): raw_response_text = raw_response_text[:-3]
        raw_response_text = raw_response_text.strip()

        try:
            parsed_json = json.loads(raw_response_text)
        except json.JSONDecodeError as json_e:
            error_msg = f"LLM response (commands) was not valid JSON: {json_e}. Response: {raw_response_text}"
            logging.error(error_msg, exc_info=True, extra=log_extra)
            conversation_logger.error(f"LLM Response Parse Error (Command Gen): {error_msg}", extra=log_extra)
            raise ValueError(f"LLM command response was not valid JSON.") from json_e

        # Validate structure
        if not isinstance(parsed_json, dict) or "commands" not in parsed_json:
             conversation_logger.error(f"LLM Invalid Structure (Command Gen): Missing 'commands' key. Response: {parsed_json}", extra=log_extra)
             raise ValueError("LLM JSON (commands) missing 'commands' key.")
        commands = parsed_json["commands"]
        if not isinstance(commands, list):
             conversation_logger.error(f"LLM Invalid Structure (Command Gen): 'commands' not a list. Response: {parsed_json}", extra=log_extra)
             raise ValueError("'commands' value must be a list.")
        if not all(isinstance(cmd, str) for cmd in commands):
             conversation_logger.error(f"LLM Invalid Structure (Command Gen): Command list has non-string. Response: {parsed_json}", extra=log_extra)
             raise ValueError("Command list contains non-string elements.")

        conversation_logger.info(f"LLM Parsed Commands: {commands}", extra=log_extra)
        print(f"LLM proposed commands (ConvID: {conv_id}): {commands}")
        return commands

    except Exception as e:
        logging.error(f"Error during LLM command generation call or processing: {e}", exc_info=True, extra=log_extra)
        conversation_logger.error(f"LLM Call/Processing Error (Command Gen): {e}", exc_info=True, extra=log_extra)
        raise Exception(f"Error interacting with LLM for command generation: {e}") from e


# --- LLM Interactive Response Generation ---
def get_llm_interactive_response(prompt_context: str, original_goal: str, conv_id):
    """Gets a suggested response from the LLM for an interactive prompt, logs interaction."""
    log_extra = {'conv_id': conv_id}

    allowed, message = check_rate_limit()
    if not allowed:
        logging.error(f"Rate limit hit for interactive response: {message}", extra=log_extra)
        conversation_logger.error(f"LLM Call Aborted (Interactive): Rate limit hit: {message}", extra=log_extra)
        raise Exception(f"Rate limit exceeded (interactive): {message}")

    system_prompt = """
You are an AI assistant helping to automate a command-line task.
A command has paused and is asking for input. Based on the command's output shown below and the original goal, provide ONLY the text that should be entered as a response to the prompt.
Do NOT provide explanations, apologies, or any text other than the direct input needed.
If unsure, provide a neutral or common default (like 'y' for yes/no prompts if the goal implies continuation). If sensitive input like a password (other than sudo) is required, state you cannot provide it. Be concise.

Original Goal: "{goal}"

Command Output Snippet (containing the prompt):
---
{context}
---

Your suggested input:"""
    full_prompt = system_prompt.format(goal=original_goal, context=prompt_context)

    conversation_logger.info(f"LLM Prompt (Interactive Resp):\n{full_prompt}", extra=log_extra)
    print(f"Sending interactive prompt context to LLM (ConvID: {conv_id})...")

    try:
        record_api_call()
        # Consider adding specific generation config if needed (e.g., stop sequences)
        response = model.generate_content(full_prompt)
        answer = response.text.strip()

        conversation_logger.info(f"LLM Raw Response (Interactive Resp): {answer}", extra=log_extra)

        # Basic cleanup
        if (answer.startswith('"') and answer.endswith('"')) or \
           (answer.startswith("'") and answer.endswith("'")):
            answer = answer[1:-1]

        conversation_logger.info(f"LLM Cleaned Response (Interactive Resp): '{answer}'", extra=log_extra)
        print(f"LLM suggested interactive response (ConvID: {conv_id}): '{answer}'")
        return answer

    except Exception as e:
        logging.error(f"Error during LLM interactive response call: {e}", exc_info=True, extra=log_extra)
        conversation_logger.error(f"LLM Call/Processing Error (Interactive Resp): {e}", exc_info=True, extra=log_extra)
        raise Exception(f"Error interacting with LLM for interactive response: {e}") from e


# --- Command Execution using pexpect (with enhanced logging) ---
def execute_commands(commands: list, original_goal: str, conv_id) -> tuple[bool, str, str]:
    """
    Executes commands using pexpect, handling interactive prompts via LLM,
    and logging prompt/response pairs. Logs interaction to conversation log.
    Returns: (success: bool, aggregated_log: str, aggregated_stderr: str)
    """
    log_extra = {'conv_id': conv_id}
    if not PEXPECT_AVAILABLE:
        error_msg = "Cannot execute commands: pexpect library is not available on this system."
        logging.error(error_msg, extra=log_extra)
        conversation_logger.error("Pexpect not available, cannot execute interactively.", extra=log_extra)
        return False, "", error_msg

    full_log = "" # Combined raw log of interaction for returning
    final_stderr = "" # Collect specific error output for returning
    overall_success = True

    if not commands:
        print("No commands to execute.")
        conversation_logger.info("No commands proposed by LLM to execute.", extra=log_extra)
        return True, "No commands to execute.", ""

    conversation_logger.info(f"Starting execution of {len(commands)} commands.", extra=log_extra)

    for cmd_idx, cmd in enumerate(commands):
        if not cmd or not isinstance(cmd, str) or cmd.isspace():
            print(f"Skipping empty/invalid command string: {cmd!r}")
            conversation_logger.warning(f"Skipping empty command string: {cmd!r}", extra=log_extra)
            continue

        print(f"\n--- Executing Command {cmd_idx+1}/{len(commands)} (Interactive): {cmd} ---")
        cmd_log_header = f"\n\n>>> EXEC ({cmd_idx+1}/{len(commands)}): $ {cmd}\n"
        full_log += cmd_log_header
        conversation_logger.info(f"Executing Command: $ {cmd}", extra=log_extra)
        child = None
        prompt_context_for_log = "" # Keep track of context for error logging
        try:
            child = pexpect.spawn('/bin/bash', ['-c', cmd], timeout=300, encoding='utf-8', echo=False)

            # Define patterns
            patterns = [
                pexpect.EOF,                                # 0
                pexpect.TIMEOUT,                            # 1
                r"(?:\[sudo\] )?password for .*?: ?",        # 2: Sudo password prompt
                r"(\(yes/no\)|\[Y[ea]*s?/N[o]?[au]*\?*\])",  # 3: Yes/No prompts
                r"(?i)are you sure you want to continue\?", # 4: Confirmation prompt
                r"(?i)enter .*?: ?",                        # 5: Generic 'Enter X:' prompt
                # Add more specific, less ambiguous patterns if possible
            ]
            compiled_patterns = [pat if isinstance(pat, (int, type(pexpect.EOF), type(pexpect.TIMEOUT))) else re.compile(pat, re.IGNORECASE) for pat in patterns]

            while True: # Interaction loop for this command
                try:
                    index = child.expect(compiled_patterns)

                    output_before = child.before # Keep raw output
                    matched_prompt_text = child.after if index > 1 else ""
                    prompt_context_for_log = (output_before + matched_prompt_text).strip()

                    if output_before:
                        print(f"Output:\n{output_before.strip()}")
                        full_log += output_before # Add raw output to main log
                        conversation_logger.info(f"Output Received:\n{output_before.strip()}", extra=log_extra)

                    # Handle based on the matched pattern index
                    if index == 0: # EOF
                        print("Command finished (EOF).")
                        full_log += "--- Command End (EOF) ---\n"
                        conversation_logger.info("Command execution reached EOF.", extra=log_extra)
                        break

                    elif index == 1: # TIMEOUT
                        raise pexpect.TIMEOUT("Command timed out.")

                    elif index == 2: # Sudo password prompt
                        print(f"Prompt Detected: {matched_prompt_text.strip()}")
                        log_msg = f"[PROMPT DETECTED]:\n{prompt_context_for_log}\n"
                        full_log += log_msg
                        conversation_logger.info(f"Sudo Prompt Detected:\n{prompt_context_for_log}", extra=log_extra)
                        if SUDO_PASSWORD:
                            print("Sending sudo password...")
                            child.sendline(SUDO_PASSWORD)
                            log_msg = "[RESPONSE SENT]: [sudo password]\n"
                            full_log += log_msg
                            conversation_logger.info("Sent sudo password.", extra=log_extra)
                        else:
                             log_msg = "[ERROR]: Sudo prompt detected, but SUDO_PASSWORD not set.\n"
                             full_log += log_msg
                             conversation_logger.error("Sudo prompt detected, but SUDO_PASSWORD not set.", extra=log_extra)
                             raise ValueError("Sudo prompt detected, but SUDO_PASSWORD not set in .env")

                    elif index >= 3: # Interactive prompt detected
                         print(f"Interactive Prompt Detected: {matched_prompt_text.strip()}")
                         log_msg = f"[PROMPT DETECTED]:\n{prompt_context_for_log}\n"
                         full_log += log_msg
                         conversation_logger.info(f"Interactive Prompt Detected:\n{prompt_context_for_log}", extra=log_extra)
                         print(f"Asking LLM for response...")
                         prompt_text_for_llm = prompt_context_for_log # Use full context
                         try:
                             llm_answer = get_llm_interactive_response(prompt_text_for_llm, original_goal, conv_id)
                             print(f"Sending LLM response: '{llm_answer}'")
                             child.sendline(llm_answer)
                             log_msg = f"[RESPONSE SENT (LLM)]: {llm_answer}\n"
                             full_log += log_msg
                             conversation_logger.info(f"Sent LLM Response: '{llm_answer}'", extra=log_extra)
                         except Exception as llm_err:
                              error_msg = f"Failed to get/send LLM response for interactive prompt: {llm_err}"
                              log_msg = f"[ERROR]: {error_msg}\n"
                              full_log += log_msg
                              conversation_logger.error(f"LLM Interactive Response Error: {llm_err}", extra=log_extra)
                              raise RuntimeError(error_msg) from llm_err

                    # Continue interaction loop

                # --- Error Handling within Interaction Loop ---
                except pexpect.TIMEOUT:
                    overall_success = False; error_msg = f"Command timed out: '{cmd}'"
                    print(f"ERROR: {error_msg}"); final_stderr += error_msg + "\n"; logging.error(error_msg, extra=log_extra)
                    conversation_logger.error(f"Execution TIMEOUT for command: $ {cmd}", extra=log_extra)
                    if child: child.close(force=True); break # Force close and break inner loop
                except EOFError: # Should be caught by pexpect.EOF, but handle defensively
                     overall_success = False; error_msg = f"EOF occurred unexpectedly: '{cmd}'"
                     print(f"ERROR: {error_msg}"); final_stderr += error_msg + "\n"; logging.error(error_msg, extra=log_extra)
                     conversation_logger.error(f"Unexpected EOF for command: $ {cmd}", extra=log_extra)
                     if child: child.close(force=True); break # Force close and break inner loop
                except Exception as interaction_err: # Catch other errors during expect/send
                     overall_success = False; error_msg = f"Error during interactive execution of '{cmd}': {interaction_err}"
                     # Log context available at point of error
                     log_context_err = f"[ERROR DURING INTERACTION]: Context:\n{prompt_context_for_log}\nError: {interaction_err}\n"
                     full_log += log_context_err # Add error context to main log
                     print(f"ERROR: {error_msg}"); final_stderr += error_msg + "\n"; logging.error(error_msg, exc_info=True, extra=log_extra)
                     conversation_logger.error(f"Interaction Error for command: $ {cmd}\nContext:\n{prompt_context_for_log}\nError: {interaction_err}", exc_info=True, extra=log_extra)
                     if child: child.close(force=True); break # Force close and break inner loop
                # --- End Error Handling ---

            # After the interaction loop (EOF or error break)
            if child and not child.closed:
                try:
                    # Read any final output
                    remaining_output = child.read().strip()
                    if remaining_output:
                         print(f"Remaining Output:\n{remaining_output}")
                         full_log += remaining_output + "\n" # Add final output to main log
                         conversation_logger.info(f"Final Output Received:\n{remaining_output}", extra=log_extra)
                         full_log += "--- Command End (Final Read) ---\n"
                except Exception as read_err:
                     print(f"Warning: Error reading final output: {read_err}")
                     log_warn = f"[WARNING]: Error reading final output: {read_err}\n"
                     full_log += log_warn
                     conversation_logger.warning(f"Error reading final output: {read_err}", extra=log_extra)
                child.close() # Close gracefully if possible

            # Check exit/signal status
            exit_status = child.exitstatus if child else None
            signal_status = child.signalstatus if child else None
            conversation_logger.info(f"Command finished. Exit Status: {exit_status}, Signal Status: {signal_status}", extra=log_extra)

            if exit_status is not None and exit_status != 0:
                overall_success = False; error_msg = f"Command '{cmd}' exited with non-zero status: {exit_status}"
                print(f"ERROR: {error_msg}"); final_stderr += error_msg + "\n"; logging.error(error_msg, extra=log_extra)
                conversation_logger.error(f"Command failed: $ {cmd} - Exit Status: {exit_status}", extra=log_extra)
                break # Stop processing further commands in this attempt
            elif signal_status is not None:
                 overall_success = False; error_msg = f"Command '{cmd}' terminated by signal: {signal_status}"
                 print(f"ERROR: {error_msg}"); final_stderr += error_msg + "\n"; logging.error(error_msg, extra=log_extra)
                 conversation_logger.error(f"Command failed: $ {cmd} - Terminated by Signal: {signal_status}", extra=log_extra)
                 break # Stop processing further commands in this attempt

        except Exception as e:
            # Catch errors during pexpect.spawn or outside the inner loop
            overall_success = False; err_msg = f"Error setting up/finalizing execution for '{cmd}': {e}"
            print(f"ERROR: {err_msg}"); final_stderr += err_msg + "\n"; logging.error(err_msg, exc_info=True, extra=log_extra)
            conversation_logger.error(f"Outer Execution Error for command: $ {cmd} - Error: {e}", exc_info=True, extra=log_extra)
            if child and not child.closed:
                child.close(force=True) # Ensure child is closed
            break # Stop processing further commands in this attempt

        # Break outer command loop if failure occurred in this command
        if not overall_success:
             break

    # Log end of block execution
    conversation_logger.info(f"Finished execution block. Overall success this block: {overall_success}", extra=log_extra)
    print("--- Command Execution Block Finished ---")
    # Return the full raw log and any specific errors collected
    return overall_success, full_log.strip(), final_stderr.strip()


# --- Main Processing Loop ---
def process_prompt_and_execute(initial_prompt: str, max_retries: int = 3):
    """
    Takes prompt, gets/executes commands (interactively), confirms, retries.
    Filters stdout output before logging/returning. Logs conversation flow.
    Returns: (overall_success: bool, results_log: list)
    """
    conv_id = str(uuid.uuid4())
    log_extra = {'conv_id': conv_id}

    conversation_logger.info(f"--- NEW TASK START ---", extra=log_extra)
    conversation_logger.info(f"Initial Web Prompt: {initial_prompt}", extra=log_extra)
    conversation_logger.info(f"Max Retries: {max_retries}", extra=log_extra)

    current_prompt = initial_prompt
    results_log = [] # For returning structured results to web UI
    overall_success = False

    for attempt in range(max_retries + 1):
        print(f"\n--- Attempt {attempt + 1}/{max_retries + 1} (ConvID: {conv_id}) ---")
        conversation_logger.info(f"--- Starting Attempt {attempt + 1}/{max_retries + 1} ---", extra=log_extra)
        attempt_data = {
            "attempt": attempt + 1,
            "prompt_sent": current_prompt, # Log the prompt used for *this* attempt
            "llm_commands": [],
            "execution_success": False,
            "stdout": "", # Will store FILTERED output
            "stderr": ""  # Will store raw error output
        }
        proceed_with_execution = True
        raw_log_output_for_retry = "" # Store raw output from execute_commands for potential retry prompt

        try:
            # 1. Get commands from LLM
            commands = get_llm_commands(current_prompt, conv_id)
            attempt_data["llm_commands"] = commands

            # 2. Confirmation Step
            if REQUIRE_CONFIRMATION and commands:
                print("\n################ CONFIRMATION REQUIRED ################")
                conversation_logger.info("Confirmation required. Displaying commands to user.", extra=log_extra)
                print("LLM proposes the following commands:")
                for i, cmd in enumerate(commands): print(f"  {i+1}: {cmd}")
                print("-----------------------------------------------------")
                try:
                    # Prompt appears in the terminal running the server
                    response = input(">>> Execute these commands? (yes/no): ").lower().strip()
                    if response != 'yes':
                        proceed_with_execution = False
                        print("--- Execution cancelled by user. ---")
                        attempt_data["stderr"] = "Execution cancelled by user."
                        conversation_logger.warning("Execution cancelled by user confirmation.", extra=log_extra)
                except Exception as input_err: # Catch EOFError or other issues
                    proceed_with_execution = False
                    print(f"--- Error/EOF during confirmation: {input_err}. Cancelling execution. ---")
                    attempt_data["stderr"] = f"Execution cancelled (confirmation error: {input_err})."
                    conversation_logger.error(f"Execution cancelled due to confirmation error: {input_err}", extra=log_extra)

                if not proceed_with_execution:
                     results_log.append(attempt_data) # Log cancelled attempt to UI results
                     overall_success = False # User cancelled, overall fails for this task
                     conversation_logger.warning("--- TASK END (Cancelled by Confirmation) ---", extra=log_extra)
                     break # Exit retry loop for this task

            # 3. Execute commands (if proceeding)
            if proceed_with_execution:
                if commands:
                    # Execute and get RAW output first
                    exec_success, raw_log_output_for_retry, error_output = execute_commands(commands, initial_prompt, conv_id)

                    # Filter the raw output for UI/final log
                    filtered_log_output = output_filter.filter(raw_log_output_for_retry, exec_success)

                    # Store filtered output for UI/final log
                    attempt_data["execution_success"] = exec_success
                    attempt_data["stdout"] = filtered_log_output # Store filtered version
                    attempt_data["stderr"] = error_output # Keep stderr raw

                    # Log filtered output to conversation log
                    conversation_logger.info(f"Execution Result (Attempt {attempt+1}): Success={exec_success}", extra=log_extra)
                    if filtered_log_output:
                        conversation_logger.info(f"Execution Log (stdout/filtered):\n{filtered_log_output}", extra=log_extra)
                    if error_output:
                        conversation_logger.error(f"Execution Errors (stderr):\n{error_output}", extra=log_extra)

                else:
                    # No commands proposed
                    print("LLM returned no commands. Nothing to execute.")
                    attempt_data["execution_success"] = True # No failure occurred
                    attempt_data["stderr"] = "LLM returned no commands."
                    conversation_logger.info("LLM returned no commands, skipping execution.", extra=log_extra)
                    results_log.append(attempt_data) # Log this state
                    break # Exit loop, nothing more to do

                results_log.append(attempt_data) # Append attempt data AFTER execution/filtering

                # 4. Check result and decide next step
                if exec_success:
                    print("Commands executed successfully in this attempt.")
                    overall_success = True
                    conversation_logger.info(f"--- TASK END (Success on Attempt {attempt+1}) ---", extra=log_extra)
                    break # Success, exit the retry loop
                else:
                    # Execution failed
                    print(f"Command execution failed in this attempt.")
                    if attempt < max_retries:
                        print("Feeding error back to LLM for correction...")
                        # Use RAW output for LLM context
                        # Prioritize stderr, otherwise use tail of RAW stdout/log
                        # Limit context size to avoid overly large prompts
                        error_context_for_llm = error_output if error_output else raw_log_output_for_retry[-1500:]
                        current_prompt = (
                            f"The previous attempt failed.\n"
                            f"Original Goal: '{initial_prompt}'\n"
                            f"Commands Tried: {commands}\n"
                            f"Error/Output Log:\n{error_context_for_llm}\n\n" # Use raw context
                            f"Provide corrected commands."
                        )
                        conversation_logger.info(f"Execution failed (Attempt {attempt+1}). Preparing retry prompt.", extra=log_extra)
                        # The prompt for the *next* attempt will be logged by get_llm_commands
                    else:
                        # Max retries reached
                        print("Max retries reached. Stopping.")
                        overall_success = False
                        conversation_logger.warning(f"--- TASK END (Failed - Max Retries Reached) ---", extra=log_extra)
                        break # Exit loop

        except Exception as e:
            # Handle critical errors in the loop
            err_msg = f"Critical error (attempt {attempt + 1}, ConvID: {conv_id}): {e}"
            print(f"ERROR: {err_msg}")
            # Log to both logs
            logging.error(err_msg, exc_info=True, extra=log_extra)
            conversation_logger.critical(f"--- TASK END (Critical Error) ---\nError: {e}", exc_info=True, extra=log_extra)
            # Update attempt data for UI
            attempt_data["stderr"] = f"Application Error: {e}"
            attempt_data["execution_success"] = False
            # Ensure this failed attempt is added to results_log if not already there
            if not any(att for att in results_log if att['attempt'] == attempt + 1):
                 results_log.append(attempt_data)
            overall_success = False
            break # Stop processing on critical error

    # Final log entry if loop completes or breaks in certain ways
    # This ensures a task end marker is logged even if specific conditions aren't met above
    # Avoid double logging if already logged (e.g., success, max retries, cancelled)
    last_log_entry = conversation_logger.handlers[0].stream.tell() if conversation_logger.handlers else 0 # Crude check
    if last_log_entry > 0: # Check if anything was logged
         # A more robust check might involve tracking if an END marker was logged explicitly
         pass # Assume previous logic handled end state logging

    # Fallback log if no other end condition logged it
    if not results_log or not any("TASK END" in msg for msg in ["TODO: Get last few log messages"]): # Requires better check
         if overall_success:
             conversation_logger.info(f"--- TASK END (Completed) ---", extra=log_extra)
         else:
             conversation_logger.warning(f"--- TASK END (Failed/Unknown State) ---", extra=log_extra)


    return overall_success, results_log
