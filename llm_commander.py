# --- START OF FILE llm-commander/llm_commander.py ---

# llm-commander/llm_commander.py
import uuid
import logging
import time # Keep for potential future delays if needed
import os
from datetime import datetime

from config import settings # Import loaded configuration
from log_setup import error_logger, LOGS_DIR # Import configured loggers and base log dir
from llm_client import LLMClient
from command_executor import CommandExecutor
from output_filter import OutputFilter

class LLMCommanderApp:
    """
    Main application class for LLM Commander.
    Orchestrates getting commands from LLM, executing them, handling retries,
    and filtering output. Manages dynamic task logging.
    """

    def __init__(self):
        """Initializes the application components."""
        self.config = settings
        self.error_logger = error_logger # Use the globally configured error logger
        self.logs_base_dir = LOGS_DIR # Base directory for all logs

        # Instantiate components, passing necessary config/dependencies
        self.llm_client = LLMClient(
            api_key=self.config['GEMINI_API_KEY'],
            model_name=self.config['LLM_MODEL'],
            max_calls_minute=self.config['MAX_LLM_CALLS_PER_MINUTE'],
            max_calls_day=self.config['MAX_LLM_CALLS_PER_DAY']
        )
        self.executor = CommandExecutor(
            llm_client=self.llm_client,
            sudo_password=self.config['SUDO_PASSWORD'] # Pass sudo password
        )
        self.output_filter = OutputFilter(
            success_lines=self.config['FILTER_SUCCESS_LINES']
        )
        self.require_confirmation = self.config['REQUIRE_CONFIRMATION']

        self.error_logger.info("LLMCommanderApp initialized successfully.")
        print(f"--- Command execution confirmation required: {self.require_confirmation} ---")
        print(f"--- Output filter will keep last {self.config['FILTER_SUCCESS_LINES']} lines on success ---")

    def _setup_task_logging(self, conv_id: str) -> tuple[logging.Logger, str, logging.FileHandler]:
        """Sets up logging handlers for a specific task."""
        now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        conv_log_dir = os.path.join(self.logs_base_dir, 'tasks', f"{now_str}_{conv_id}")
        os.makedirs(conv_log_dir, exist_ok=True)

        task_logger_name = f'TaskLogger_{conv_id}'
        task_logger = logging.getLogger(task_logger_name)
        task_logger.setLevel(logging.INFO)
        task_logger.propagate = False # Don't send to parent loggers

        # Ensure handler is not added multiple times if function is called again for same ID (unlikely)
        if any(isinstance(h, logging.FileHandler) and task_logger_name in h.name for h in task_logger.handlers):
             # Find existing handler (logic might need refinement based on handler naming)
             handler = next((h for h in task_logger.handlers if isinstance(h, logging.FileHandler) and task_logger_name in h.name), None)
             return task_logger, conv_log_dir, handler

        # Create and add file handler for task.log
        conv_log_file = os.path.join(conv_log_dir, 'task.log')
        handler = logging.FileHandler(conv_log_file, encoding='utf-8')
        handler.setLevel(logging.INFO)
        # Formatter doesn't need conv_id anymore, it's implicit in the file path
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        # Give handler a name for easier removal later
        handler.name = f"{task_logger_name}_file_handler"

        task_logger.addHandler(handler)
        return task_logger, conv_log_dir, handler

    def _cleanup_task_logging(self, task_logger: logging.Logger, handler: logging.FileHandler):
        """Removes and closes the handler for a task logger."""
        if handler:
            try:
                handler.close()
                task_logger.removeHandler(handler)
            except Exception as e:
                self.error_logger.error(f"Error closing/removing log handler for {task_logger.name}: {e}", exc_info=True)


    def process_task(self, initial_prompt: str, max_retries: int = 3) -> tuple[bool, list]:
        """
        Processes a user prompt through the LLM and execution cycle.

        Args:
            initial_prompt: The initial user request or error message.
            max_retries: The maximum number of retry attempts on failure.

        Returns:
            A tuple containing:
            - overall_success (bool): True if the task succeeded, False otherwise.
            - results_log (list): A list of dictionaries, each detailing an attempt.
        """
        conv_id = str(uuid.uuid4())
        task_logger, conv_log_dir, task_log_handler = None, None, None # Initialize
        task_end_logged = False # <<< Initialize flag to track if end message was logged

        try:
            # --- Setup Task-Specific Logging ---
            task_logger, conv_log_dir, task_log_handler = self._setup_task_logging(conv_id)
            output_log_file = os.path.join(conv_log_dir, 'output.log') # Define output log path

            task_logger.info(f"--- NEW TASK START (ConvID: {conv_id}) ---")
            task_logger.info(f"Log Directory: {conv_log_dir}")
            task_logger.info(f"Initial Web Prompt: {initial_prompt}")
            task_logger.info(f"Max Retries: {max_retries}")
            print(f"\n=== Starting New Task (ConvID: {conv_id}) ===")
            print(f"Initial Prompt: {initial_prompt}")
            print(f"Detailed logs in: {conv_log_dir}")

            current_prompt = initial_prompt
            results_log = [] # For returning structured results
            overall_success = False
            full_raw_output = "" # Accumulate raw output across all attempts for the final output.log

            for attempt in range(max_retries + 1):
                print(f"\n--- Attempt {attempt + 1}/{max_retries + 1} (ConvID: {conv_id}) ---")
                task_logger.info(f"--- Starting Attempt {attempt + 1}/{max_retries + 1} ---")
                attempt_data = {
                    "attempt": attempt + 1,
                    "prompt_sent": current_prompt,
                    "llm_commands": [],
                    "execution_success": False,
                    "stdout": "", # Filtered output for UI
                    "stderr": ""  # Raw error output for UI
                }
                proceed_with_execution = True
                raw_log_output_this_attempt = "" # Store raw output for this specific attempt for retry context

                try:
                    # 1. Get commands from LLM
                    print("Requesting commands from LLM...")
                    # Pass the task-specific logger
                    commands = self.llm_client.get_llm_commands(current_prompt, conv_id, task_logger)
                    attempt_data["llm_commands"] = commands
                    print(f"LLM proposed commands: {commands}")
                    # Note: LLMClient now logs details using task_logger

                    # 2. Confirmation Step
                    if self.require_confirmation and commands:
                        print("\n################ CONFIRMATION REQUIRED ################")
                        task_logger.info("Confirmation required. Displaying commands.")
                        print("LLM proposes the following commands:")
                        for i, cmd in enumerate(commands): print(f"  {i+1}: {cmd}")
                        print("-----------------------------------------------------")
                        try:
                            # Prompt appears in the terminal running the *server*
                            response = input(">>> Execute these commands? (yes/no): ").lower().strip()
                            if response != 'yes' and response != 'y':
                                proceed_with_execution = False
                                print("--- Execution cancelled by user. ---")
                                attempt_data["stderr"] = "Execution cancelled by user."
                                task_logger.warning("Execution cancelled by user confirmation.")
                        except Exception as input_err:
                            proceed_with_execution = False
                            err_msg = f"Execution cancelled (confirmation error: {input_err})."
                            print(f"--- Error during confirmation: {input_err}. Cancelling execution. ---")
                            attempt_data["stderr"] = err_msg
                            # Log to main error log AND task log
                            self.error_logger.error(f"Confirmation input error (ConvID: {conv_id}): {input_err}", exc_info=True)
                            task_logger.error(f"Execution cancelled due to confirmation error: {input_err}")

                        if not proceed_with_execution:
                            results_log.append(attempt_data)
                            overall_success = False
                            task_logger.warning("--- TASK END (Cancelled by Confirmation) ---")
                            task_end_logged = True # <<< Set flag
                            break # Exit retry loop for this task

                    # 3. Execute commands (if proceeding)
                    if proceed_with_execution:
                        if commands:
                            # Execute using the CommandExecutor instance, passing the task logger
                            exec_success, raw_log_output_this_attempt, error_output = self.executor.execute_commands(
                                commands, initial_prompt, conv_id, task_logger
                            )
                            # Accumulate raw output for the final output.log file
                            full_raw_output += f"\n\n--- Attempt {attempt + 1} Raw Output ---\n" + raw_log_output_this_attempt

                            # Filter the raw output using the OutputFilter instance
                            filtered_log_output = self.output_filter.filter(raw_log_output_this_attempt, exec_success)

                            # Store results for this attempt (for UI)
                            attempt_data["execution_success"] = exec_success
                            attempt_data["stdout"] = filtered_log_output # Store filtered version
                            attempt_data["stderr"] = error_output # Keep stderr raw

                            # Log filtered output summary to task log
                            task_logger.info(f"Execution Result (Attempt {attempt+1}): Success={exec_success}")
                            if filtered_log_output:
                                task_logger.info(f"Execution Log Summary (stdout/filtered):\n{filtered_log_output}")
                            if error_output:
                                # Specific errors already logged by executor using task_logger
                                task_logger.error(f"Execution Errors Summary (stderr):\n{error_output}")

                        else:
                            # No commands proposed
                            print("LLM returned no commands. Nothing to execute.")
                            attempt_data["execution_success"] = True # No failure occurred
                            attempt_data["stdout"] = "LLM returned no commands."
                            task_logger.info("LLM returned no commands, skipping execution.")
                            results_log.append(attempt_data) # Log this state
                            overall_success = True # Considered success if no commands needed/returned
                            task_logger.info("--- TASK END (No Commands to Execute) ---")
                            task_end_logged = True # <<< Set flag
                            break # Exit loop, nothing more to do

                        results_log.append(attempt_data) # Append attempt data AFTER execution/filtering

                        # 4. Check result and decide next step
                        if exec_success:
                            print(f"--- Attempt {attempt + 1} Succeeded ---")
                            overall_success = True
                            task_logger.info(f"--- TASK END (Success on Attempt {attempt+1}) ---")
                            task_end_logged = True # <<< Set flag
                            break # Success, exit the retry loop
                        else:
                            # Execution failed
                            print(f"--- Attempt {attempt + 1} Failed ---")
                            if attempt < max_retries:
                                print("Preparing retry prompt for LLM...")
                                # Use RAW output from *this attempt* for LLM context
                                error_context_for_llm = error_output if error_output else raw_log_output_this_attempt[-1500:] # Limit context
                                current_prompt = (
                                    f"The previous attempt to achieve the goal failed.\n"
                                    f"Original Goal: '{initial_prompt}'\n"
                                    f"Commands Tried in Failed Attempt: {commands}\n"
                                    f"Error/Output Log from Failed Attempt:\n---\n{error_context_for_llm}\n---\n\n"
                                    f"Analyze the error and the original goal, then provide corrected shell commands to achieve the goal. Respond ONLY with the JSON object."
                                )
                                task_logger.info(f"Execution failed (Attempt {attempt+1}). Preparing retry.")
                                # Next loop iteration will call get_llm_commands with this new prompt
                            else:
                                # Max retries reached
                                print("Max retries reached. Stopping.")
                                overall_success = False
                                task_logger.warning(f"--- TASK END (Failed - Max Retries Reached) ---")
                                task_end_logged = True # <<< Set flag
                                break # Exit loop

                except Exception as e:
                    # Handle critical errors during LLM calls or other parts of the loop
                    err_msg = f"Critical error during attempt {attempt + 1} (ConvID: {conv_id}): {e}"
                    print(f"ERROR: {err_msg}")
                    # Log to main error log AND task log
                    self.error_logger.critical(err_msg, exc_info=True)
                    if task_logger: # Check if logger was set up before error
                         task_logger.critical(f"--- TASK END (Critical Error during Attempt {attempt + 1}) ---\nError: {e}", exc_info=True)
                         task_end_logged = True # <<< Set flag
                    else:
                         self.error_logger.critical(f"Task {conv_id} failed before logger setup: {e}", exc_info=True)


                    # Update attempt data for UI
                    attempt_data["stderr"] = f"Application Error: {e}"
                    attempt_data["execution_success"] = False
                    # Ensure this failed attempt is added to results_log if not already
                    if not any(att for att in results_log if att['attempt'] == attempt + 1):
                        results_log.append(attempt_data)

                    overall_success = False
                    break # Stop processing on critical error

            # --- End of Retry Loop ---

            # Write the accumulated raw output to output.log
            if conv_log_dir: # Ensure directory was created
                try:
                    with open(output_log_file, 'w', encoding='utf-8') as f_out:
                        f_out.write(full_raw_output.strip())
                    if task_logger:
                        task_logger.info(f"Full raw execution output saved to: {output_log_file}")
                except Exception as write_err:
                    err_msg = f"Failed to write full output log to {output_log_file}: {write_err}"
                    print(f"ERROR: {err_msg}")
                    self.error_logger.error(err_msg, exc_info=True)
                    if task_logger: task_logger.error(err_msg, exc_info=True)

            print(f"=== Task Finished (ConvID: {conv_id}) - Overall Success: {overall_success} ===")

            # Log final status only if logger exists AND end message wasn't already logged
            if task_logger and not task_end_logged: # <<< Use the flag here
                 task_logger.info(f"--- TASK END (Final Status: Success={overall_success}) ---")

            return overall_success, results_log

        finally:
            # --- Cleanup Task-Specific Logging ---
            if task_logger and task_log_handler:
                self._cleanup_task_logging(task_logger, task_log_handler)

# --- END OF FILE llm-commander/llm_commander.py ---