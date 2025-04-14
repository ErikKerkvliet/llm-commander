# llm-commander/llm_commander.py
import uuid
import logging
import time # Keep for potential future delays if needed
import os
from datetime import datetime
import threading # Import threading for Event

from config import settings # Import loaded configuration
from log_setup import error_logger, LOGS_DIR # Import configured loggers and base log dir
from llm_client import LLMClient
from command_executor import CommandExecutor # No changes needed here structurally
from output_filter import OutputFilter

class LLMCommanderApp:
    """
    Main application class for LLM Commander.
    Orchestrates getting commands from LLM, executing them, handling retries,
    and filtering output. Manages dynamic task logging and interaction state.
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
            llm_client=self.llm_client, # Executor now relies less on LLMClient directly for interaction
            sudo_password=self.config['SUDO_PASSWORD'] # Pass sudo password
        )
        self.output_filter = OutputFilter(
            success_lines=self.config['FILTER_SUCCESS_LINES']
        )
        self.require_confirmation = self.config['REQUIRE_CONFIRMATION']

        self.error_logger.info("LLMCommanderApp initialized successfully.")
        print(f"--- Command execution confirmation required via UI: {self.require_confirmation} ---")
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
             handler = next((h for h in task_logger.handlers if isinstance(h, logging.FileHandler) and task_logger_name in h.name), None)
             return task_logger, conv_log_dir, handler

        # Create and add file handler for task.log
        conv_log_file = os.path.join(conv_log_dir, 'task.log')
        handler = logging.FileHandler(conv_log_file, encoding='utf-8')
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
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

    def _wait_for_user_confirmation(self, task_id: str, task_state_manager: dict, commands: list, task_logger: logging.Logger) -> bool:
        """Signals UI for confirmation and waits for response."""
        wait_event = task_state_manager[task_id].get("wait_event")
        if not wait_event:
             task_logger.error(f"Task {task_id} missing wait_event during confirmation.")
             return False

        prompt_text = "Confirm execution of the following commands:\n" + "\n".join([f"  {i+1}: {cmd}" for i, cmd in enumerate(commands)])
        task_state_manager[task_id].update({
            "status": "awaiting_confirmation",
            "prompt_needed": True,
            "prompt_text": prompt_text,
            "input_type": "confirmation", # Specific type for UI
            "user_response": None
        })
        wait_event.clear()
        task_logger.info("Waiting for user confirmation via UI...")
        print("\n################ CONFIRMATION REQUIRED VIA WEB UI ################")
        print("Check the web interface to confirm or deny execution.")
        wait_event.wait() # Pause thread

        user_response = task_state_manager[task_id].get("user_response")
        task_state_manager[task_id].update({ # Clear prompt state
            "prompt_needed": False,
            "prompt_text": None,
            "input_type": None,
            "user_response": None
        })

        if isinstance(user_response, str) and user_response.lower() == 'yes':
            task_logger.info("User confirmed execution via UI.")
            print("--- User confirmed execution via UI. ---")
            return True
        else:
            task_logger.warning(f"User denied execution or provided invalid confirmation via UI: '{user_response}'")
            print(f"--- User denied execution via UI (Response: '{user_response}'). ---")
            return False


    def process_task_background(self, initial_prompt: str, max_retries: int, task_id: str, task_state_manager: dict):
        """
        The actual task processing logic, designed to run in a background thread.

        Args:
            initial_prompt: The initial user request.
            max_retries: Maximum retry attempts.
            task_id: The unique ID for this task.
            task_state_manager: The shared dictionary holding task states, including the 'wait_event'.
        """
        conv_id = task_id # Use task_id as the conversation ID for consistency
        task_logger, conv_log_dir, task_log_handler = None, None, None
        task_end_logged = False
        overall_success = False
        results_log = [] # Store detailed attempt info here

        try:
            # --- Setup Task-Specific Logging ---
            task_logger, conv_log_dir, task_log_handler = self._setup_task_logging(conv_id)
            output_log_file = os.path.join(conv_log_dir, 'output.log')

            # Update initial state
            task_state_manager[task_id].update({
                "status": "running",
                "log_dir": conv_log_dir,
                "results": results_log # Keep adding attempt data here
            })

            task_logger.info(f"--- NEW TASK START (ConvID: {conv_id}) ---")
            task_logger.info(f"Log Directory: {conv_log_dir}")
            task_logger.info(f"Initial Web Prompt: {initial_prompt}")
            task_logger.info(f"Max Retries: {max_retries}")
            print(f"\n=== Starting Background Task (ConvID: {conv_id}) ===")
            print(f"Initial Prompt: {initial_prompt}")
            print(f"Detailed logs in: {conv_log_dir}")

            current_prompt = initial_prompt
            full_raw_output = "" # Accumulate raw output across all attempts

            for attempt in range(max_retries + 1):
                task_logger.info(f"--- Starting Attempt {attempt + 1}/{max_retries + 1} ---")
                task_state_manager[task_id]["status"] = f"running_attempt_{attempt+1}" # More granular status

                attempt_data = {
                    "attempt": attempt + 1,
                    "prompt_sent": current_prompt,
                    "llm_commands": [],
                    "execution_success": False,
                    "stdout": "", # Filtered output for UI/final result
                    "stderr": ""  # Raw error output for UI/final result
                }
                results_log.append(attempt_data) # Add early to track progress
                proceed_with_execution = True
                raw_log_output_this_attempt = ""

                try:
                    # 1. Get commands from LLM
                    print(f"\n--- Attempt {attempt + 1}/{max_retries + 1} (ConvID: {conv_id}) ---")
                    print("Requesting commands from LLM...")
                    task_logger.info("Requesting commands from LLM.")
                    commands = self.llm_client.get_llm_commands(current_prompt, conv_id, task_logger)
                    attempt_data["llm_commands"] = commands
                    print(f"LLM proposed commands: {commands}")
                    task_logger.info(f"LLM proposed commands: {commands}")

                    # 2. Confirmation Step (via UI)
                    if self.require_confirmation and commands:
                        task_logger.info("Confirmation required. Waiting for UI response.")
                        proceed_with_execution = self._wait_for_user_confirmation(
                            task_id, task_state_manager, commands, task_logger
                        )

                        if not proceed_with_execution:
                            attempt_data["stderr"] = "Execution cancelled by user confirmation via UI."
                            overall_success = False
                            task_logger.warning("--- TASK END (Cancelled by Confirmation) ---")
                            task_end_logged = True
                            break # Exit retry loop

                    # 3. Execute commands (if proceeding)
                    if proceed_with_execution:
                        if commands:
                            task_logger.info("Executing commands...")
                            # Execute using the CommandExecutor, passing state manager and task_id
                            exec_success, raw_log_output_this_attempt, error_output = self.executor.execute_commands(
                                commands, initial_prompt, conv_id, task_logger, task_state_manager, task_id
                            )
                            full_raw_output += f"\n\n--- Attempt {attempt + 1} Raw Output ---\n" + raw_log_output_this_attempt
                            filtered_log_output = self.output_filter.filter(raw_log_output_this_attempt, exec_success)

                            # Update attempt data in results_log
                            attempt_data["execution_success"] = exec_success
                            attempt_data["stdout"] = filtered_log_output
                            attempt_data["stderr"] = error_output

                            task_logger.info(f"Execution Result (Attempt {attempt+1}): Success={exec_success}")
                            if filtered_log_output:
                                task_logger.info(f"Execution Log Summary (stdout/filtered):\n{filtered_log_output}")
                            if error_output:
                                task_logger.error(f"Execution Errors Summary (stderr):\n{error_output}")

                        else:
                            # No commands proposed
                            print("LLM returned no commands. Nothing to execute.")
                            attempt_data["execution_success"] = True
                            attempt_data["stdout"] = "LLM returned no commands."
                            task_logger.info("LLM returned no commands, skipping execution.")
                            overall_success = True
                            task_logger.info("--- TASK END (No Commands to Execute) ---")
                            task_end_logged = True
                            break # Exit loop

                        # 4. Check result and decide next step
                        if exec_success:
                            print(f"--- Attempt {attempt + 1} Succeeded ---")
                            overall_success = True
                            task_logger.info(f"--- TASK END (Success on Attempt {attempt+1}) ---")
                            task_end_logged = True
                            break # Success, exit the retry loop
                        else:
                            # Execution failed
                            print(f"--- Attempt {attempt + 1} Failed ---")
                            task_logger.warning(f"Execution failed on attempt {attempt + 1}.")
                            if attempt < max_retries:
                                print("Preparing retry prompt for LLM...")
                                error_context_for_llm = error_output if error_output else raw_log_output_this_attempt[-1500:]
                                current_prompt = (
                                    f"The previous attempt to achieve the goal failed.\n"
                                    f"Original Goal: '{initial_prompt}'\n"
                                    f"Commands Tried in Failed Attempt: {commands}\n"
                                    f"Error/Output Log from Failed Attempt:\n---\n{error_context_for_llm}\n---\n\n"
                                    f"Analyze the error and the original goal, then provide corrected shell commands to achieve the goal. Respond ONLY with the JSON object."
                                )
                                task_logger.info(f"Preparing retry prompt.")
                            else:
                                print("Max retries reached. Stopping.")
                                overall_success = False
                                task_logger.warning(f"--- TASK END (Failed - Max Retries Reached) ---")
                                task_end_logged = True
                                break # Exit loop

                except Exception as e:
                    # Handle critical errors (LLM, unexpected executor errors, etc.)
                    err_msg = f"Critical error during attempt {attempt + 1} (ConvID: {conv_id}): {e}"
                    print(f"ERROR: {err_msg}")
                    self.error_logger.critical(err_msg, exc_info=True)
                    if task_logger:
                         task_logger.critical(f"--- TASK END (Critical Error during Attempt {attempt + 1}) ---\nError: {e}", exc_info=True)
                         task_end_logged = True
                    else:
                         self.error_logger.critical(f"Task {conv_id} failed before logger setup: {e}", exc_info=True)

                    attempt_data["stderr"] = f"Application Error: {e}"
                    attempt_data["execution_success"] = False
                    overall_success = False
                    # Ensure pexpect child is cleaned up if it exists in state
                    if task_state_manager[task_id].get('pexpect_child'):
                        try:
                           child = task_state_manager[task_id]['pexpect_child']
                           if child and not child.closed:
                               child.close(force=True)
                           task_state_manager[task_id]['pexpect_child'] = None
                           task_logger.warning("Cleaned up pexpect child after critical error.")
                        except Exception as cleanup_err:
                           task_logger.error(f"Error cleaning up pexpect child after critical error: {cleanup_err}")
                    break # Stop processing on critical error

            # --- End of Retry Loop ---

            # Write the accumulated raw output to output.log
            if conv_log_dir:
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

            final_status = "complete" if overall_success else "failed"
            print(f"=== Background Task Finished (ConvID: {conv_id}) - Overall Success: {overall_success} ===")
            if task_logger and not task_end_logged:
                 task_logger.info(f"--- TASK END (Final Status: {final_status}) ---")

            # Update final state in manager
            task_state_manager[task_id].update({
                "status": final_status,
                "result": { # Structure final result for UI
                    "overall_success": overall_success,
                    "results": results_log # Contains history of all attempts
                },
                "prompt_needed": False, # Ensure prompt flags are cleared
                "prompt_text": None,
                "input_type": None,
                "user_response": None,
            })


        except Exception as outer_err:
             # Catch errors outside the main loop (e.g., logging setup)
             err_msg = f"Critical error processing task {conv_id}: {outer_err}"
             print(f"FATAL ERROR: {err_msg}")
             self.error_logger.critical(err_msg, exc_info=True)
             if task_logger and not task_end_logged: # Log to task log if possible
                 task_logger.critical(f"--- TASK END (Critical Outer Error) ---\nError: {outer_err}", exc_info=True)
             # Update state manager to reflect critical failure
             task_state_manager[task_id].update({
                 "status": "failed",
                 "result": {"error": f"Critical Application Error: {outer_err}"},
                 "prompt_needed": False,
                 "prompt_text": None,
                 "input_type": None,
                 "user_response": None
             })
             # Cleanup pexpect child if needed
             if task_state_manager[task_id].get('pexpect_child'):
                 try:
                     child = task_state_manager[task_id]['pexpect_child']
                     if child and not child.closed:
                         child.close(force=True)
                     task_state_manager[task_id]['pexpect_child'] = None
                     if task_logger: task_logger.warning("Cleaned up pexpect child after outer critical error.")
                 except Exception as cleanup_err:
                     if task_logger: task_logger.error(f"Error cleaning up pexpect child after outer critical error: {cleanup_err}")


        finally:
            # --- Cleanup Task-Specific Logging ---
            if task_logger and task_log_handler:
                self._cleanup_task_logging(task_logger, task_log_handler)
            # Final check to ensure pexpect child is removed from state if loop finished normally
            if task_state_manager.get(task_id) and task_state_manager[task_id].get('pexpect_child'):
                 task_state_manager[task_id]['pexpect_child'] = None
                 if task_logger: task_logger.debug("Ensured pexpect_child removed from state post-task.")