# llm-commander/llm_commander.py
import uuid
import logging
import time # Keep for potential future delays if needed

from config import settings # Import loaded configuration
from log_setup import conversation_logger, error_logger # Import configured loggers
from llm_client import LLMClient
from command_executor import CommandExecutor
from output_filter import OutputFilter

class LLMCommanderApp:
    """
    Main application class for LLM Commander.
    Orchestrates getting commands from LLM, executing them, handling retries,
    and filtering output.
    """

    def __init__(self):
        """Initializes the application components."""
        self.config = settings
        self.error_logger = error_logger
        self.conversation_logger = conversation_logger

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
        log_extra = {'conv_id': conv_id}

        self.conversation_logger.info(f"--- NEW TASK START (ConvID: {conv_id}) ---", extra=log_extra)
        self.conversation_logger.info(f"Initial Web Prompt: {initial_prompt}", extra=log_extra)
        self.conversation_logger.info(f"Max Retries: {max_retries}", extra=log_extra)
        print(f"\n=== Starting New Task (ConvID: {conv_id}) ===")
        print(f"Initial Prompt: {initial_prompt}")

        current_prompt = initial_prompt
        results_log = [] # For returning structured results
        overall_success = False

        for attempt in range(max_retries + 1):
            print(f"\n--- Attempt {attempt + 1}/{max_retries + 1} (ConvID: {conv_id}) ---")
            self.conversation_logger.info(f"--- Starting Attempt {attempt + 1}/{max_retries + 1} ---", extra=log_extra)
            attempt_data = {
                "attempt": attempt + 1,
                "prompt_sent": current_prompt,
                "llm_commands": [],
                "execution_success": False,
                "stdout": "", # Filtered output
                "stderr": ""  # Raw error output
            }
            proceed_with_execution = True
            raw_log_output_for_retry = "" # Store raw output for retry context

            try:
                # 1. Get commands from LLM
                print("Requesting commands from LLM...")
                commands = self.llm_client.get_llm_commands(current_prompt, conv_id)
                attempt_data["llm_commands"] = commands
                print(f"LLM proposed commands: {commands}")

                # 2. Confirmation Step
                if self.require_confirmation and commands:
                    print("\n################ CONFIRMATION REQUIRED ################")
                    self.conversation_logger.info("Confirmation required. Displaying commands.", extra=log_extra)
                    print("LLM proposes the following commands:")
                    for i, cmd in enumerate(commands): print(f"  {i+1}: {cmd}")
                    print("-----------------------------------------------------")
                    try:
                        # Prompt appears in the terminal running the *server*
                        response = input(">>> Execute these commands? (yes/no): ").lower().strip()
                        if response != 'yes' or response == 'y':
                            proceed_with_execution = False
                            print("--- Execution cancelled by user. ---")
                            attempt_data["stderr"] = "Execution cancelled by user."
                            self.conversation_logger.warning("Execution cancelled by user confirmation.", extra=log_extra)
                    except Exception as input_err:
                        proceed_with_execution = False
                        err_msg = f"Execution cancelled (confirmation error: {input_err})."
                        print(f"--- Error during confirmation: {input_err}. Cancelling execution. ---")
                        attempt_data["stderr"] = err_msg
                        self.error_logger.error(f"Confirmation input error: {input_err}", exc_info=True, extra=log_extra)
                        self.conversation_logger.error(f"Execution cancelled due to confirmation error: {input_err}", extra=log_extra)

                    if not proceed_with_execution:
                        results_log.append(attempt_data)
                        overall_success = False
                        self.conversation_logger.warning("--- TASK END (Cancelled by Confirmation) ---", extra=log_extra)
                        break # Exit retry loop for this task

                # 3. Execute commands (if proceeding)
                if proceed_with_execution:
                    if commands:
                        # Execute using the CommandExecutor instance
                        exec_success, raw_log_output_for_retry, error_output = self.executor.execute_commands(
                            commands, initial_prompt, conv_id
                        )

                        # Filter the raw output using the OutputFilter instance
                        filtered_log_output = self.output_filter.filter(raw_log_output_for_retry, exec_success)

                        # Store results for this attempt
                        attempt_data["execution_success"] = exec_success
                        attempt_data["stdout"] = filtered_log_output # Store filtered version
                        attempt_data["stderr"] = error_output # Keep stderr raw

                        # Log filtered output to conversation log
                        self.conversation_logger.info(f"Execution Result (Attempt {attempt+1}): Success={exec_success}", extra=log_extra)
                        if filtered_log_output:
                            self.conversation_logger.info(f"Execution Log (stdout/filtered):\n{filtered_log_output}", extra=log_extra)
                        if error_output:
                            # Already logged errors within executor, but log summary here
                            self.conversation_logger.error(f"Execution Errors Summary (stderr):\n{error_output}", extra=log_extra)

                    else:
                        # No commands proposed
                        print("LLM returned no commands. Nothing to execute.")
                        attempt_data["execution_success"] = True # No failure occurred
                        attempt_data["stdout"] = "LLM returned no commands."
                        self.conversation_logger.info("LLM returned no commands, skipping execution.", extra=log_extra)
                        results_log.append(attempt_data) # Log this state
                        overall_success = True # Considered success if no commands needed/returned
                        break # Exit loop, nothing more to do

                    results_log.append(attempt_data) # Append attempt data AFTER execution/filtering

                    # 4. Check result and decide next step
                    if exec_success:
                        print(f"--- Attempt {attempt + 1} Succeeded ---")
                        overall_success = True
                        self.conversation_logger.info(f"--- TASK END (Success on Attempt {attempt+1}) ---", extra=log_extra)
                        break # Success, exit the retry loop
                    else:
                        # Execution failed
                        print(f"--- Attempt {attempt + 1} Failed ---")
                        if attempt < max_retries:
                            print("Preparing retry prompt for LLM...")
                            # Use RAW output for LLM context
                            error_context_for_llm = error_output if error_output else raw_log_output_for_retry[-1500:] # Limit context
                            current_prompt = (
                                f"The previous attempt to achieve the goal failed.\n"
                                f"Original Goal: '{initial_prompt}'\n"
                                f"Commands Tried in Failed Attempt: {commands}\n"
                                f"Error/Output Log from Failed Attempt:\n---\n{error_context_for_llm}\n---\n\n"
                                f"Analyze the error and the original goal, then provide corrected shell commands to achieve the goal. Respond ONLY with the JSON object."
                            )
                            self.conversation_logger.info(f"Execution failed (Attempt {attempt+1}). Preparing retry.", extra=log_extra)
                            # Next loop iteration will call get_llm_commands with this new prompt
                        else:
                            # Max retries reached
                            print("Max retries reached. Stopping.")
                            overall_success = False
                            self.conversation_logger.warning(f"--- TASK END (Failed - Max Retries Reached) ---", extra=log_extra)
                            break # Exit loop

            except Exception as e:
                # Handle critical errors during LLM calls or other parts of the loop
                err_msg = f"Critical error during attempt {attempt + 1} (ConvID: {conv_id}): {e}"
                print(f"ERROR: {err_msg}")
                self.error_logger.critical(err_msg, exc_info=True, extra=log_extra)
                self.conversation_logger.critical(f"--- TASK END (Critical Error) ---\nError: {e}", exc_info=True, extra=log_extra)

                # Update attempt data for UI
                attempt_data["stderr"] = f"Application Error: {e}"
                attempt_data["execution_success"] = False
                # Ensure this failed attempt is added to results_log if not already
                if not any(att for att in results_log if att['attempt'] == attempt + 1):
                    results_log.append(attempt_data)

                overall_success = False
                break # Stop processing on critical error

        # --- End of Retry Loop ---
        print(f"=== Task Finished (ConvID: {conv_id}) - Overall Success: {overall_success} ===")

        # Final log marker if not already logged by break conditions
        # This check is tricky. Assuming the loop break conditions logged the final state correctly.
        # A more robust way might involve setting a flag when an END marker is logged.

        return overall_success, results_log