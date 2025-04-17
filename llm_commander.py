# llm-commander/llm_commander.py
# Refactor process_task_background to use the planning approach

import uuid
import logging
import time # Keep for potential future delays if needed
import os
from datetime import datetime
import threading # Import threading for Event

from config import settings # Import loaded configuration
from log_setup import error_logger, LOGS_DIR # Import configured loggers and base log dir
from llm_client import LLMClient
from command_executor import CommandExecutor
from output_filter import OutputFilter

class LLMCommanderApp:
    """
    Main application class for LLM Commander.
    Orchestrates getting a plan from LLM, then generating and executing commands
    for each step, handling interactions and filtering output.
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
            llm_client=self.llm_client, # Executor might still be needed for sudo/interactive logic
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

    def _wait_for_user_confirmation(self, task_id: str, task_state_manager: dict, commands: list, plan_step: str, task_logger: logging.Logger) -> bool:
        """Signals UI for confirmation of commands for a specific plan step and waits for response."""
        wait_event = task_state_manager[task_id].get("wait_event")
        if not wait_event:
             task_logger.error(f"Task {task_id} missing wait_event during confirmation.")
             return False

        prompt_text = f"Confirm execution for step: '{plan_step}'\n\nCommands:\n" + "\n".join([f"  - {cmd}" for cmd in commands])
        task_state_manager[task_id].update({
            "status": "awaiting_confirmation",
            "current_step": f"Awaiting confirmation for: {plan_step}", # Update current step description
            "prompt_needed": True,
            "prompt_text": prompt_text,
            "input_type": "confirmation", # Specific type for UI
            "user_response": None
        })
        wait_event.clear()
        task_logger.info(f"Waiting for user confirmation (UI) for step: '{plan_step}'")
        print(f"\n################ CONFIRMATION REQUIRED VIA WEB UI (Step: {plan_step}) ################")
        print("Check the web interface to confirm or deny execution for this step.")
        wait_event.wait() # Pause thread

        user_response = task_state_manager[task_id].get("user_response")
        task_state_manager[task_id].update({ # Clear prompt state
            "prompt_needed": False,
            "prompt_text": None,
            "input_type": None,
            "user_response": None
            # Keep current_step description until next step starts or task ends
        })

        if isinstance(user_response, str) and user_response.lower() == 'yes':
            task_logger.info(f"User confirmed execution via UI for step: '{plan_step}'.")
            print(f"--- User confirmed execution via UI for step: '{plan_step}'. ---")
            return True
        else:
            task_logger.warning(f"User denied execution or provided invalid confirmation via UI for step '{plan_step}': '{user_response}'")
            print(f"--- User denied execution via UI for step: '{plan_step}' (Response: '{user_response}'). ---")
            return False


    def process_task_background(self, initial_prompt: str, max_retries: int, task_id: str, task_state_manager: dict):
        """
        The actual task processing logic: Plan -> Execute Steps. Runs in a background thread.

        Args:
            initial_prompt: The initial user request.
            max_retries: Maximum retry attempts (NOW LARGELY UNUSED, simple fail on step error).
            task_id: The unique ID for this task.
            task_state_manager: The shared dictionary holding task states.
        """
        conv_id = task_id
        task_logger, conv_log_dir, task_log_handler = None, None, None
        task_end_logged = False
        overall_success = False
        plan = []
        results_log = [] # Store detailed *step* info here
        full_raw_output = "" # Accumulate raw output across all steps

        try:
            # --- Setup Task-Specific Logging ---
            task_logger, conv_log_dir, task_log_handler = self._setup_task_logging(conv_id)
            output_log_file = os.path.join(conv_log_dir, 'output.log')

            # --- Initial State Update ---
            task_state_manager[task_id].update({
                "status": "planning",
                "current_step": "Generating execution plan...",
                "log_dir": conv_log_dir,
                "results": results_log # Store step results here
            })

            task_logger.info(f"--- NEW TASK START (ConvID: {conv_id}) ---")
            task_logger.info(f"Log Directory: {conv_log_dir}")
            task_logger.info(f"Initial Web Prompt: {initial_prompt}")
            # task_logger.info(f"Max Retries (Note: applies per step if retry logic added): {max_retries}") # Rephrase if retries aren't used
            print(f"\n=== Starting Background Task (ConvID: {conv_id}) ===")
            print(f"Initial Prompt: {initial_prompt}")
            print(f"Detailed logs in: {conv_log_dir}")

            # --- 1. Get Plan from LLM ---
            print("Requesting execution plan from LLM...")
            task_logger.info("Requesting execution plan from LLM.")
            try:
                plan = self.llm_client.get_llm_plan(initial_prompt, conv_id, task_logger)
                task_logger.info(f"LLM Generated Plan: {plan}")
                print(f"LLM Generated Plan:")
                for i, step_desc in enumerate(plan):
                    print(f"  {i+1}: {step_desc}")
                if not plan:
                    task_logger.warning("LLM returned an empty plan. Task considered failed.")
                    print("LLM returned an empty plan. Cannot proceed.")
                    raise ValueError("LLM returned an empty plan.")
                # Add plan to results log meta-data? or just log it
                results_log.append({"type": "plan", "steps": plan})

            except Exception as plan_err:
                err_msg = f"Failed to get execution plan from LLM: {plan_err}"
                print(f"ERROR: {err_msg}")
                task_logger.error(err_msg, exc_info=True)
                self.error_logger.error(f"Task {conv_id} failed during planning: {plan_err}", exc_info=True)
                # Update state manager to reflect planning failure
                task_state_manager[task_id].update({
                    "status": "failed",
                    "current_step": "Failed to generate plan.",
                    "result": {"error": err_msg, "plan": [], "steps_results": []}
                })
                # Ensure logging is cleaned up if it was set up
                if task_logger and task_log_handler:
                    self._cleanup_task_logging(task_logger, task_log_handler)
                return # Exit background thread

            # --- 2. Execute Plan Steps ---
            previous_steps_summary = "" # Build summary for context
            for step_index, step_description in enumerate(plan):
                step_num = step_index + 1
                task_logger.info(f"--- Starting Step {step_num}/{len(plan)}: {step_description} ---")
                print(f"\n--- Executing Step {step_num}/{len(plan)}: {step_description} ---")
                task_state_manager[task_id].update({
                    "status": f"executing_step_{step_num}",
                    "current_step": f"Step {step_num}/{len(plan)}: {step_description}"
                })

                step_data = {
                    "type": "step_result",
                    "step_number": step_num,
                    "description": step_description,
                    "commands": [],
                    "execution_success": False,
                    "stdout": "", # Filtered output for UI/final result
                    "stderr": ""  # Raw error output for UI/final result
                }
                results_log.append(step_data) # Add early
                proceed_with_step = True
                raw_log_output_this_step = ""

                try:
                    # 2a. Get Commands for the Step
                    print("Requesting commands for step from LLM...")
                    task_logger.info(f"Requesting commands for step '{step_description}'.")
                    commands = self.llm_client.get_llm_commands_for_step(
                        step_description, initial_prompt, previous_steps_summary, conv_id, task_logger
                    )
                    step_data["commands"] = commands
                    print(f"LLM proposed commands for step: {commands}")
                    task_logger.info(f"LLM proposed commands for step: {commands}")

                    # 2b. Confirmation Step (via UI) for this step's commands
                    if self.require_confirmation and commands:
                        task_logger.info("Confirmation required for step commands. Waiting for UI response.")
                        proceed_with_step = self._wait_for_user_confirmation(
                            task_id, task_state_manager, commands, step_description, task_logger
                        )

                        if not proceed_with_step:
                            step_data["stderr"] = "Execution of step cancelled by user confirmation via UI."
                            overall_success = False # Mark overall task as failed
                            task_logger.warning(f"--- TASK END (Cancelled by Confirmation at Step {step_num}) ---")
                            task_end_logged = True
                            break # Exit plan execution loop

                    # 2c. Execute commands (if proceeding)
                    if proceed_with_step:
                        if commands:
                            task_logger.info(f"Executing commands for step {step_num}...")
                            exec_success, raw_log_output_this_step, error_output = self.executor.execute_commands(
                                commands, initial_prompt, conv_id, task_logger, task_state_manager, task_id
                            )
                            full_raw_output += f"\n\n--- Step {step_num} ({step_description}) Raw Output ---\n" + raw_log_output_this_step
                            filtered_log_output = self.output_filter.filter(raw_log_output_this_step, exec_success)

                            # Update step data
                            step_data["execution_success"] = exec_success
                            step_data["stdout"] = filtered_log_output
                            step_data["stderr"] = error_output

                            task_logger.info(f"Execution Result (Step {step_num}): Success={exec_success}")
                            if filtered_log_output:
                                task_logger.info(f"Step {step_num} Log Summary (stdout/filtered):\n{filtered_log_output}")
                            if error_output:
                                task_logger.error(f"Step {step_num} Errors Summary (stderr):\n{error_output}")

                        else:
                            # No commands proposed for this step
                            print("LLM returned no commands for this step. Skipping execution.")
                            step_data["execution_success"] = True # Consider step successful if no commands needed
                            step_data["stdout"] = "LLM returned no commands for this step."
                            task_logger.info(f"LLM returned no commands for step {step_num}, skipping execution.")
                            exec_success = True # Treat as success for plan continuation

                        # 2d. Check step result and decide next action
                        if exec_success:
                            print(f"--- Step {step_num} Succeeded ---")
                            task_logger.info(f"Step {step_num} completed successfully.")
                            # Add summary of successful step for next LLM call context
                            previous_steps_summary += f"Step {step_num}: '{step_description}' completed successfully.\n"
                            # Continue to the next step in the loop
                        else:
                            # Execution failed for this step
                            print(f"--- Step {step_num} Failed ---")
                            task_logger.warning(f"Execution failed on step {step_num}: {step_description}.")
                            overall_success = False # Mark overall task as failed
                            task_logger.warning(f"--- TASK END (Failed at Step {step_num}) ---")
                            task_end_logged = True
                            # Simple failure model: Stop entire plan
                            break # Exit plan execution loop

                except Exception as step_err:
                    # Handle critical errors during step processing (LLM, executor, etc.)
                    err_msg = f"Critical error during step {step_num} ('{step_description}') (ConvID: {conv_id}): {step_err}"
                    print(f"ERROR: {err_msg}")
                    self.error_logger.critical(err_msg, exc_info=True)
                    if task_logger:
                         task_logger.critical(f"--- TASK END (Critical Error during Step {step_num}) ---\nError: {step_err}", exc_info=True)
                         task_end_logged = True

                    step_data["stderr"] = f"Application Error during step: {step_err}"
                    step_data["execution_success"] = False
                    overall_success = False
                    # Ensure pexpect child is cleaned up if it exists in state
                    if task_state_manager[task_id].get('pexpect_child'):
                        try:
                           child = task_state_manager[task_id]['pexpect_child']
                           if child and not child.closed:
                               child.close(force=True)
                           task_state_manager[task_id]['pexpect_child'] = None
                           task_logger.warning("Cleaned up pexpect child after critical step error.")
                        except Exception as cleanup_err:
                           task_logger.error(f"Error cleaning up pexpect child after critical step error: {cleanup_err}")
                    break # Stop plan execution on critical error during a step

            # --- End of Plan Execution Loop ---

            # Check if loop completed without break (i.e., all steps succeeded)
            if not task_end_logged: # If no failure/cancellation broke the loop early
                 overall_success = True
                 task_logger.info("--- TASK END (Success - All plan steps completed) ---")
                 task_end_logged = True
                 task_state_manager[task_id]["current_step"] = "All plan steps completed successfully."

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
                 # This case should ideally not happen if logic above is correct
                 task_logger.info(f"--- TASK END (Final Status Check: {final_status}) ---")

            # Update final state in manager
            final_result_data = {
                "overall_success": overall_success,
                "plan": plan, # Include the original plan
                "steps_results": [r for r in results_log if r.get("type") == "step_result"] # Filter step results
                # Could add overall error message here if needed
            }
            if not overall_success and "error" not in final_result_data:
                # Add a generic failure message if one wasn't captured more specifically
                last_step_stderr = results_log[-1].get("stderr", "") if results_log and results_log[-1].get("type") == "step_result" else ""
                final_result_data["error"] = f"Task failed during plan execution. Check step results. Last step error: {last_step_stderr or 'N/A'}"


            task_state_manager[task_id].update({
                "status": final_status,
                "result": final_result_data, # Store structured results
                "prompt_needed": False, # Ensure prompt flags are cleared
                "prompt_text": None,
                "input_type": None,
                "user_response": None,
                 # Keep the last relevant "current_step" or set a final one
                "current_step": task_state_manager[task_id].get("current_step", "Task finished.")
            })


        except Exception as outer_err:
             # Catch errors outside the main loop (e.g., logging setup, initial planning)
             err_msg = f"Critical error processing task {conv_id}: {outer_err}"
             print(f"FATAL ERROR: {err_msg}")
             self.error_logger.critical(err_msg, exc_info=True)
             if task_logger and not task_end_logged: # Log to task log if possible
                 task_logger.critical(f"--- TASK END (Critical Outer Error) ---\nError: {outer_err}", exc_info=True)
             # Update state manager to reflect critical failure
             task_state_manager[task_id].update({
                 "status": "failed",
                 "current_step": f"Critical application error: {outer_err}",
                 "result": {"error": f"Critical Application Error: {outer_err}", "plan": plan, "steps_results": []},
                 "prompt_needed": False,
                 "prompt_text": None,
                 "input_type": None,
                 "user_response": None
             })
             # Cleanup pexpect child if needed (though unlikely to exist here unless planning failed mid-exec)
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
            # Final check to ensure pexpect child is removed from state
            if task_state_manager.get(task_id) and task_state_manager[task_id].get('pexpect_child'):
                 task_state_manager[task_id]['pexpect_child'] = None
                 if task_logger: task_logger.debug("Ensured pexpect_child removed from state post-task.")