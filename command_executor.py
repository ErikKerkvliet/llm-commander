# llm-commander/command_executor.py
import logging
import re
import subprocess # Keep for non-interactive fallback if needed later
import threading # Import threading for Event

# Try importing pexpect, handle import error for non-Unix systems
try:
    import pexpect
    PEXPECT_AVAILABLE = True
except ImportError:
    PEXPECT_AVAILABLE = False
    print("WARNING: 'pexpect' library not found. Interactive command execution will not be available.")
    print("         On Windows, consider using WSL or alternative libraries like 'weexpect'.")

# Use main error logger from log_setup for executor-level errors
from log_setup import error_logger

# Import LLMClient type hint if possible (avoids circular dependency issue at runtime)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from llm_client import LLMClient
    from logging import Logger # Import Logger type hint


# --- Custom Exception for Signaling User Input ---
class UserInputRequired(Exception):
    """Custom exception to signal that user input is needed."""
    def __init__(self, prompt_text, prompt_type="generic"):
        self.prompt_text = prompt_text
        self.prompt_type = prompt_type # e.g., 'generic', 'sudo'
        super().__init__(f"User input required ({prompt_type}): {prompt_text}")


class CommandExecutor:
    """Executes shell commands, potentially interactively using pexpect."""

    def __init__(self, llm_client: 'LLMClient', sudo_password: str | None):
        """
        Initializes the CommandExecutor.

        Args:
            llm_client: An instance of LLMClient (less used now for direct interaction).
            sudo_password: The sudo password (if available). SECURITY RISK!
        """
        self.llm_client = llm_client # Keep for potential future use, but interaction flow changes
        self.sudo_password = sudo_password
        if not PEXPECT_AVAILABLE:
            error_logger.warning("'pexpect' not available. Interactive execution disabled.")
            print("WARNING: Interactive command execution is disabled because 'pexpect' is not installed.")

    def execute_commands(self, commands: list[str], original_goal: str, conv_id: str, task_logger: 'Logger', task_state_manager: dict, task_id: str) -> tuple[bool, str, str]:
        """
        Executes a list of commands using pexpect, signaling for user input via task_state_manager.

        Args:
            commands: A list of command strings to execute.
            original_goal: The initial user prompt/goal.
            conv_id: The task ID for logging.
            task_logger: The logger instance specific to this task.
            task_state_manager: The shared dictionary holding task states.
            task_id: The specific ID for this task in the manager.

        Returns:
            A tuple containing:
            - success (bool): True if all commands executed without error, False otherwise.
            - aggregated_log (str): Combined raw stdout/stderr and interaction log for this execution block.
            - aggregated_stderr (str): Specific error messages encountered during this block.

        Raises:
            UserInputRequired: When input is needed from the user via the UI.
            Exception: For other critical execution errors.
        """
        if not PEXPECT_AVAILABLE:
            error_msg = "Cannot execute commands interactively: pexpect library is not available."
            task_logger.error(error_msg)
            error_logger.error(f"(ConvID: {conv_id}) {error_msg}") # Also log to main error log
            # Update state to reflect failure before returning
            task_state_manager[task_id].update({"status": "failed", "result": {"error": error_msg}})
            return False, "", error_msg

        full_log = "" # Combined raw log of interaction for returning
        final_stderr = "" # Collect specific error output for returning
        overall_success = True
        wait_event = task_state_manager[task_id].get("wait_event")
        if not wait_event or not isinstance(wait_event, threading.Event):
            raise ValueError(f"Task {task_id} is missing a valid threading.Event in state manager.")

        if not commands:
            task_logger.info("No commands provided for execution.")
            return True, "No commands to execute.", ""

        task_logger.info(f"Starting execution of {len(commands)} commands.")

        for cmd_idx, cmd in enumerate(commands):
            if not cmd or not isinstance(cmd, str) or cmd.isspace():
                task_logger.warning(f"Skipping empty/invalid command string: {cmd!r}")
                continue

            task_logger.info(f"Executing Command {cmd_idx+1}/{len(commands)}: $ {cmd}")
            print(f"\n--- Executing Command {cmd_idx+1}/{len(commands)} (Interactive): {cmd} ---")
            cmd_log_header = f"\n\n>>> EXEC ({cmd_idx+1}/{len(commands)}): $ {cmd}\n"
            full_log += cmd_log_header
            child = None
            prompt_context_for_log = "" # Track context for logging

            try:
                # Use 'bash -c' to handle pipes, redirections etc. within the command string
                child = pexpect.spawn('/bin/bash', ['-c', cmd], timeout=300, encoding='utf-8', echo=False)
                # Assign child to state manager EARLY in case of immediate prompt
                task_state_manager[task_id]['pexpect_child'] = child

                patterns = [
                    pexpect.EOF,                                # 0
                    pexpect.TIMEOUT,                            # 1
                    r"(?:\[sudo\] )?password for .*?: ?",        # 2: Sudo password prompt
                    r"(\(yes/no\)|\[Y[ea]*s?/N[o]?[au]*\?*\])",  # 3: Yes/No prompts
                    r"(?i)are you sure you want to continue\?", # 4: Confirmation prompt
                    r"(?i)enter .*?: ?",                        # 5: Generic 'Enter X:' prompt
                    # Add more specific, less ambiguous patterns if possible
                ]
                # Compile regex patterns for efficiency
                compiled_patterns = [pat if isinstance(pat, (type(pexpect.EOF), type(pexpect.TIMEOUT))) else re.compile(pat, re.IGNORECASE) for pat in patterns]


                while True: # Interaction loop for this command
                    try:
                        index = child.expect(compiled_patterns)

                        output_before = child.before.strip() # Keep raw output, strip outer whitespace
                        matched_prompt_text = child.after.strip() if index > 1 else ""
                        prompt_context_for_log = (output_before + "\n" + matched_prompt_text).strip() # Context for logging/LLM

                        if output_before:
                            print(f"Output:\n{output_before}")
                            full_log += output_before + "\n" # Add raw output to main log
                            task_logger.info(f"Output Received:\n{output_before}")

                        # Handle based on the matched pattern index
                        if index == 0: # EOF
                            task_logger.debug("Command finished (EOF).")
                            print("Command finished (EOF).")
                            full_log += "--- Command End (EOF) ---\n"
                            break # Exit inner loop

                        elif index == 1: # TIMEOUT
                            raise pexpect.TIMEOUT("Command timed out during expect.")

                        elif index == 2: # Sudo password prompt
                            task_logger.info(f"Sudo Prompt Detected: {matched_prompt_text}")
                            print(f"Prompt Detected: {matched_prompt_text}")
                            log_msg = f"[PROMPT DETECTED]:\n{prompt_context_for_log}\n"
                            full_log += log_msg

                            if self.sudo_password:
                                task_logger.info("Sending configured sudo password.")
                                print("Sending configured sudo password...")
                                child.sendline(self.sudo_password)
                                log_msg = "[RESPONSE SENT]: [configured sudo password]\n"
                                full_log += log_msg
                            else:
                                task_logger.warning("Sudo prompt detected, SUDO_PASSWORD not configured. Asking user via UI.")
                                print("Sudo prompt detected, asking user via UI...")
                                # --- Signal UI for Sudo Password ---
                                task_state_manager[task_id].update({
                                    "status": "awaiting_input",
                                    "prompt_needed": True,
                                    "prompt_text": f"Sudo password required for user:\n{prompt_context_for_log}",
                                    "input_type": "password", # Hint for UI
                                    "user_response": None # Clear previous response
                                })
                                wait_event.clear() # Ensure event is cleared before waiting
                                task_logger.info("Waiting for user input (sudo password) via UI...")
                                wait_event.wait() # Pause thread until UI provides input

                                # --- Resume after UI input ---
                                user_input = task_state_manager[task_id].get("user_response")
                                task_state_manager[task_id].update({ # Clear prompt state
                                     "prompt_needed": False,
                                     "prompt_text": None,
                                     "input_type": None,
                                     "user_response": None
                                })
                                if user_input is not None: # Check if input was actually provided
                                    task_logger.info("Received sudo password from user UI. Sending.")
                                    print("Received sudo password from UI. Sending...")
                                    child.sendline(user_input)
                                    log_msg = "[RESPONSE SENT (UI - Sudo Password)]: ***\n"
                                    full_log += log_msg
                                else:
                                    # This case might happen if the task is cancelled or times out while waiting
                                    error_msg = "Failed to get sudo password from user UI (no response or cancelled)."
                                    log_msg = f"[ERROR]: {error_msg}\n"
                                    full_log += log_msg
                                    task_logger.error(error_msg)
                                    error_logger.error(f"(ConvID: {conv_id}) {error_msg}")
                                    raise ValueError("Sudo prompt occurred, but failed to get password from user.")


                        elif index >= 3: # Interactive prompt detected (Yes/No, Continue, Enter X, etc.)
                            task_logger.info(f"Interactive Prompt Detected: {matched_prompt_text}")
                            print(f"Interactive Prompt Detected: {matched_prompt_text}")
                            log_msg = f"[PROMPT DETECTED]:\n{prompt_context_for_log}\n"
                            full_log += log_msg

                            print(f"Asking user for response via UI...")
                            # --- Signal UI for Generic Input ---
                            task_state_manager[task_id].update({
                                "status": "awaiting_input",
                                "prompt_needed": True,
                                "prompt_text": f"Input required:\n{prompt_context_for_log}",
                                "input_type": "text", # Hint for UI
                                "user_response": None # Clear previous response
                            })
                            wait_event.clear() # Ensure event is cleared before waiting
                            task_logger.info("Waiting for user input (interactive prompt) via UI...")
                            wait_event.wait() # Pause thread

                            # --- Resume after UI input ---
                            user_input = task_state_manager[task_id].get("user_response")
                            task_state_manager[task_id].update({ # Clear prompt state
                                 "prompt_needed": False,
                                 "prompt_text": None,
                                 "input_type": None,
                                 "user_response": None
                            })

                            if user_input is not None:
                                task_logger.info(f"Received response from user UI: '{user_input}'. Sending.")
                                print(f"Received response from UI: '{user_input}'. Sending...")
                                child.sendline(user_input)
                                log_msg = f"[RESPONSE SENT (UI)]: {user_input}\n"
                                full_log += log_msg
                            else:
                                error_msg = "Failed to get interactive response from user UI (no response or cancelled)."
                                log_msg = f"[ERROR]: {error_msg}\n"
                                full_log += log_msg
                                task_logger.error(error_msg)
                                error_logger.error(f"(ConvID: {conv_id}) {error_msg}")
                                raise RuntimeError(f"Failed to get interactive response from user UI for prompt: {prompt_context_for_log}")


                        # Continue interaction loop

                    # --- Error Handling within Interaction Loop ---
                    except pexpect.TIMEOUT:
                        overall_success = False
                        error_msg = f"Command '{cmd}' timed out while waiting for output/prompt."
                        print(f"ERROR: {error_msg}")
                        final_stderr += error_msg + "\n"
                        task_logger.error(error_msg)
                        error_logger.error(f"(ConvID: {conv_id}) Execution TIMEOUT for command: $ {cmd}")
                        if child: child.close(force=True)
                        break # Break inner loop, move to next command or finish

                    except EOFError: # Should be caught by pexpect.EOF, but handle defensively
                        overall_success = False
                        error_msg = f"EOF occurred unexpectedly during interaction with command: '{cmd}'"
                        print(f"ERROR: {error_msg}")
                        final_stderr += error_msg + "\n"
                        task_logger.error(error_msg)
                        error_logger.error(f"(ConvID: {conv_id}) Unexpected EOF for command: $ {cmd}")
                        if child: child.close(force=True)
                        break # Break inner loop

                    except Exception as interaction_err: # Catch other errors during expect/send
                        overall_success = False
                        error_msg = f"Error during interactive execution of '{cmd}': {interaction_err}"
                        log_context_err = f"[ERROR DURING INTERACTION]: Context:\n{prompt_context_for_log}\nError: {interaction_err}\n"
                        full_log += log_context_err # Add error context to main log
                        print(f"ERROR: {error_msg}")
                        final_stderr += error_msg + "\n"
                        task_logger.error(f"Interaction Error for command: $ {cmd}\nContext:\n{prompt_context_for_log}\nError: {interaction_err}", exc_info=True)
                        error_logger.error(f"(ConvID: {conv_id}) Interaction Error for command: $ {cmd} - Error: {interaction_err}", exc_info=True)
                        if child: child.close(force=True)
                        break # Break inner loop
                    # --- End Interaction Error Handling ---

                # --- Post Interaction Loop (after EOF or break) ---
                if child and not child.closed:
                    try:
                        # Read any final output after EOF or error break
                        remaining_output = child.read().strip()
                        if remaining_output:
                            print(f"Remaining Output:\n{remaining_output}")
                            full_log += remaining_output + "\n" # Add final output to main log
                            task_logger.info(f"Final Output Received:\n{remaining_output}")
                            full_log += "--- Command End (Final Read) ---\n"
                    except Exception as read_err:
                        warn_msg = f"Error reading final output after command close/break: {read_err}"
                        task_logger.warning(warn_msg)
                        log_warn = f"[WARNING]: {warn_msg}\n"
                        full_log += log_warn
                    finally:
                        # Ensure graceful close if possible
                        if not child.closed:
                           child.close()
                        # Remove child from state manager after it's closed
                        if task_state_manager[task_id].get('pexpect_child') == child:
                            task_state_manager[task_id]['pexpect_child'] = None


                # Check exit/signal status *after* closing
                exit_status = child.exitstatus
                signal_status = child.signalstatus
                task_logger.info(f"Command finished. Exit Status: {exit_status}, Signal Status: {signal_status}")

                if exit_status is not None and exit_status != 0:
                    overall_success = False
                    error_msg = f"Command '{cmd}' exited with non-zero status: {exit_status}"
                    print(f"ERROR: {error_msg}")
                    final_stderr += error_msg + "\n"
                    task_logger.error(f"Command failed: $ {cmd} - Exit Status: {exit_status}")
                    error_logger.error(f"(ConvID: {conv_id}) Command failed: $ {cmd} - Exit Status: {exit_status}")
                    # Don't break here in the executor; let llm_commander decide based on overall_success
                    # break # Stop processing further commands in this attempt

                elif signal_status is not None:
                    overall_success = False
                    error_msg = f"Command '{cmd}' terminated by signal: {signal_status}"
                    print(f"ERROR: {error_msg}")
                    final_stderr += error_msg + "\n"
                    task_logger.error(f"Command failed: $ {cmd} - Terminated by Signal: {signal_status}")
                    error_logger.error(f"(ConvID: {conv_id}) Command failed: $ {cmd} - Terminated by Signal: {signal_status}")
                    # Don't break here in the executor
                    # break # Stop processing further commands

            except Exception as spawn_err:
                # Catch errors during pexpect.spawn or outside the inner loop
                overall_success = False
                err_msg = f"Critical error setting up or finalizing execution for '{cmd}': {spawn_err}"
                print(f"ERROR: {err_msg}")
                final_stderr += err_msg + "\n"
                task_logger.error(f"Outer Execution Error for command: $ {cmd} - Error: {spawn_err}", exc_info=True)
                error_logger.error(f"(ConvID: {conv_id}) Outer Execution Error for command: $ {cmd} - Error: {spawn_err}", exc_info=True)
                if child and not child.closed:
                    child.close(force=True) # Ensure child is closed
                # Remove child from state manager on critical error
                if 'pexpect_child' in task_state_manager[task_id]:
                    task_state_manager[task_id]['pexpect_child'] = None
                # Let llm_commander handle the overall failure
                # break # Stop processing further commands

            # If *this specific command* failed, we stop executing the rest in the list for this attempt.
            if not overall_success:
                task_logger.warning(f"Execution block terminated early due to failure in command: $ {cmd}")
                break

        # --- End of Command Loop ---
        task_logger.info(f"Finished execution block. Overall success this block: {overall_success}")
        print("--- Command Execution Block Finished ---")
        return overall_success, full_log.strip(), final_stderr.strip()