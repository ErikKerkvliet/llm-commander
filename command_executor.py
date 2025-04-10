# llm-commander/command_executor.py
import logging
import re
import subprocess # Keep for non-interactive fallback if needed later

# Try importing pexpect, handle import error for non-Unix systems
try:
    import pexpect
    PEXPECT_AVAILABLE = True
except ImportError:
    PEXPECT_AVAILABLE = False
    print("WARNING: 'pexpect' library not found. Interactive command execution will not be available.")
    print("         On Windows, consider using WSL or alternative libraries like 'weexpect'.")

# Use the logger configured in log_setup
logger = logging.getLogger(__name__)
conversation_logger = logging.getLogger('ConversationLogger') # Get conversation logger

# Import LLMClient type hint if possible (avoids circular dependency issue at runtime)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from llm_client import LLMClient


class CommandExecutor:
    """Executes shell commands, potentially interactively using pexpect."""

    def __init__(self, llm_client: 'LLMClient', sudo_password: str | None):
        """
        Initializes the CommandExecutor.

        Args:
            llm_client: An instance of LLMClient to handle interactive prompts.
            sudo_password: The sudo password (if available). SECURITY RISK!
        """
        self.llm_client = llm_client
        self.sudo_password = sudo_password
        if not PEXPECT_AVAILABLE:
            logger.warning("'pexpect' not available. Interactive execution disabled.")
            print("WARNING: Interactive command execution is disabled because 'pexpect' is not installed.")

    def execute_commands(self, commands: list[str], original_goal: str, conv_id: str) -> tuple[bool, str, str]:
        """
        Executes a list of commands using pexpect, handling interactive prompts via LLM.

        Args:
            commands: A list of command strings to execute.
            original_goal: The initial user prompt/goal (for context in interactive).
            conv_id: The conversation ID for logging.

        Returns:
            A tuple containing:
            - success (bool): True if all commands executed without error, False otherwise.
            - aggregated_log (str): Combined stdout/stderr and interaction log.
            - aggregated_stderr (str): Specific error messages encountered.
        """
        log_extra = {'conv_id': conv_id}
        if not PEXPECT_AVAILABLE:
            error_msg = "Cannot execute commands interactively: pexpect library is not available."
            logger.error(error_msg, extra=log_extra)
            conversation_logger.error("Pexpect not available, cannot execute interactively.", extra=log_extra)
            # Fallback to non-interactive if needed, or just fail here?
            # For now, we fail if pexpect is required for interaction.
            return False, "", error_msg

        full_log = "" # Combined raw log of interaction for returning
        final_stderr = "" # Collect specific error output for returning
        overall_success = True

        if not commands:
            logger.info("No commands provided for execution.", extra=log_extra)
            conversation_logger.info("No commands proposed by LLM to execute.", extra=log_extra)
            return True, "No commands to execute.", ""

        conversation_logger.info(f"Starting execution of {len(commands)} commands.", extra=log_extra)

        for cmd_idx, cmd in enumerate(commands):
            if not cmd or not isinstance(cmd, str) or cmd.isspace():
                logger.warning(f"Skipping empty/invalid command string: {cmd!r}", extra=log_extra)
                conversation_logger.warning(f"Skipping empty command string: {cmd!r}", extra=log_extra)
                continue

            logger.info(f"Executing Command {cmd_idx+1}/{len(commands)}: $ {cmd}", extra=log_extra)
            print(f"\n--- Executing Command {cmd_idx+1}/{len(commands)} (Interactive): {cmd} ---")
            cmd_log_header = f"\n\n>>> EXEC ({cmd_idx+1}/{len(commands)}): $ {cmd}\n"
            full_log += cmd_log_header
            conversation_logger.info(f"Executing Command: $ {cmd}", extra=log_extra)
            child = None
            prompt_context_for_log = "" # Track context for logging

            try:
                # Use 'bash -c' to handle pipes, redirections etc. within the command string
                child = pexpect.spawn('/bin/bash', ['-c', cmd], timeout=300, encoding='utf-8', echo=False)

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
                            conversation_logger.info(f"Output Received:\n{output_before}", extra=log_extra)

                        # Handle based on the matched pattern index
                        if index == 0: # EOF
                            logger.debug("Command finished (EOF).", extra=log_extra)
                            print("Command finished (EOF).")
                            full_log += "--- Command End (EOF) ---\n"
                            conversation_logger.info("Command execution reached EOF.", extra=log_extra)
                            break # Exit inner loop

                        elif index == 1: # TIMEOUT
                            raise pexpect.TIMEOUT("Command timed out during expect.")

                        elif index == 2: # Sudo password prompt
                            logger.info(f"Sudo Prompt Detected: {matched_prompt_text}", extra=log_extra)
                            print(f"Prompt Detected: {matched_prompt_text}")
                            log_msg = f"[PROMPT DETECTED]:\n{prompt_context_for_log}\n"
                            full_log += log_msg
                            conversation_logger.info(f"Sudo Prompt Detected:\n{prompt_context_for_log}", extra=log_extra)

                            if self.sudo_password:
                                logger.info("Sending sudo password.", extra=log_extra)
                                print("Sending sudo password...")
                                child.sendline(self.sudo_password)
                                log_msg = "[RESPONSE SENT]: [sudo password]\n"
                                full_log += log_msg
                                conversation_logger.info("Sent sudo password.", extra=log_extra)
                            else:
                                log_msg = "[ERROR]: Sudo prompt detected, but SUDO_PASSWORD not available.\n"
                                full_log += log_msg
                                conversation_logger.error("Sudo prompt detected, but no SUDO_PASSWORD configured.", extra=log_extra)
                                raise ValueError("Sudo prompt detected, but SUDO_PASSWORD not set.")

                        elif index >= 3: # Interactive prompt detected
                            logger.info(f"Interactive Prompt Detected: {matched_prompt_text}", extra=log_extra)
                            print(f"Interactive Prompt Detected: {matched_prompt_text}")
                            log_msg = f"[PROMPT DETECTED]:\n{prompt_context_for_log}\n"
                            full_log += log_msg
                            conversation_logger.info(f"Interactive Prompt Detected:\n{prompt_context_for_log}", extra=log_extra)

                            print(f"Asking LLM for response...")
                            try:
                                llm_answer = self.llm_client.get_llm_interactive_response(prompt_context_for_log, original_goal, conv_id)
                                logger.info(f"Sending LLM response: '{llm_answer}'", extra=log_extra)
                                print(f"Sending LLM response: '{llm_answer}'")
                                child.sendline(llm_answer)
                                log_msg = f"[RESPONSE SENT (LLM)]: {llm_answer}\n"
                                full_log += log_msg
                                conversation_logger.info(f"Sent LLM Response: '{llm_answer}'", extra=log_extra)
                            except Exception as llm_err:
                                error_msg = f"Failed to get/send LLM response for interactive prompt: {llm_err}"
                                log_msg = f"[ERROR]: {error_msg}\n"
                                full_log += log_msg
                                conversation_logger.error(f"LLM Interactive Response Error: {llm_err}", extra=log_extra, exc_info=True)
                                # Raise to break the command execution loop
                                raise RuntimeError(error_msg) from llm_err

                        # Continue interaction loop

                    # --- Error Handling within Interaction Loop ---
                    except pexpect.TIMEOUT:
                        overall_success = False
                        error_msg = f"Command '{cmd}' timed out while waiting for output/prompt."
                        print(f"ERROR: {error_msg}")
                        final_stderr += error_msg + "\n"
                        logger.error(error_msg, extra=log_extra)
                        conversation_logger.error(f"Execution TIMEOUT for command: $ {cmd}", extra=log_extra)
                        if child: child.close(force=True)
                        break # Break inner loop, move to next command or finish

                    except EOFError: # Should be caught by pexpect.EOF, but handle defensively
                        overall_success = False
                        error_msg = f"EOF occurred unexpectedly during interaction with command: '{cmd}'"
                        print(f"ERROR: {error_msg}")
                        final_stderr += error_msg + "\n"
                        logger.error(error_msg, extra=log_extra)
                        conversation_logger.error(f"Unexpected EOF for command: $ {cmd}", extra=log_extra)
                        if child: child.close(force=True)
                        break # Break inner loop

                    except Exception as interaction_err: # Catch other errors during expect/send
                        overall_success = False
                        error_msg = f"Error during interactive execution of '{cmd}': {interaction_err}"
                        log_context_err = f"[ERROR DURING INTERACTION]: Context:\n{prompt_context_for_log}\nError: {interaction_err}\n"
                        full_log += log_context_err # Add error context to main log
                        print(f"ERROR: {error_msg}")
                        final_stderr += error_msg + "\n"
                        logger.error(error_msg, exc_info=True, extra=log_extra)
                        conversation_logger.error(f"Interaction Error for command: $ {cmd}\nContext:\n{prompt_context_for_log}\nError: {interaction_err}", exc_info=True, extra=log_extra)
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
                            conversation_logger.info(f"Final Output Received:\n{remaining_output}", extra=log_extra)
                            full_log += "--- Command End (Final Read) ---\n"
                    except Exception as read_err:
                        logger.warning(f"Error reading final output after command close/break: {read_err}", extra=log_extra)
                        log_warn = f"[WARNING]: Error reading final output: {read_err}\n"
                        full_log += log_warn
                        conversation_logger.warning(f"Error reading final output: {read_err}", extra=log_extra)
                    finally:
                        # Ensure graceful close if possible
                        if not child.closed:
                           child.close()

                # Check exit/signal status *after* closing
                exit_status = child.exitstatus
                signal_status = child.signalstatus
                conversation_logger.info(f"Command finished. Exit Status: {exit_status}, Signal Status: {signal_status}", extra=log_extra)

                if exit_status is not None and exit_status != 0:
                    overall_success = False
                    error_msg = f"Command '{cmd}' exited with non-zero status: {exit_status}"
                    print(f"ERROR: {error_msg}")
                    final_stderr += error_msg + "\n"
                    logger.error(error_msg, extra=log_extra)
                    conversation_logger.error(f"Command failed: $ {cmd} - Exit Status: {exit_status}", extra=log_extra)
                    break # Stop processing further commands in this attempt

                elif signal_status is not None:
                    overall_success = False
                    error_msg = f"Command '{cmd}' terminated by signal: {signal_status}"
                    print(f"ERROR: {error_msg}")
                    final_stderr += error_msg + "\n"
                    logger.error(error_msg, extra=log_extra)
                    conversation_logger.error(f"Command failed: $ {cmd} - Terminated by Signal: {signal_status}", extra=log_extra)
                    break # Stop processing further commands

            except Exception as spawn_err:
                # Catch errors during pexpect.spawn or outside the inner loop
                overall_success = False
                err_msg = f"Critical error setting up or finalizing execution for '{cmd}': {spawn_err}"
                print(f"ERROR: {err_msg}")
                final_stderr += err_msg + "\n"
                logger.error(err_msg, exc_info=True, extra=log_extra)
                conversation_logger.error(f"Outer Execution Error for command: $ {cmd} - Error: {spawn_err}", exc_info=True, extra=log_extra)
                if child and not child.closed:
                    child.close(force=True) # Ensure child is closed
                break # Stop processing further commands

            # Break outer command loop if a failure occurred for this command
            if not overall_success:
                logger.warning(f"Execution block terminated early due to failure in command: $ {cmd}", extra=log_extra)
                break

        # --- End of Command Loop ---
        conversation_logger.info(f"Finished execution block. Overall success this block: {overall_success}", extra=log_extra)
        print("--- Command Execution Block Finished ---")
        return overall_success, full_log.strip(), final_stderr.strip()