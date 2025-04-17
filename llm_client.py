# llm-commander/llm_client.py
# Update system prompts in get_llm_plan and get_llm_commands_for_step

import logging
import json
import re
from datetime import datetime, timedelta
from collections import deque
import google.generativeai as genai

# Use the main error logger configured in log_setup for client-level errors
from log_setup import error_logger

# Default logger if none is passed to methods (logs only critical config errors)
default_logger = logging.getLogger(__name__)

class LLMClient:
    """Handles interactions with the Google Generative AI API."""

    def __init__(self, api_key: str, model_name: str, max_calls_minute: int, max_calls_day: int):
        self.model_name = model_name
        self.max_calls_minute = max_calls_minute
        self.max_calls_day = max_calls_day
        self.api_call_times_minute = deque()
        self.api_call_times_day = deque()

        try:
            if not api_key:
                raise ValueError("Gemini API Key is required.")
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel(self.model_name)
            # Use main error logger for setup info/errors
            error_logger.info(f"Successfully configured Gemini model: {self.model_name}")
        except Exception as e:
            error_logger.critical(f"Fatal: Failed to configure Gemini: {e}", exc_info=True)
            raise RuntimeError(f"Failed to configure Gemini LLM: {e}") from e

    def _check_rate_limit(self, conv_id: str, task_logger: logging.Logger) -> tuple[bool, str]:
        """Checks if an API call is allowed based on rate limits."""
        now = datetime.now()
        one_minute_ago = now - timedelta(minutes=1)
        while self.api_call_times_minute and self.api_call_times_minute[0] < one_minute_ago:
            self.api_call_times_minute.popleft()
        one_day_ago = now - timedelta(days=1)
        while self.api_call_times_day and self.api_call_times_day[0] < one_day_ago:
            self.api_call_times_day.popleft()

        if len(self.api_call_times_minute) >= self.max_calls_minute:
            msg = f"Rate limit per minute exceeded ({self.max_calls_minute}/min)."
            task_logger.warning(f"LLM Call Aborted (ConvID: {conv_id}): {msg}")
            error_logger.warning(f"LLM Rate limit hit (minute) for ConvID: {conv_id}") # Also log to main error log
            return False, msg
        if len(self.api_call_times_day) >= self.max_calls_day:
            msg = f"Rate limit per day exceeded ({self.max_calls_day}/day)."
            task_logger.warning(f"LLM Call Aborted (ConvID: {conv_id}): {msg}")
            error_logger.warning(f"LLM Rate limit hit (day) for ConvID: {conv_id}") # Also log to main error log
            return False, msg
        return True, "OK"

    def _record_api_call(self):
        """Records the timestamp of an API call."""
        now = datetime.now()
        self.api_call_times_minute.append(now)
        self.api_call_times_day.append(now)

    def _parse_llm_json_response(self, raw_response_text: str, expected_key: str, conv_id: str, task_logger: logging.Logger, log_context: str) -> dict | list:
        """Parses and validates LLM JSON response, extracting the value of expected_key."""
        # Handle markdown code block wrappers
        if raw_response_text.startswith("```json"): raw_response_text = raw_response_text[7:]
        if raw_response_text.endswith("```"): raw_response_text = raw_response_text[:-3]
        raw_response_text = raw_response_text.strip()

        try:
            parsed_json = json.loads(raw_response_text)
        except json.JSONDecodeError as json_e:
            error_msg = f"LLM response ({log_context}) was not valid JSON: {json_e}. Response: {raw_response_text}"
            task_logger.error(f"LLM Response Parse Error ({log_context}): {error_msg}")
            error_logger.error(f"LLM JSON Parse Error (ConvID: {conv_id}, Context: {log_context}): {error_msg}", exc_info=True)
            raise ValueError(f"LLM {log_context} response was not valid JSON.") from json_e

        # Validate structure
        if not isinstance(parsed_json, dict) or expected_key not in parsed_json:
             error_msg = f"LLM Invalid Structure ({log_context}): Missing '{expected_key}' key. Response: {parsed_json}"
             task_logger.error(error_msg)
             error_logger.error(f"LLM Structure Error (ConvID: {conv_id}, Context: {log_context}): {error_msg}")
             raise ValueError(f"LLM JSON ({log_context}) missing '{expected_key}' key.")

        value = parsed_json[expected_key]

        # Specific validation based on expected key
        if expected_key == "commands":
            if not isinstance(value, list):
                 error_msg = f"LLM Invalid Structure ({log_context}): '{expected_key}' not a list. Response: {parsed_json}"
                 task_logger.error(error_msg)
                 error_logger.error(f"LLM Structure Error (ConvID: {conv_id}, Context: {log_context}): {error_msg}")
                 raise ValueError(f"'{expected_key}' value must be a list.")
            if not all(isinstance(cmd, str) for cmd in value):
                 error_msg = f"LLM Invalid Structure ({log_context}): Command list has non-string. Response: {parsed_json}"
                 task_logger.error(error_msg)
                 error_logger.error(f"LLM Structure Error (ConvID: {conv_id}, Context: {log_context}): {error_msg}")
                 raise ValueError("Command list contains non-string elements.")
        elif expected_key == "plan":
             if not isinstance(value, list):
                 error_msg = f"LLM Invalid Structure ({log_context}): '{expected_key}' not a list. Response: {parsed_json}"
                 task_logger.error(error_msg)
                 error_logger.error(f"LLM Structure Error (ConvID: {conv_id}, Context: {log_context}): {error_msg}")
                 raise ValueError(f"'{expected_key}' value must be a list.")
             if not all(isinstance(step, str) for step in value):
                 error_msg = f"LLM Invalid Structure ({log_context}): Plan list has non-string. Response: {parsed_json}"
                 task_logger.error(error_msg)
                 error_logger.error(f"LLM Structure Error (ConvID: {conv_id}, Context: {log_context}): {error_msg}")
                 raise ValueError("Plan list contains non-string elements.")

        return value

    def get_llm_plan(self, initial_prompt: str, conv_id: str, task_logger: logging.Logger) -> list[str]:
        """
        Gets a sequence of plan steps from the LLM based on the initial user prompt.
        """
        allowed, message = self._check_rate_limit(conv_id, task_logger)
        if not allowed:
            raise Exception(f"Rate limit exceeded: {message}")

        # --- UPDATED SYSTEM PROMPT ---
        system_prompt = """
You are an AI assistant specializing in planning tasks for system administration.
Your ONLY goal is to break down the user's request into a logical sequence of high-level steps or actions achievable via non-interactive shell commands.
Respond ONLY with a valid JSON object containing a single key "plan". The value of "plan" MUST be a list of strings. Each string represents one step in the plan.
Do NOT include explanations, apologies, greetings, or any text other than the JSON object.
The steps should be actionable descriptions, not the shell commands themselves (e.g., "Check available disk space", "Identify files larger than 1GB", "Ask user for confirmation to delete").

**IMPORTANT CONSTRAINTS**:
1.  Plan steps MUST describe actions performable directly via non-interactive terminal commands. Do NOT suggest steps that require opening interactive applications (like text editors `nano`, `vim`, `emacs`, or other TUIs).
2.  If a step involves generating code (e.g., a script), the step description MUST explicitly include the action of saving that code to a specific file using non-interactive commands (e.g., "Generate Python script to list files and save it to list_files.py using echo/cat"). Choose a sensible filename if one is not provided.

If the request is unclear, unsafe, cannot be broken down into steps, or violates the constraints, respond with: lbrace"plan": []rbrace

User Request:
{prompt}
"""
        # --- END UPDATED SYSTEM PROMPT ---

        full_prompt = system_prompt.format(prompt=initial_prompt)

        task_logger.info(f"LLM Prompt (Plan Gen):\n{full_prompt}")
        default_logger.info(f"Sending planning prompt to LLM (ConvID: {conv_id}).")

        try:
            self._record_api_call()
            response = self.model.generate_content(full_prompt)
            raw_response_text = response.text.strip()
            task_logger.info(f"LLM Raw Response (Plan Gen):\n{raw_response_text}")

            plan_steps = self._parse_llm_json_response(raw_response_text, "plan", conv_id, task_logger, "Plan Gen")

            task_logger.info(f"LLM Parsed Plan: {plan_steps}")
            default_logger.info(f"LLM generated plan (ConvID: {conv_id}): {plan_steps}")
            return plan_steps

        except Exception as e:
            task_logger.error(f"LLM Call/Processing Error (Plan Gen): {e}", exc_info=True)
            error_logger.error(f"Error during LLM plan generation (ConvID: {conv_id}): {e}", exc_info=True)
            raise Exception(f"Error interacting with LLM for plan generation: {e}") from e

    def get_llm_commands_for_step(self, plan_step: str, initial_goal: str, previous_steps_summary: str, conv_id: str, task_logger: logging.Logger) -> list[str]:
        """
        Gets shell commands from the LLM for a specific plan step.
        """
        allowed, message = self._check_rate_limit(conv_id, task_logger)
        if not allowed:
            raise Exception(f"Rate limit exceeded: {message}")

        # --- UPDATED SYSTEM PROMPT ---
        system_prompt = """
You are an expert system administrator AI assistant. Your task is to translate the current plan step into a sequence of **non-interactive Ubuntu Linux terminal commands**.
Respond ONLY with a valid JSON object containing a single key "commands". The value of "commands" MUST be a list of strings. Each string is a single shell command to be executed in sequence for THIS STEP ONLY.
Ensure the commands are appropriate for an Ubuntu environment.

**IMPORTANT CONSTRAINTS**:
1.  Do NOT generate commands that launch interactive terminal applications (e.g., `nano`, `vim`, `emacs`, `less`, `top`, `htop`, `aptitude`, etc.).
2.  For creating or modifying files, use non-interactive commands like `echo "content" > file`, `printf "content" >> file`, `cat << EOF > file ... EOF`, `mkdir`, `touch`, `sed`, `awk`, etc.
3.  The commands must directly achieve the described step without requiring further interactive input within the command itself (unless it's a standard prompt handled by the execution environment like sudo password or yes/no confirmation).

Do NOT include any explanations, apologies, task text, markdown formatting, comments, or anything other than the JSON object.
If you cannot determine appropriate non-interactive commands for this step, the step is unclear/unsafe, or violates the constraints, respond with: lbrace"commands": []rbrace

Original Goal: {goal}
Previous Steps Completed Summary: {prev_summary}
Current Step to Execute: {step}
"""
        # --- END UPDATED SYSTEM PROMPT ---

        full_prompt = system_prompt.format(goal=initial_goal, prev_summary=previous_steps_summary or "None", step=plan_step)

        task_logger.info(f"LLM Prompt (Command Gen for Step '{plan_step}'):\n{full_prompt}")
        default_logger.info(f"Sending command generation prompt to LLM for step (ConvID: {conv_id}).")

        try:
            self._record_api_call()
            response = self.model.generate_content(full_prompt)
            raw_response_text = response.text.strip()
            task_logger.info(f"LLM Raw Response (Command Gen for Step):\n{raw_response_text}")

            commands = self._parse_llm_json_response(raw_response_text, "commands", conv_id, task_logger, "Command Gen for Step")

            task_logger.info(f"LLM Parsed Commands for Step: {commands}")
            default_logger.info(f"LLM proposed commands for step (ConvID: {conv_id}): {commands}")
            return commands

        except Exception as e:
            task_logger.error(f"LLM Call/Processing Error (Command Gen for Step): {e}", exc_info=True)
            error_logger.error(f"Error during LLM command generation for step (ConvID: {conv_id}): {e}", exc_info=True)
            raise Exception(f"Error interacting with LLM for command generation: {e}") from e


    # --- get_llm_interactive_response remains the same ---
    def get_llm_interactive_response(self, prompt_context: str, original_goal: str, conv_id: str, task_logger: logging.Logger) -> str:
        """
        Gets a suggested response from the LLM for an interactive command prompt.
        (No changes needed for this method)
        """
        allowed, message = self._check_rate_limit(conv_id, task_logger)
        if not allowed:
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

        task_logger.info(f"LLM Prompt (Interactive Resp):\n{full_prompt}")
        default_logger.info(f"Sending interactive prompt context to LLM (ConvID: {conv_id}).")

        try:
            self._record_api_call()
            response = self.model.generate_content(full_prompt)
            answer = response.text.strip()
            task_logger.info(f"LLM Raw Response (Interactive Resp): {answer}")

            # Basic cleanup
            if (answer.startswith('"') and answer.endswith('"')) or \
               (answer.startswith("'") and answer.endswith("'")):
                answer = answer[1:-1]

            task_logger.info(f"LLM Cleaned Response (Interactive Resp): '{answer}'")
            default_logger.info(f"LLM suggested interactive response (ConvID: {conv_id}): '{answer}'")
            return answer

        except Exception as e:
            task_logger.error(f"LLM Call/Processing Error (Interactive Resp): {e}", exc_info=True)
            error_logger.error(f"Error during LLM interactive response call (ConvID: {conv_id}): {e}", exc_info=True)
            raise Exception(f"Error interacting with LLM for interactive response: {e}") from e