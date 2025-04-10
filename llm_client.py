# llm-commander/llm_client.py
import logging
import json
from datetime import datetime, timedelta
from collections import deque
import google.generativeai as genai

# Use the logger configured in log_setup
logger = logging.getLogger(__name__)
conversation_logger = logging.getLogger('ConversationLogger') # Get conversation logger

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
            logger.info(f"Successfully configured Gemini model: {self.model_name}")
        except Exception as e:
            logger.critical(f"Fatal: Failed to configure Gemini: {e}", exc_info=True)
            raise RuntimeError(f"Failed to configure Gemini LLM: {e}") from e

    def _check_rate_limit(self, conv_id: str) -> tuple[bool, str]:
        """Checks if an API call is allowed based on rate limits."""
        log_extra = {'conv_id': conv_id}
        now = datetime.now()
        one_minute_ago = now - timedelta(minutes=1)
        while self.api_call_times_minute and self.api_call_times_minute[0] < one_minute_ago:
            self.api_call_times_minute.popleft()
        one_day_ago = now - timedelta(days=1)
        while self.api_call_times_day and self.api_call_times_day[0] < one_day_ago:
            self.api_call_times_day.popleft()

        if len(self.api_call_times_minute) >= self.max_calls_minute:
            msg = "Rate limit per minute exceeded."
            logger.warning(msg, extra=log_extra)
            conversation_logger.warning(f"LLM Call Aborted: {msg}", extra=log_extra)
            return False, msg
        if len(self.api_call_times_day) >= self.max_calls_day:
            msg = "Rate limit per day exceeded."
            logger.warning(msg, extra=log_extra)
            conversation_logger.warning(f"LLM Call Aborted: {msg}", extra=log_extra)
            return False, msg
        return True, "OK"

    def _record_api_call(self):
        """Records the timestamp of an API call."""
        now = datetime.now()
        self.api_call_times_minute.append(now)
        self.api_call_times_day.append(now)

    def get_llm_commands(self, prompt_text: str, conv_id: str) -> list[str]:
        """Gets commands from the LLM based on a user prompt."""
        log_extra = {'conv_id': conv_id}
        allowed, message = self._check_rate_limit(conv_id)
        if not allowed:
            raise Exception(f"Rate limit exceeded: {message}")

        system_prompt = """
You are an expert system administrator AI assistant. Your ONLY task is to translate user requests or error messages into a sequence of shell commands runnable on a Linux-based system.
Respond ONLY with a valid JSON object containing a single key "commands". The value of "commands" MUST be a list of strings. Each string is a single shell command to be executed in sequence.
Do NOT include any explanations, apologies, conversational text, markdown formatting, or anything other than the JSON object.
If you cannot determine appropriate commands or the request is unclear/unsafe, respond with: {"commands": []}
"""
        full_prompt = f"{system_prompt}\n\nUser Request/Error:\n{prompt_text}"

        conversation_logger.info(f"LLM Prompt (Command Gen):\n{full_prompt}", extra=log_extra)
        logger.info(f"Sending command generation prompt to LLM (ConvID: {conv_id}).")

        try:
            self._record_api_call()
            response = self.model.generate_content(full_prompt)
            raw_response_text = response.text.strip()
            conversation_logger.info(f"LLM Raw Response (Command Gen):\n{raw_response_text}", extra=log_extra)

            # Handle markdown code block wrappers
            if raw_response_text.startswith("```json"): raw_response_text = raw_response_text[7:]
            if raw_response_text.endswith("```"): raw_response_text = raw_response_text[:-3]
            raw_response_text = raw_response_text.strip()

            try:
                parsed_json = json.loads(raw_response_text)
            except json.JSONDecodeError as json_e:
                error_msg = f"LLM response (commands) was not valid JSON: {json_e}. Response: {raw_response_text}"
                logger.error(error_msg, exc_info=True, extra=log_extra)
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
            logger.info(f"LLM proposed commands (ConvID: {conv_id}): {commands}")
            return commands

        except Exception as e:
            logger.error(f"Error during LLM command generation: {e}", exc_info=True, extra=log_extra)
            conversation_logger.error(f"LLM Call/Processing Error (Command Gen): {e}", exc_info=True, extra=log_extra)
            # Re-raise as a generic exception to be caught by the main loop
            raise Exception(f"Error interacting with LLM for command generation: {e}") from e


    def get_llm_interactive_response(self, prompt_context: str, original_goal: str, conv_id: str) -> str:
        """Gets a suggested response from the LLM for an interactive command prompt."""
        log_extra = {'conv_id': conv_id}
        allowed, message = self._check_rate_limit(conv_id)
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

        conversation_logger.info(f"LLM Prompt (Interactive Resp):\n{full_prompt}", extra=log_extra)
        logger.info(f"Sending interactive prompt context to LLM (ConvID: {conv_id}).")

        try:
            self._record_api_call()
            response = self.model.generate_content(full_prompt)
            answer = response.text.strip()
            conversation_logger.info(f"LLM Raw Response (Interactive Resp): {answer}", extra=log_extra)

            # Basic cleanup
            if (answer.startswith('"') and answer.endswith('"')) or \
               (answer.startswith("'") and answer.endswith("'")):
                answer = answer[1:-1]

            conversation_logger.info(f"LLM Cleaned Response (Interactive Resp): '{answer}'", extra=log_extra)
            logger.info(f"LLM suggested interactive response (ConvID: {conv_id}): '{answer}'")
            return answer

        except Exception as e:
            logger.error(f"Error during LLM interactive response call: {e}", exc_info=True, extra=log_extra)
            conversation_logger.error(f"LLM Call/Processing Error (Interactive Resp): {e}", exc_info=True, extra=log_extra)
            raise Exception(f"Error interacting with LLM for interactive response: {e}") from e