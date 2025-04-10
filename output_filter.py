# llm-commander/output_filter.py
import re
import logging

# Use the logger configured in log_setup
logger = logging.getLogger(__name__) # Get logger for this module

class OutputFilter:
    """
    Filters command output (stdout/log) based on execution success.
    - On failure: Extracts Python tracebacks.
    - On success: Keeps the last N lines.
    """
    TRACEBACK_REGEX = re.compile(
        r"Traceback \(most recent call last\):[\s\S]*?^\w+Error: .*",
        re.MULTILINE
    )
    TRACEBACK_START_MARKER = "Traceback (most recent call last):"
    DEFAULT_SUCCESS_LINES = 20

    def __init__(self, success_lines: int = DEFAULT_SUCCESS_LINES):
        """
        Initializes the filter.
        Args:
            success_lines: Number of lines to keep from the end on success.
        """
        if not isinstance(success_lines, int) or success_lines <= 0:
            logger.warning(f"Invalid success_lines value ({success_lines}), using default {self.DEFAULT_SUCCESS_LINES}.")
            self.success_lines = self.DEFAULT_SUCCESS_LINES
        else:
            self.success_lines = success_lines
        # Use logger from log_setup
        logger.info(f"OutputFilter initialized to keep last {self.success_lines} lines on success.")

    def _extract_tracebacks_regex(self, data: str) -> str:
        """Attempts to extract tracebacks using regex."""
        try:
            matches = self.TRACEBACK_REGEX.findall(data)
            if matches:
                return "\n---\n".join(matches)
        except Exception as e:
            logger.error(f"Error during regex traceback extraction: {e}", exc_info=True)
        return ""

    def _extract_tracebacks_lines(self, data: str) -> str:
        """Extracts tracebacks using line-based checking as a fallback."""
        try:
            lines = data.splitlines()
            traceback_lines = []
            in_traceback = False
            for line in lines:
                if line.startswith(self.TRACEBACK_START_MARKER):
                    in_traceback = True
                    traceback_lines.append(line)
                elif in_traceback:
                    is_indented = line.startswith((' ', '\t'))
                    is_error_line = re.match(r"^\w+Error:", line)
                    if line.strip() == "" or is_indented or is_error_line:
                        traceback_lines.append(line)
                        if is_error_line: # End of block after error line
                            in_traceback = False
                    elif not is_indented: # End block on unindented non-error line
                        in_traceback = False

            return "\n".join(traceback_lines)
        except Exception as e:
             logger.error(f"Error during line-based traceback extraction: {e}", exc_info=True)
             return ""

    def filter(self, output_data: str, success: bool) -> str:
        """
        Filters the output data based on the success flag.

        Args:
            output_data: The raw stdout/log string.
            success: Boolean indicating if the command execution succeeded.

        Returns:
            The filtered output string.
        """
        if not isinstance(output_data, str):
            logger.warning("Invalid input type for output_data in filter, expected string.")
            return ""

        if not success:
            logger.debug("Filtering output for failure: extracting tracebacks.")
            filtered_output = self._extract_tracebacks_regex(output_data)
            if not filtered_output:
                 logger.debug("Regex found no tracebacks, trying line-based fallback.")
                 filtered_output = self._extract_tracebacks_lines(output_data)

            if filtered_output:
                logger.info("Traceback found and extracted.")
                return f"[Filtered for Tracebacks]\n---\n{filtered_output.strip()}\n---"
            else:
                 logger.info("No traceback found on failure, returning last lines.")
                 lines = output_data.splitlines()
                 last_lines = lines[-self.success_lines:]
                 return f"[Failure: No Traceback Found - Showing Last {len(last_lines)} Lines]\n...\n" + "\n".join(last_lines)
        else:
            logger.debug(f"Filtering output for success: keeping last {self.success_lines} lines.")
            lines = output_data.splitlines()
            if len(lines) <= self.success_lines:
                return output_data
            else:
                last_lines = lines[-self.success_lines:]
                logger.info(f"Output truncated to last {len(last_lines)} lines.")
                return f"... (last {len(last_lines)} lines of output)\n" + "\n".join(last_lines)