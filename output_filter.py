# llm-commander/output_filter.py
# No changes required in this file. It remains the same.
import re
import logging

# Use the main error logger configured in log_setup if needed for internal errors
from log_setup import error_logger # For filter's own errors

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
    DEFAULT_SUCCESS_LINES = 2000000

    def __init__(self, success_lines: int = DEFAULT_SUCCESS_LINES):
        """
        Initializes the filter.
        Args:
            success_lines: Number of lines to keep from the end on success.
        """
        if not isinstance(success_lines, int) or success_lines <= 0:
            error_logger.warning(f"Invalid success_lines value ({success_lines}), using default {self.DEFAULT_SUCCESS_LINES}.")
            self.success_lines = self.DEFAULT_SUCCESS_LINES
        else:
            self.success_lines = success_lines
        # Use logger from log_setup if needed for operational info
        # logging.getLogger(__name__).info(f"OutputFilter initialized...") # Example
        error_logger.info(f"OutputFilter initialized to keep last {self.success_lines} lines on success.") # Use error_logger for config info

    def _extract_tracebacks_regex(self, data: str) -> str:
        """Attempts to extract tracebacks using regex."""
        try:
            matches = self.TRACEBACK_REGEX.findall(data)
            if matches:
                return "\n---\n".join(matches)
        except Exception as e:
            error_logger.error(f"Error during regex traceback extraction: {e}", exc_info=True)
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
             error_logger.error(f"Error during line-based traceback extraction: {e}", exc_info=True)
             return ""

    @staticmethod
    def filter_collapse_pair_empty(lines):
        """
        Filters a list of strings according to specific rules for empty strings ('').

        - Keeps non-empty strings (including whitespace-only).
        - Replaces exactly two consecutive '' with a single ''.
        - Removes single occurrences of ''.
        - Handles >2 consecutive '' based on pairs (e.g., '' '' '' -> '').

        Args:
            lines: A list of strings.

        Returns:
            A new list of strings with filtering applied.
        """
        filtered_lines = []
        i = 0
        n = len(lines)

        while i < n:
            current_line = lines[i]

            if current_line != '':
                # Rule 1: Keep non-empty lines
                filtered_lines.append(current_line)
                i += 1
            else:
                # Current line is '' - check the next one
                # Check if there *is* a next line and if it's *also* ''
                if i + 1 < n and lines[i + 1] == '':
                    # Rule 2: Found two consecutive ''
                    filtered_lines.append('')  # Add one '' to represent the pair
                    i += 2  # Skip both processed ''
                else:
                    # Rule 3: This is a single '' (or the last item)
                    # Remove it by doing nothing (not appending)
                    i += 1  # Move past the single ''

        return filtered_lines

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
            error_logger.warning("Invalid input type for output_data in filter, expected string.")
            return ""

        # Use debug level for filtering actions if desired
        # logging.getLogger(__name__).debug(f"Filtering output. Success={success}")

        if not success:
            # error_logger.debug("Filtering output for failure: extracting tracebacks.")
            filtered_output = self._extract_tracebacks_regex(output_data)
            if not filtered_output:
                 # error_logger.debug("Regex found no tracebacks, trying line-based fallback.")
                 filtered_output = self._extract_tracebacks_lines(output_data)

            if filtered_output:
                # error_logger.info("Traceback found and extracted.") # Can be noisy
                return f"[Filtered for Tracebacks]\n---\n{filtered_output.strip()}\n---"
            else:
                 # error_logger.info("No traceback found on failure, returning last lines.")
                 lines = output_data.splitlines()
                 last_lines = lines[-self.success_lines:]
                 return f"[Failure: No Traceback Found - Showing Last {len(last_lines)} Lines]\n...\n" + "\n".join(last_lines)
        else:
            # error_logger.debug(f"Filtering output for success: keeping last {self.success_lines} lines.")
            lines = output_data.splitlines()
            lines = self.filter_collapse_pair_empty(lines)

            if len(lines) <= self.success_lines:
                return '\n'.join(lines)
            else:
                last_lines = lines[-self.success_lines:]
                # error_logger.info(f"Output truncated to last {len(last_lines)} lines.") # Can be noisy
                return f"... (last {len(last_lines)} lines of output)\n" + "\n".join(last_lines)