# llm-commander/README.md
# (Changes only in Setup, Usage, and Configuration sections regarding logging)

# LLM Commander

**DANGER ZONE:** This application uses a Large Language Model (LLM) like Google Gemini to interpret natural language commands and translate them into executable shell commands, including potentially using `sudo`. **It executes these commands on the host machine.** This is inherently **VERY DANGEROUS** and should **ONLY** be run in a completely isolated, controlled, and trusted environment (like a dedicated, firewalled virtual machine) where accidental or malicious command execution cannot cause harm to important data or systems. **NEVER expose this application directly to the internet.**

*(**Note:** Ensure you create a `.gitignore` file to prevent committing sensitive files like `.env` and the `logs/` directory.)*

## Prerequisites

*   Python 3.8+
*   `pip` (Python package installer)
*   A Google Gemini API Key (from Google AI Studio or Google Cloud)
*   A Unix-like operating system (Linux, macOS, WSL on Windows) is required for `pexpect` functionality. The interactive features will not work reliably on native Windows Command Prompt or PowerShell.
*   Credentials (username and password) for a user with `sudo` privileges *on the machine where the server runs* if you intend to execute `sudo` commands (though storing the password is a major risk).

## Setup

1.  **Clone the repository (or download the code):**
    ```bash
    git clone <your-repo-url>
    cd llm-commander
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # Linux/macOS/WSL
    # Or: venv\Scripts\activate  # Windows Cmd/PowerShell
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Create the `.env` file:**
    Copy the structure from the Configuration section below into a new file named `.env` in the project root.
    ```bash
    touch .env
    # nano .env  (or your preferred editor)
    ```

5.  **Configure `.env`:**
    **Carefully** edit the `.env` file and replace **ALL** placeholder values with your actual information:
    *   `GEMINI_API_KEY`
    *   `LLM_MODEL` (Verify the model name is current)
    *   `SUDO_PASSWORD` (!!! HIGH SECURITY RISK !!! Consider removing sudo use entirely)
    *   `WEB_USERNAME` & `WEB_PASSWORD` (Choose strong credentials)
    *   `SECRET_KEY` (Generate a strong, random key using `python -c 'import secrets; print(secrets.token_hex(24))'`)
    *   Adjust other settings (`REQUIRE_CONFIRMATION`, `FILTER_SUCCESS_LINES`, rate limits) as needed.

6.  **Create `.gitignore` (Required):**
    Create a `.gitignore` file in the project root and add at least the following lines:
    ```gitignore
    .env
    venv/
    logs/
    __pycache__/
    *.pyc
    *.log # Might be redundant with logs/, but good practice
    ```

7.  **Firewall (Optional but Recommended):**
    If you intend to access the web interface from other machines on your local network, configure the host machine's firewall to allow incoming connections on the port the server runs on (default 5000).
    *   **UFW (Ubuntu/Debian):** `sudo ufw allow 5000/tcp`
    *   **Firewalld (CentOS/Fedora):** `sudo firewall-cmd --permanent --add-port=5000/tcp && sudo firewall-cmd --reload`

## Running the Application

1.  Ensure your virtual environment is activated (`source venv/bin/activate`).
2.  Run the Flask web server:
    ```bash
    python web_server.py
    ```
3.  The server will start, typically listening on `http://0.0.0.0:5000`. The output will confirm the address, port, and log file locations.

## Usage

1.  Open a web browser and navigate to the address shown when the server starts (e.g., `http://127.0.0.1:5000/login` or `http://<server-ip>:5000/login`).
2.  Log in using the `WEB_USERNAME` and `WEB_PASSWORD` you set in the `.env` file.
3.  Upon successful login, you will be redirected to the main commander page (`/`).
4.  Enter a task description or command prompt into the text area (e.g., "Install the cowsay package", "Show current disk usage").
5.  Adjust the "Max Retries" if desired.
6.  Click the "Execute Task" button.
7.  **Confirmation Step (If Enabled):** If `REQUIRE_CONFIRMATION=True` in your `.env`, you **MUST** check the **terminal** where `web_server.py` is running. It will display the commands the LLM wants to execute and prompt you with `>>> Execute these commands? (yes/no):`. Type `yes` and press Enter to proceed; any other input will cancel the execution for that task.
8.  **Results:** The web page will update to show the status and the results of the execution attempt(s). This includes the commands tried, success status, and filtered output/errors for each attempt.
9.  **Logs:**
    *   **General Errors:** Check `logs/error.log` for application-level errors (configuration, LLM API issues, critical failures).
    *   **Web Server Activity:** Check `logs/web_server.log` for Flask request/response logs and web-specific errors.
    *   **Task-Specific Logs:** For each task submitted via the web UI, a new directory is created under `logs/conversations/` named like `YYYY-MM-DD_HH-MM-SS_{uuid}`. Inside this directory:
        *   `conversation.log`: Contains the detailed step-by-step history of the LLM interactions (prompts, responses), execution flow control messages, and confirmation steps for that specific task.
        *   `output.log`: Contains the **raw, unfiltered** standard output (stdout), standard error (stderr), and interactive prompt/response details captured during the execution of the shell commands for that task.
10. **Logout:** Use the "Logout" link in the top right of the main page.

## Configuration (`.env` Variables)

*   `GEMINI_API_KEY`: **Required.** Your API key for Google Gemini.
*   `LLM_MODEL`: Model name to use (e.g., `models/gemini-1.5-flash-latest`). Verify current names in Google documentation.
*   `SUDO_PASSWORD`: Password for the `sudo` user if `sudo` commands are expected. **(HIGH Security Risk!)**. Omit if `sudo` is not needed or handled differently (e.g., passwordless sudoers).
*   `SUDO_USERNAME`: (Optional) Username for `sudo` commands if different from the user running the script (less common).
*   `MAX_LLM_CALLS_PER_MINUTE`: Client-side rate limit for LLM calls per minute.
*   `MAX_LLM_CALLS_PER_DAY`: Client-side rate limit for LLM calls per day.
*   `WEB_USERNAME`: **Required.** Username for logging into the web interface.
*   `WEB_PASSWORD`: **Required.** Password for logging into the web interface.
*   `SECRET_KEY`: **Required.** Strong, random secret key for Flask sessions (CSRF, login). **Keep this secret!** Generate using `python -c 'import secrets; print(secrets.token_hex(24))'`.
*   `REQUIRE_CONFIRMATION`: Set to `True` to enable the manual confirmation step in the terminal before execution. Defaults to `False`.
*   `FILTER_SUCCESS_LINES`: Number of output lines to keep when filtering successful command output *for the web UI*. Raw output is always logged. Defaults to `20`.

## Security Considerations

*   **Command Injection:** The core risk. The LLM is instructed to only provide commands, but malicious input or LLM errors could potentially generate harmful commands. There is no guarantee of safety. **The confirmation step (`REQUIRE_CONFIRMATION=True`) is strongly advised.**
*   **Authentication:** Session-based authentication provides basic protection. For access outside a trusted local network, **HTTPS is mandatory**, ideally via a reverse proxy (Nginx, Caddy, Apache) that handles TLS termination. The proxy can also add further authentication layers.
*   **Sudo Password Storage:** Storing the `sudo` password in `.env` is extremely insecure. **Strongly consider NOT using `sudo` commands with this tool.** If absolutely necessary:
    *   Configure `sudoers` for passwordless execution of *only* the specific, necessary commands (more secure but requires careful setup).
    *   *Do not store the password* and accept that commands requiring it will likely fail interactive prompts (unless `pexpect` handles the OS-level graphical prompt, which is unlikely).
*   **Network Exposure:** Do not expose the raw Flask server (port 5000 or other) directly to the internet. Always place it behind a firewall and preferably access it via a VPN or a properly configured reverse proxy.
*   **Interactive Prompt Automation:** Automatically answering prompts based on LLM suggestions is inherently risky. The LLM may misunderstand context or provide dangerous responses (e.g., confirming destructive actions like `rm -rf /`). The `conversation.log` and `output.log` files are critical for auditing these interactions.
*   **Rate Limiting:** The current rate limiting is client-side and basic. Implement server-side rate limiting (e.g., using Flask-Limiter) for better protection against abuse if exposed.
*   **Dependencies:** Keep all dependencies up-to-date to patch potential security vulnerabilities (`pip list --outdated`, `pip install -U <package>`).
*   **Logging:** Sensitive information (like parts of commands or output) might be logged. Secure the `logs/` directory appropriately (e.g., restrict file permissions).

## Potential Improvements / Future Work

*   Use a production-grade WSGI server (e.g., Gunicorn + Nginx, Waitress) instead of the Flask development server.
*   Implement background tasks (e.g., using Celery and Redis/RabbitMQ) for long-running command sequences to prevent web request timeouts and improve UI responsiveness.
*   Enhance error handling and provide more specific feedback to the user.
*   Add more sophisticated patterns for interactive prompt detection in `pexpect`.
*   Implement a more secure mechanism for handling `sudo` execution (e.g., integrating with `sudoers`, removing password dependency).
*   Improve the web UI/UX (e.g., better progress indication, streaming output, viewing logs).
*   Add unit and integration tests.
*   Implement more robust input validation and sanitization.
*   Add configuration for log rotation size/count.
*   Consider structured logging (e.g., JSON format) for easier machine parsing.

## License

[Optional: Add License Information Here, e.g., This project is licensed under the MIT License.]