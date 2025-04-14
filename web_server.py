import os
import logging
import socket
import getpass
import uuid # Import uuid
import threading # Import threading
import time # Import time
from datetime import datetime
from logging.handlers import RotatingFileHandler # Use rotating file handler
from concurrent.futures import ThreadPoolExecutor # Alternative for managing threads

from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, flash, session
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash

# Import configuration and the main app class
from config import settings
from llm_commander import LLMCommanderApp # Import the main application class
from log_setup import error_logger, LOGS_DIR # Import error logger and logs dir

# --- Initialize Core Application Logic ---
# Create a single instance of the main application
try:
    llm_commander_app = LLMCommanderApp()
except Exception as app_init_err:
    if 'error_logger' in locals() or 'error_logger' in globals():
         error_logger.critical(f"Failed to initialize LLMCommanderApp: {app_init_err}", exc_info=True)
         log_path = os.path.join(LOGS_DIR, 'error.log')
    else:
         log_path = "error.log (logging not fully initialized)"
    print(f"FATAL ERROR: Could not initialize core application logic: {app_init_err}")
    print(f"Check {log_path} for details. Exiting.")
    exit(1)


# --- Flask App Setup ---
app = Flask(__name__, template_folder='templates', static_folder='static') # Add static folder
app.config['SECRET_KEY'] = settings.get('FLASK_SECRET_KEY', None)

if not app.config['SECRET_KEY']:
     print("FATAL ERROR: FLASK_SECRET_KEY is not set in the configuration.")
     exit(1)

# --- Task State Management (In-Memory - WARNING: Not suitable for multi-worker setups) ---
# This dictionary will store the state of active tasks.
# Keys are task_ids (UUIDs).
# Values are dictionaries like:
# {
#   "status": "started" | "running_attempt_X" | "awaiting_confirmation" | "awaiting_input" | "resuming" | "complete" | "failed",
#   "prompt_needed": bool,
#   "prompt_text": str | None,
#   "input_type": "confirmation" | "text" | "password" | None,
#   "user_response": str | None, # Stores the input from the user briefly
#   "result": dict | None, # Final result object
#   "wait_event": threading.Event(), # Used to pause/resume the background thread
#   "log_dir": str | None,
#   "start_time": datetime,
#   "pexpect_child": pexpect_child_object | None # Temporary reference, cleaned up
#   "thread": threading.Thread object | None # Reference to the background thread
# }
ACTIVE_TASKS = {}
TASK_LOCK = threading.Lock() # To protect access to ACTIVE_TASKS

# --- Thread Pool for Background Tasks ---
# Using a thread pool can be slightly more efficient than creating new threads each time.
executor = ThreadPoolExecutor(max_workers=10) # Adjust max_workers as needed

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "warning"
login_manager.login_message = "Please log in to access this page."

# --- User Data & Class ---
WEB_USERNAME = settings.get('WEB_USERNAME')
WEB_PASSWORD = settings.get('WEB_PASSWORD')

if not WEB_USERNAME or not WEB_PASSWORD:
    print("FATAL ERROR: WEB_USERNAME or WEB_PASSWORD not set in configuration.")
    exit(1)

try:
    WEB_PASSWORD_HASH = generate_password_hash(WEB_PASSWORD)
except Exception as hash_err:
    error_logger.critical(f"Failed to hash web password: {hash_err}", exc_info=True)
    print(f"FATAL ERROR: Could not hash web password: {hash_err}")
    print(f"Check {os.path.join(LOGS_DIR, 'error.log')} for details. Exiting.")
    exit(1)

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    if user_id == WEB_USERNAME:
        return User(user_id)
    return None

# --- Login Form (Flask-WTF) ---
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# --- Logging Setup ---
if not os.path.exists(LOGS_DIR):
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
    except OSError as e:
        print(f"Warning: Failed to create log directory '{LOGS_DIR}': {e}")

log_file = os.path.join(LOGS_DIR, 'web_server.log')
try:
    file_handler = RotatingFileHandler(log_file, maxBytes=1024*1024*5, backupCount=3, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s [%(pathname)s:%(lineno)d]')
    file_handler.setFormatter(formatter)
    if app.logger.hasHandlers():
        app.logger.handlers.clear()
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info("Flask application file logger configured.")
except Exception as log_setup_err:
    print(f"ERROR setting up Flask file logging: {log_setup_err}. Logs might go to console only.")


# --- Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        app.logger.info(f"Login attempt for user: {username}")
        if username == WEB_USERNAME and check_password_hash(WEB_PASSWORD_HASH, password):
            user = User(username)
            login_user(user)
            app.logger.info(f"Login successful for user: {username}")
            next_page = request.args.get('next')
            if next_page and (not next_page.startswith('/') or next_page.startswith('//') or ':' in next_page):
                 app.logger.warning(f"Invalid 'next' parameter detected during login: '{next_page}'. Redirecting to index.")
                 next_page = None
            flash('Login successful!', 'success')
            return redirect(next_page or url_for('index'))
        else:
            app.logger.warning(f"Login failed for user: {username}")
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form, title="Login")

@app.route('/logout')
@login_required
def logout():
    user_id = current_user.id
    logout_user()
    app.logger.info(f"User '{user_id}' logged out.")
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Main Application Route ---
@app.route('/')
@login_required
def index():
    app.logger.info(f"Serving default view (LLM Executor Tab) to user: {current_user.id}")
    # Make sure to pass the username for potential display in base.html
    return render_template('llm_executor.html', username=current_user.id, title="LLM Task Executor", active_tab="llm")


# --- Optional: Route for the other tab ---
@app.route('/dashboard')
@login_required
def dashboard():
    # Placeholder logic...
    current_main_task = "Example: Deploy web application"
    current_step = "Example: Waiting for user confirmation"
    history_data = [
        {'id': 'conv_abc_123', 'prompt': 'Install nginx', 'status': 'Success', 'timestamp': '2023-10-27 10:00:00'},
        # ... more tasks
    ]
    app.logger.info(f"Serving Dashboard Tab to user: {current_user.id}")
    return render_template(
        'dashboard.html',
        username=current_user.id,
        title="Dashboard",
        active_tab="dashboard",
        main_task=current_main_task,
        current_task=current_step,
        task_history=history_data
    )

# --- API Endpoints for Asynchronous Task Handling ---

@app.route('/execute', methods=['POST'])
@login_required
def handle_execute():
    """Starts a new task execution in the background."""
    user_id = current_user.id
    app.logger.info(f"Received '/execute' POST request from user: {user_id}")

    if not request.is_json:
        app.logger.error("Bad Request: Payload is not JSON.")
        return jsonify({"error": "Bad Request", "message": "Request must be JSON"}), 400

    data = request.get_json()
    if not data:
        app.logger.error("Bad Request: Empty JSON payload received.")
        return jsonify({"error": "Bad Request", "message": "Request body cannot be empty"}), 400

    initial_prompt = data.get('prompt')
    max_retries_str = data.get('max_retries', '3')

    try:
        max_retries = int(max_retries_str)
        if not (0 <= max_retries <= 10):
             raise ValueError("max_retries must be between 0 and 10")
    except (ValueError, TypeError):
        app.logger.error(f"Bad Request: Invalid 'max_retries' value: {max_retries_str}")
        return jsonify({"error": "Bad Request", "message": f"'max_retries' must be an integer between 0 and 10. Received: {max_retries_str}"}), 400

    if not initial_prompt or not isinstance(initial_prompt, str) or initial_prompt.isspace():
        app.logger.error("Bad Request: 'prompt' is missing or invalid.")
        return jsonify({"error": "Bad Request", "message": "'prompt' must be a non-empty string"}), 400

    task_id = str(uuid.uuid4())
    wait_event = threading.Event()

    # Store initial task state
    with TASK_LOCK:
        ACTIVE_TASKS[task_id] = {
            "status": "started",
            "prompt_needed": False,
            "prompt_text": None,
            "input_type": None,
            "user_response": None,
            "result": None,
            "wait_event": wait_event,
            "log_dir": None,
            "start_time": datetime.now(),
            "pexpect_child": None,
            "thread": None, # Will be set below
            "user_id": user_id # Associate task with user
        }

    app.logger.info(f"User '{user_id}' starting task {task_id} for prompt (len={len(initial_prompt)}, retries={max_retries}): {initial_prompt[:100]}...")

    try:
        # --- Start the background task ---
        # Pass the ACTIVE_TASKS dictionary (or a wrapper/manager if more complex state needed)
        thread = threading.Thread(
            target=llm_commander_app.process_task_background,
            args=(initial_prompt, max_retries, task_id, ACTIVE_TASKS),
            daemon=True # Daemon threads exit when the main program exits
        )
        # Alternatively, using the ThreadPoolExecutor:
        # future = executor.submit(llm_commander_app.process_task_background, initial_prompt, max_retries, task_id, ACTIVE_TASKS)
        # Store the thread reference
        with TASK_LOCK:
             ACTIVE_TASKS[task_id]["thread"] = thread
        thread.start()
        app.logger.info(f"Task {task_id} started in background thread {thread.name}.")

        # Return immediately with the task ID
        return jsonify({"task_id": task_id, "status": "started"}), 202 # 202 Accepted

    except Exception as e:
        # Catch errors during thread creation/start
        app.logger.error(f"Failed to start background task {task_id} for user '{user_id}': {e}", exc_info=True)
        error_logger.error(f"Web server failed to start task {task_id} for user '{user_id}': {e}", exc_info=True)
        # Clean up initial state if thread failed to start
        with TASK_LOCK:
            if task_id in ACTIVE_TASKS:
                del ACTIVE_TASKS[task_id]
        return jsonify({"error": "Internal Server Error", "message": "Failed to start task processing."}), 500


@app.route('/task_status/<task_id>', methods=['GET'])
@login_required
def get_task_status(task_id):
    """Provides the current status and results (if available) of a task."""
    user_id = current_user.id
    app.logger.debug(f"User '{user_id}' requesting status for task: {task_id}")

    with TASK_LOCK:
        task_info = ACTIVE_TASKS.get(task_id)

    if not task_info:
        app.logger.warning(f"Status requested for unknown task ID: {task_id}")
        return jsonify({"error": "Not Found", "message": "Task ID not found."}), 404

    # --- Security Check: Ensure user owns the task ---
    # Simple check, could be enhanced based on roles/permissions if needed
    if task_info.get("user_id") != user_id:
        app.logger.warning(f"User '{user_id}' attempted to access task {task_id} owned by '{task_info.get('user_id')}'.")
        return jsonify({"error": "Forbidden", "message": "You do not have permission to view this task."}), 403


    # Selectively return fields relevant to the frontend
    status_response = {
        "task_id": task_id,
        "status": task_info["status"],
        "prompt_needed": task_info.get("prompt_needed", False),
        "prompt_text": task_info.get("prompt_text") if task_info.get("prompt_needed") else None,
        "input_type": task_info.get("input_type") if task_info.get("prompt_needed") else None,
        "result": task_info.get("result") # Send the final result if status is complete/failed
    }

    # Optional: Clean up completed/failed tasks after a delay?
    # if task_info["status"] in ["complete", "failed"]:
    #     # Consider removing from ACTIVE_TASKS after a grace period
    #     pass

    app.logger.debug(f"Task {task_id} status for user '{user_id}': {status_response['status']}")
    return jsonify(status_response), 200


@app.route('/provide_input/<task_id>', methods=['POST'])
@login_required
def provide_task_input(task_id):
    """Receives user input for a task awaiting input."""
    user_id = current_user.id
    app.logger.info(f"Received '/provide_input' POST for task {task_id} from user '{user_id}'")

    if not request.is_json:
        app.logger.error(f"Bad Request (provide_input {task_id}): Payload is not JSON.")
        return jsonify({"error": "Bad Request", "message": "Request must be JSON"}), 400

    data = request.get_json()
    user_input = data.get('user_input')

    if user_input is None: # Allow empty string, but not missing key
        app.logger.error(f"Bad Request (provide_input {task_id}): 'user_input' missing.")
        return jsonify({"error": "Bad Request", "message": "'user_input' key is required."}), 400

    with TASK_LOCK:
        task_info = ACTIVE_TASKS.get(task_id)

        if not task_info:
            app.logger.warning(f"Input provided for unknown task ID: {task_id}")
            return jsonify({"error": "Not Found", "message": "Task ID not found or already completed."}), 404

        # --- Security Check: Ensure user owns the task ---
        if task_info.get("user_id") != user_id:
             app.logger.warning(f"User '{user_id}' attempted to provide input for task {task_id} owned by '{task_info.get('user_id')}'.")
             return jsonify({"error": "Forbidden", "message": "You do not have permission to modify this task."}), 403

        # Check if the task is actually waiting for input
        if not task_info.get("prompt_needed") or task_info["status"] not in ["awaiting_input", "awaiting_confirmation"]:
            app.logger.warning(f"Input provided for task {task_id}, but it was not awaiting input (status: {task_info['status']}).")
            return jsonify({"error": "Conflict", "message": "Task is not currently awaiting input."}), 409

        # Store the response and signal the waiting thread
        task_info["user_response"] = user_input
        task_info["status"] = "resuming" # Update status
        wait_event = task_info.get("wait_event")

        if wait_event:
            app.logger.info(f"Received input for task {task_id}: '{user_input[:20]}...'. Signaling thread.")
            wait_event.set() # Resume the background thread
            return jsonify({"status": "input_received", "message": "Input received, task resuming."}), 200
        else:
            # Should not happen if state is managed correctly
            app.logger.error(f"Task {task_id} was awaiting input but had no wait_event!")
            task_info["status"] = "failed" # Mark as failed
            task_info["result"] = {"error": "Internal state error (missing wait event)."}
            return jsonify({"error": "Internal Server Error", "message": "Internal state error processing input."}), 500


# --- Basic Health Check ---
@app.route('/health', methods=['GET'])
def health_check():
    app.logger.debug("Health check endpoint accessed.")
    return jsonify({"status": "ok"}), 200

# --- Utility ---
def get_local_ip_hostname():
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(0.1)
        try:
            s.connect(('8.8.8.8', 1))
            ip_address = s.getsockname()[0]
        except OSError:
            ip_address = '127.0.0.1'
        return ip_address
  except Exception:
    return "127.0.0.1"

# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    host_ip = '0.0.0.0'
    local_ip_display = get_local_ip_hostname()

    print("--- Starting LLM Commander Web Server ---")
    print("--- SECURITY WARNING ---")
    print("This application executes commands suggested by an LLM.")
    print("Ensure it runs ONLY in a SECURE, TRUSTED, ISOLATED environment.")
    print("NEVER expose this directly to the internet.")
    print("--- ASYNC TASKING NOTE ---")
    print("Using in-memory state for background tasks.")
    print("DO NOT run with multiple workers (e.g., gunicorn -w > 1).")
    print("---")
    print(f"Logging to directory: {LOGS_DIR}")
    if not app.config['SECRET_KEY']:
         print("CRITICAL SECURITY ISSUE: Flask Secret Key is NOT set!")
    else:
         print("Flask App Secret Key is set: Yes")
    print(f"Web UI Username: {WEB_USERNAME}")
    print(f"Access the login page via:")
    print(f"  - http://localhost:{port}/login")
    if local_ip_display != '127.0.0.1':
        print(f"  - http://{local_ip_display}:{port}/login")
    print(f"Server listening on: {host_ip}:{port}")
    print("---")

    try:
        from waitress import serve
        print("Running with Waitress WSGI server.")
        # Explicitly set threads=1 if using the in-memory state management
        # For development/testing, Waitress default might be okay, but be aware.
        serve(app, host=host_ip, port=port, threads=4) # Default threads is 4, BE CAREFUL with state
    except ImportError:
        print("Waitress not found, falling back to Flask development server.")
        print("WARNING: Flask's development server is NOT suitable for production.")
        # Run Flask dev server (single-threaded by default unless specified)
        app.run(host=host_ip, port=port, debug=False, threaded=True) # threaded=True is needed for background tasks