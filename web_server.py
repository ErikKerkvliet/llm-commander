# llm-commander-master/web_server.py
# Modifications:
# - Update ACTIVE_TASKS structure comment
# - Add initial_prompt and current_step to task state on creation
# - Add /dashboard_status endpoint to poll for active task info

import os
import logging
import socket
import re
import getpass
import uuid # Import uuid
import threading # Import threading
import time # Import time
from datetime import datetime, date # Added date
from logging.handlers import RotatingFileHandler # Use rotating file handler
from concurrent.futures import ThreadPoolExecutor # Alternative for managing threads

from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, flash, session, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
# Added json for the graph data
import json


# Import configuration and the main app class
from config import settings
from llm_commander import LLMCommanderApp # Import the main application class
from log_setup import error_logger, LOGS_DIR, LOGS_TASKS # Import error logger and logs dir
from log_data_extractor import extract_log_data

TASK_ID_PATTERN = re.compile(r"^\d{8}_\d{6}_[a-f0-9\-]+$", re.IGNORECASE)

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
#   "initial_prompt": str, # The very first prompt from the user
#   "current_step": str, # Description of what the task is currently doing (e.g., "Requesting commands", "Executing...", "Waiting for input...")
#   "prompt_needed": bool,
#   "prompt_text": str | None, # Text for modal if prompt_needed is True
#   "input_type": "confirmation" | "text" | "password" | None,
#   "user_response": str | None, # Stores the input from the user briefly
#   "result": dict | None, # Final result object (contains 'overall_success' and 'results' list)
#   "wait_event": threading.Event(), # Used to pause/resume the background thread
#   "log_dir": str | None,
#   "start_time": datetime,
#   "pexpect_child": pexpect_child_object | None, # Temporary reference, cleaned up
#   "thread": threading.Thread object | None, # Reference to the background thread
#   "user_id": str # User who initiated the task
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
    # Reduced file size for potentially more frequent dashboard polling logs
    file_handler = RotatingFileHandler(log_file, maxBytes=1024*1024*2, backupCount=3, encoding='utf-8')
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


# --- Dashboard Route ---
@app.route('/dashboard')
@login_required
def dashboard():
    # Data is now primarily loaded via the /dashboard_status polling endpoint
    # We still pass static elements like graph data here if needed

    # --- NEW: Generate Sample Graph Data ---
    graph_labels = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug"]
    graph_data = [150, 220, 180, 250, 300, 280, 310, 330]

    app.logger.info(f"Serving Dashboard Tab structure to user: {current_user.id}")
    return render_template(
        'dashboard.html',
        username=current_user.id,
        title="Dashboard",
        active_tab="dashboard",
        # No need to pass main_task/current_task here anymore
        today_date=date.today().strftime("%Y-%m-%d"), # Add today's date for the earnings card
        # Pass graph data to the template (convert to JSON for JS)
        graph_labels=json.dumps(graph_labels),
        graph_data=json.dumps(graph_data)
    )

# --- NEW: Route for Dashboard Polling ---
@app.route('/dashboard_status')
@login_required
def get_dashboard_status():
    """API endpoint for the dashboard to poll for the current user's active task status."""
    user_id = current_user.id
    active_task_info = None

    with TASK_LOCK:
        # Find the most recently started, *non-final* task for this user
        # Assuming one active task per user for this simple view
        user_tasks = [
            (task_id, info) for task_id, info in ACTIVE_TASKS.items()
            if info.get("user_id") == user_id and info.get("status") not in ["complete", "failed"]
        ]

        if user_tasks:
            # Sort by start time descending to get the latest one
            user_tasks.sort(key=lambda item: item[1].get("start_time", datetime.min), reverse=True)
            # Get the info of the latest active task
            active_task_info = user_tasks[0][1] # item[1] is the info dict

    if active_task_info:
        app.logger.debug(f"Dashboard poll: Found active task for user '{user_id}'. Status: {active_task_info.get('status')}")
        response_data = {
            "active": True,
            "main_task": active_task_info.get("initial_prompt", "N/A"),
            "current_step": active_task_info.get("current_step", "N/A"),
            "status": active_task_info.get("status", "unknown").replace("_", " ").capitalize()
        }
    else:
        app.logger.debug(f"Dashboard poll: No active task found for user '{user_id}'.")
        response_data = {
            "active": False,
            "main_task": "No active task.",
            "current_step": "Idle.",
            "status": "idle"
        }

    return jsonify(response_data)


# --- Route for Earnings Modal Content ---
@app.route('/get_earnings_info')
@login_required
def get_earnings_info():
    """Provides the HTML content for the earnings explanation modal."""
    user_id = current_user.id
    app.logger.info(f"User '{user_id}' requested earnings info modal content.")

    # Static content for this example. Could be dynamic in a real app.
    explanation_html = """
    <h4>Accessing Your Funds</h4>
    <p>Thank you for your contributions! Currently, fund access is processed manually by our finance team to ensure security and compliance. Please follow these steps:</p>
    <ol>
        <li>Navigate to the internal 'Finance Portal' section (link available on the main intranet page).</li>
        <li>Submit a 'Withdrawal Request' form.</li>
        <li>Specify the exact amount you wish to withdraw (minimum $50).</li>
        <li>Ensure your designated payout bank account details are up-to-date in your profile before submitting.</li>
        <li>You will receive a confirmation email once the request is submitted.</li>
    </ol>
    <p><strong>Processing Time:</strong> Withdrawals are typically processed within <strong>3-5 business days</strong> after submission and approval.</p>
    <p class="text-muted"><small>Please note that transaction fees may apply depending on your bank and location. Contact the finance team via the portal for any specific queries.</small></p>
    """
    # Return as JSON for easier handling in frontend JS
    return jsonify({"html_content": explanation_html})


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
            "initial_prompt": initial_prompt, # <-- Store initial prompt
            "current_step": "Task submitted...", # <-- Initial step description
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
        # Pass the ACTIVE_TASKS dictionary
        thread = threading.Thread(
            target=llm_commander_app.process_task_background,
            args=(initial_prompt, max_retries, task_id, ACTIVE_TASKS),
            daemon=True # Daemon threads exit when the main program exits
        )
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
    """Provides the current status and results (if available) of a task for the Executor tab."""
    user_id = current_user.id
    app.logger.debug(f"Executor status request from '{user_id}' for task: {task_id}")

    with TASK_LOCK:
        task_info = ACTIVE_TASKS.get(task_id)

    if not task_info:
        app.logger.warning(f"Executor status requested for unknown task ID: {task_id}")
        return jsonify({"error": "Not Found", "message": "Task ID not found."}), 404

    # --- Security Check: Ensure user owns the task ---
    if task_info.get("user_id") != user_id:
        app.logger.warning(f"User '{user_id}' attempted to access task {task_id} owned by '{task_info.get('user_id')}'.")
        return jsonify({"error": "Forbidden", "message": "You do not have permission to view this task."}), 403

    # Selectively return fields relevant to the frontend (Executor Tab)
    status_response = {
        "task_id": task_id,
        "status": task_info["status"].replace("_", " ").capitalize(),
        "prompt_needed": task_info.get("prompt_needed", False),
        "prompt_text": task_info.get("prompt_text") if task_info.get("prompt_needed") else None,
        "input_type": task_info.get("input_type") if task_info.get("prompt_needed") else None,
        "result": task_info.get("result") # Send the final result if status is complete/failed
    }

    app.logger.debug(f"Task {task_id} executor status for user '{user_id}': {status_response['status']}")
    return jsonify(status_response), 200

@app.route('/task_history_data')
@login_required
def get_task_history_data():
    """API endpoint to fetch task history data for the user."""
    user_id = current_user.id
    app.logger.info(f"User '{user_id}' requested task history data.")

    history_data = []
    # --- Robust history loading ---
    if os.path.exists(LOGS_TASKS):
        try:
            items = sorted(os.listdir(LOGS_TASKS), reverse=True)

            for item_name in items:
                item_path = os.path.join(LOGS_TASKS, item_name)
                if os.path.isdir(item_path):
                    try:
                        # Validate folder name format before processing
                        if not TASK_ID_PATTERN.match(item_name):
                             app.logger.warning(f"Skipping non-task folder: {item_name}")
                             continue

                        log_data = extract_log_data(item_name)
                        if log_data:
                             # TODO: Future - Filter history by user_id if logs contained user info
                             # For now, showing all history accessible to the logged-in user.
                             if log_data.get('timestamp'):
                                log_data['timestamp_iso'] = log_data['timestamp'].isoformat()
                             history_data.append(log_data)
                        else:
                            app.logger.warning(f"Could not extract data for task folder: {item_name}")
                    except Exception as e:
                        app.logger.error(f"Error processing task log folder '{item_name}': {e}", exc_info=True)
                        history_data.append({
                            'id': item_name,
                            'status': 'Error Loading Log',
                            'prompt': 'Error processing log',
                            'commands': [],
                            'timestamp': None,
                            'timestamp_iso': None,
                            'error': True # Flag this entry
                        })
        except OSError as e:
            app.logger.error(f"Error listing task log directory '{LOGS_TASKS}': {e}", exc_info=True)
            return jsonify({"error": f"Error reading task history directory: {e}"}), 500
    else:
        app.logger.info(f"Task logs directory '{LOGS_TASKS}' not found. Returning empty history.")
        return jsonify([]) # Return empty list if directory doesn't exist

    # Re-sort by ISO timestamp just to be sure
    history_data.sort(key=lambda x: x.get('timestamp_iso', '0000-00-00T00:00:00'), reverse=True)

    app.logger.info(f"Returning {len(history_data)} task history items for user '{user_id}'.")
    return jsonify(history_data)

@app.route('/task_output/<task_id>', methods=['GET'])
@login_required
def get_task_output(task_id):
    """Serves the content of a task's output.log file."""
    user_id = current_user.id
    app.logger.info(f"User '{user_id}' requested output log for task: {task_id}")

    # --- Security Validation ---
    if not task_id or not TASK_ID_PATTERN.match(task_id):
        app.logger.warning(f"Invalid task ID format requested by user '{user_id}': {task_id}")
        abort(400, description="Invalid Task ID format.")

    # --- Construct Path ---
    try:
        log_dir = os.path.join(LOGS_TASKS, task_id)
        output_log_file = os.path.join(log_dir, 'output.log')
        # Basic check to prevent trivial path traversal
        if not os.path.abspath(output_log_file).startswith(os.path.abspath(LOGS_TASKS)):
             app.logger.error(f"Potential Path Traversal Attempt? User '{user_id}', Task ID '{task_id}'")
             abort(404, description="Task log not found.") # Be vague on purpose

    except Exception as path_e:
        app.logger.error(f"Error constructing path for task '{task_id}': {path_e}", exc_info=True)
        abort(500, description="Internal error creating log path.")

    # --- Check File Existence and Read ---
    # TODO: Future - Check if user_id has permission to view this specific task log
    # This might involve storing user_id *in* the log or associating task_id with user_id at creation time
    # For now, any authenticated user can view any valid task log

    if not os.path.isfile(output_log_file):
        app.logger.warning(f"Output log file not found or not a file for task '{task_id}'. Path: {output_log_file}")
        abort(404, description="Output log file not found.")

    try:
        with open(output_log_file, 'r', encoding='utf-8') as f:
            log_content = f.read()
        app.logger.info(f"Successfully read output log for task '{task_id}' (length: {len(log_content)})")
        return log_content, 200, {'Content-Type': 'text/plain; charset=utf-8'}

    except IOError as e:
        app.logger.error(f"IOError reading output log file for task '{task_id}': {e}", exc_info=True)
        abort(500, description=f"Error reading log file: {e}")
    except Exception as e:
        app.logger.error(f"Unexpected error reading output log file for task '{task_id}': {e}", exc_info=True)
        abort(500, description="An unexpected error occurred reading the log.")


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
        task_info["current_step"] = "Received user input, resuming task..." # Update step
        wait_event = task_info.get("wait_event")

        if wait_event:
            app.logger.info(f"Received input for task {task_id}: '{str(user_input)[:20]}...'. Signaling thread.")
            wait_event.set() # Resume the background thread
            return jsonify({"status": "input_received", "message": "Input received, task resuming."}), 200
        else:
            # Should not happen if state is managed correctly
            app.logger.error(f"Task {task_id} was awaiting input but had no wait_event!")
            task_info["status"] = "failed" # Mark as failed
            task_info["current_step"] = "Internal state error (missing wait event)." # Update step
            task_info["result"] = {"error": "Internal state error (missing wait event)."}
            return jsonify({"error": "Internal Server Error", "message": "Internal state error processing input."}), 500


# --- Basic Health Check ---
@app.route('/health', methods=['GET'])
def health_check():
    app.logger.debug("Health check endpoint accessed.")
    return jsonify({"status": "ok"}), 200

def default_serializer(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        return obj.isoformat() # Return ISO format string
    raise TypeError(f"Type {type(obj)} not serializable")

# --- Utility ---
def get_local_ip_hostname():
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(0.1)
        try:
            # Doesn't actually send packets
            s.connect(('10.255.255.255', 1))
            ip_address = s.getsockname()[0]
        except OSError:
            ip_address = '127.0.0.1' # Fallback if no network route
        return ip_address
  except Exception:
    return "127.0.0.1" # Broader fallback

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
        # Explicitly set threads if concerned about shared state with >1 thread processing requests
        # If state management becomes complex, stick to 1 thread or use proper inter-thread communication.
        # For simple dictionary access with locks, multiple threads *might* be okay, but increases complexity.
        # Let's keep the default (4 threads) for now but be mindful.
        serve(app, host=host_ip, port=port) # Using default Waitress threads
    except ImportError:
        print("Waitress not found, falling back to Flask development server.")
        print("WARNING: Flask's development server is NOT suitable for production.")
        # Run Flask dev server (single-threaded by default unless specified)
        # Set threaded=True to handle multiple requests concurrently (like background polling)
        app.run(host=host_ip, port=port, debug=False, threaded=True)