import os
import logging
import socket
import getpass
from logging.handlers import RotatingFileHandler # Use rotating file handler

from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, flash
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
# This instance holds the LLM client, executor, etc.
try:
    llm_commander_app = LLMCommanderApp()
except Exception as app_init_err:
    # Log critical failure during core app initialization
    error_logger.critical(f"Failed to initialize LLMCommanderApp: {app_init_err}", exc_info=True)
    print(f"FATAL ERROR: Could not initialize core application logic: {app_init_err}")
    print(f"Check {os.path.join(LOGS_DIR, 'error.log')} for details. Exiting.")
    exit(1)

# --- Initialize Core Application Logic ---
# Create a single instance of the main application
# This instance holds the LLM client, executor, etc.
try:
    llm_commander_app = LLMCommanderApp()
except Exception as app_init_err:
    # Log critical failure during core app initialization
    # Check if error_logger was initialized before trying to use it
    if 'error_logger' in locals() or 'error_logger' in globals():
         error_logger.critical(f"Failed to initialize LLMCommanderApp: {app_init_err}", exc_info=True)
         log_path = os.path.join(LOGS_DIR, 'error.log')
    else:
         log_path = "error.log (logging not fully initialized)"
    print(f"FATAL ERROR: Could not initialize core application logic: {app_init_err}")
    print(f"Check {log_path} for details. Exiting.")
    exit(1)


# --- Flask App Setup ---
# By default, Flask looks for templates in a 'templates' folder
# in the same directory as the script, or specified via template_folder
app = Flask(__name__, template_folder='templates') # Explicitly state template folder
app.config['SECRET_KEY'] = settings.get('FLASK_SECRET_KEY', None) # Use .get for safety

if not app.config['SECRET_KEY']:
     print("FATAL ERROR: FLASK_SECRET_KEY is not set in the configuration.")
     # Optionally log this if logger is available
     exit(1)

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "warning"
login_manager.login_message = "Please log in to access this page."

# --- User Data & Class ---
WEB_USERNAME = settings.get('WEB_USERNAME')
WEB_PASSWORD = settings.get('WEB_PASSWORD') # Get the plain password first

if not WEB_USERNAME or not WEB_PASSWORD:
    print("FATAL ERROR: WEB_USERNAME or WEB_PASSWORD not set in configuration.")
    exit(1)

# Hash the password ONCE at startup
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
# Ensure logs directory exists (should be handled by log_setup, but check again)
if not os.path.exists(LOGS_DIR):
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
    except OSError as e:
        # Use print as logger might not be fully ready here depending on execution order
        print(f"Warning: Failed to create log directory '{LOGS_DIR}': {e}")

# Configure Flask's logger to write to a file
log_file = os.path.join(LOGS_DIR, 'web_server.log')
try:
    # Use rotating file handler
    file_handler = RotatingFileHandler(log_file, maxBytes=1024*1024*5, backupCount=3, encoding='utf-8') # 5MB file, 3 backups
    file_handler.setLevel(logging.INFO) # Set level for file handler
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s [%(pathname)s:%(lineno)d]')
    file_handler.setFormatter(formatter)

    # Configure Flask's logger
    # Remove default handler first to avoid duplicate console logs if Flask adds one
    if app.logger.hasHandlers():
        app.logger.handlers.clear() # Clear existing handlers if any

    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO) # Set overall level for the logger

    app.logger.info("Flask application file logger configured.")

except Exception as log_setup_err:
    print(f"ERROR setting up Flask file logging: {log_setup_err}. Logs might go to console only.")


# --- Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # Redirect to the main page (which now renders the default tab)
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        app.logger.info(f"Login attempt for user: {username}")

        # Use the pre-computed hash
        if username == WEB_USERNAME and check_password_hash(WEB_PASSWORD_HASH, password):
            user = User(username)
            login_user(user)
            app.logger.info(f"Login successful for user: {username}")
            next_page = request.args.get('next')
            # Basic Open Redirect protection
            if next_page and (not next_page.startswith('/') or next_page.startswith('//') or ':' in next_page):
                 app.logger.warning(f"Invalid 'next' parameter value detected during login: '{next_page}'. Redirecting to index.")
                 next_page = None # Prevent open redirect
            flash('Login successful!', 'success')
            # Redirect to the originally requested page or the main page
            return redirect(next_page or url_for('index'))
        else:
            app.logger.warning(f"Login failed for user: {username}")
            flash('Invalid username or password.', 'danger')

    # Render the specific login template
    return render_template('login.html', form=form, title="Login")

@app.route('/logout')
@login_required
def logout():
    user_id = current_user.id
    logout_user()
    app.logger.info(f"User '{user_id}' logged out.")
    flash('You have been logged out.', 'info')
    return redirect(url_for('login')) # Redirect back to login page

# --- Main Application Route ---
# This route now renders the DEFAULT tab content file,
# which extends base.html.
@app.route('/')
@login_required
def index():
    """Renders the main page, defaulting to the LLM Executor tab."""
    app.logger.info(f"Serving default view (LLM Executor Tab) to user: {current_user.id}")
    # Render the llm_executor_tab.html template.
    # This template should contain {% extends "base.html" %}
    # and define the content for the {% block tab_content %}.
    # It should also have the 'active' class on its main panel div.
    return render_template('llm_executor.html', username=current_user.id, title="LLM Task Executor")

# --- Optional: Route for the other tab (if direct linking is desired) ---
# You might not need this if you solely rely on the JS tab switching,
# but it's good practice for potentially linking directly to the dashboard.
@app.route('/dashboard')
@login_required
def dashboard():
    """Renders the Financial Dashboard tab."""
    app.logger.info(f"Serving Financial Dashboard Tab to user: {current_user.id}")
    # Render the finance_dashboard_tab.html template.
    # This template should also extend base.html.
    # It should NOT have the 'active' class on its main panel div by default.
    return render_template('finance_dashboard.html', username=current_user.id, title="Financial Dashboard")


# --- API Endpoint (No changes needed in logic) ---
@app.route('/execute', methods=['POST']) # Only POST for execution
@login_required
def handle_execute():
    user_id = current_user.id
    app.logger.info(f"Received '/execute' POST request from user: {user_id}")

    if not request.is_json:
        app.logger.error("Bad Request: Payload is not JSON.")
        return jsonify({"error": "Bad Request", "message": "Request must be JSON"}), 400

    data = request.get_json()
    if not data: # Check if JSON body is empty or null
        app.logger.error("Bad Request: Empty JSON payload received.")
        return jsonify({"error": "Bad Request", "message": "Request body cannot be empty"}), 400

    initial_prompt = data.get('prompt')
    max_retries_str = data.get('max_retries', '3') # Default to '3' as string

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

    app.logger.info(f"User '{user_id}' processing prompt (len={len(initial_prompt)}, retries={max_retries}): {initial_prompt[:100]}...")

    try:
        # --- Call the main application logic ---
        # This call now handles its own detailed logging to conversation files
        success, results = llm_commander_app.process_task(initial_prompt, max_retries)
        # --- ---

        app.logger.info(f"Processing finished for user '{user_id}'. Overall success: {success}")
        return jsonify({
            "overall_success": success,
            "results": results
        }), 200

    except Exception as e:
        # Catch unexpected errors from the core logic
        app.logger.error(f"Unhandled exception during prompt processing for user '{user_id}': {e}", exc_info=True)
        # Also log to the dedicated error log via the imported error_logger
        error_logger.error(f"Web server caught unhandled exception during prompt processing for user '{user_id}', prompt '{initial_prompt[:50]}...': {e}", exc_info=True)
        return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred processing your request."}), 500


# --- Basic Health Check ---
@app.route('/health', methods=['GET'])
def health_check():
    # Could add more checks here (e.g., LLM connectivity if needed)
    app.logger.debug("Health check endpoint accessed.")
    return jsonify({"status": "ok"}), 200

# --- Utility ---
def get_local_ip_hostname():
  """Gets a likely non-loopback local IPv4 address."""
  try:
    # Use a socket connection to a public IP (doesn't actually send data)
    # to determine the interface used for outgoing connections.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(0.1) # Timeout to avoid blocking
        try:
            # Doesn't have to be reachable
            s.connect(('8.8.8.8', 1))
            ip_address = s.getsockname()[0]
        except OSError:
            # Fallback if connect fails (e.g., no network)
            ip_address = '127.0.0.1'
        return ip_address
  except Exception:
    # Broad exception catch for any socket issues
    return "127.0.0.1" # Fallback


# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    # Determine host IP - listen on all interfaces by default
    host_ip = '0.0.0.0'
    local_ip_display = get_local_ip_hostname() # Get a likely accessible local IP for display


    print("--- Starting LLM Commander Web Server ---")
    print("--- SECURITY WARNING ---")
    print("This application executes commands suggested by an LLM, potentially with elevated privileges.")
    print("Ensure it runs ONLY in a SECURE, TRUSTED, ISOLATED environment.")
    print("NEVER expose this directly to the internet or untrusted networks without robust security measures (reverse proxy, firewall, authentication).")
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
        print(f"  - http://{local_ip_display}:{port}/login (from other devices on the same network)")
    print(f"Server listening on: {host_ip}:{port} (accessible from any network interface)")
    print("---")
    # Use a production WSGI server (like Gunicorn or Waitress) instead of app.run(debug=False) for deployment
    # Example with Waitress (install with pip install waitress):
    try:
        from waitress import serve
        print("Running with Waitress WSGI server.")
        serve(app, host=host_ip, port=port, _quiet=True) # Use _quiet to reduce Waitress startup messages if desired
    except ImportError:
        print("Waitress not found, falling back to Flask development server.")
        print("WARNING: Flask's development server is NOT suitable for production.")
        app.run(host=host_ip, port=port, debug=False) # debug=False is crucial for security