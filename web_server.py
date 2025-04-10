# llm-commander/web_server.py
import os
import logging
import socket
import getpass

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
from log_setup import error_logger, conversation_logger # Import loggers if needed directly

# --- Initialize Core Application Logic ---
# Create a single instance of the main application
# This instance holds the LLM client, executor, etc.
try:
    llm_commander_app = LLMCommanderApp()
except Exception as app_init_err:
    # Log critical failure during core app initialization
    error_logger.critical(f"Failed to initialize LLMCommanderApp: {app_init_err}", exc_info=True)
    print(f"FATAL ERROR: Could not initialize core application logic: {app_init_err}")
    print("Check error.log for details. Exiting.")
    exit(1)


# --- Flask App Setup ---
app = Flask(__name__) # Looks for templates in 'templates' folder
app.config['SECRET_KEY'] = settings['FLASK_SECRET_KEY']

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "warning"
login_manager.login_message = "Please log in to access this page."

# --- User Data & Class ---
WEB_USERNAME = settings['WEB_USERNAME']
# Hash the password ONCE at startup
try:
    WEB_PASSWORD_HASH = generate_password_hash(settings['WEB_PASSWORD'])
except Exception as hash_err:
    error_logger.critical(f"Failed to hash web password: {hash_err}", exc_info=True)
    print(f"FATAL ERROR: Could not hash web password: {hash_err}")
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
# Use Flask's logger, potentially add file handler if needed beyond error.log
# Basic logging is handled by log_setup.py, Flask logger can be used for web-specific events.
app.logger.setLevel(logging.INFO) # Adjust level as needed

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

        # Use the pre-computed hash
        if username == WEB_USERNAME and check_password_hash(WEB_PASSWORD_HASH, password):
            user = User(username)
            login_user(user)
            app.logger.info(f"Login successful for user: {username}")
            next_page = request.args.get('next')
            if next_page and (not next_page.startswith('/') or next_page.startswith('//') or ':' in next_page):
                 app.logger.warning(f"Invalid next_page value detected during login: {next_page}. Redirecting to index.")
                 next_page = None # Prevent open redirect
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

@app.route('/')
@login_required
def index():
    app.logger.info(f"Serving index page to user: {current_user.id}")
    return render_template('index.html', username=current_user.id, title="Commander")

# --- API Endpoint ---
@app.route('/execute', methods=['POST']) # Only POST for execution
@login_required
def handle_execute():
    user_id = current_user.id
    app.logger.info(f"Received '/execute' POST request from user: {user_id}")

    if not request.is_json:
        app.logger.error("Bad Request: Payload is not JSON.")
        return jsonify({"error": "Bad Request", "message": "Request must be JSON"}), 400

    data = request.get_json()
    initial_prompt = data.get('prompt')
    max_retries_str = data.get('max_retries', '3')

    try:
        max_retries = int(max_retries_str)
        if not (0 <= max_retries <= 10):
             raise ValueError("max_retries must be between 0 and 10")
    except (ValueError, TypeError):
        app.logger.error(f"Bad Request: Invalid 'max_retries' value: {max_retries_str}")
        return jsonify({"error": "Bad Request", "message": "'max_retries' must be an integer between 0 and 10"}), 400

    if not initial_prompt or not isinstance(initial_prompt, str) or initial_prompt.isspace():
        app.logger.error("Bad Request: 'prompt' is missing or invalid.")
        return jsonify({"error": "Bad Request", "message": "'prompt' must be a non-empty string"}), 400

    app.logger.info(f"User '{user_id}' processing prompt (len={len(initial_prompt)}, retries={max_retries}): {initial_prompt[:100]}...")

    try:
        # --- Call the main application logic ---
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
        # Also log to the dedicated error log via the already configured error_logger
        error_logger.error(f"Web server caught unhandled exception during prompt processing for user '{user_id}', prompt '{initial_prompt[:50]}...': {e}", exc_info=True)
        return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred processing your request."}), 500


# --- Basic Health Check ---
@app.route('/health', methods=['GET'])
def health_check():
    # Could add more checks here (e.g., LLM connectivity if needed)
    return jsonify({"status": "ok"}), 200

# --- Utility ---
def get_local_ip_hostname():
  """Gets the local IPv4 address associated with the hostname."""
  try:
    hostname = socket.gethostname()
    # Try getting all IPs and finding a non-loopback one if needed
    ip_address = socket.gethostbyname(hostname)
    # Basic check if it's loopback
    if ip_address.startswith("127."):
         # Try getting IPs associated with interfaces
         s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
         s.settimeout(0)
         try:
             # Doesn't have to be reachable
             s.connect(('10.254.254.254', 1))
             ip_address = s.getsockname()[0]
         except Exception:
             # Fallback if connect fails
             ip_address = '127.0.0.1'
         finally:
             s.close()
    return ip_address
  except socket.gaierror:
    return "127.0.0.1" # Fallback

# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    # Determine host IP - listen on all interfaces available if not root/admin
    host_ip = '0.0.0.0' if getpass.getuser() != 'administrator' and getpass.getuser() != 'root' else get_local_ip_hostname()
    # Use a more specific IP if needed, or 0.0.0.0 to listen on all IPv4 interfaces

    print("--- Starting LLM Commander Web Server (OOP Structure) ---")
    print("--- SECURITY WARNING ---")
    print("This application executes commands suggested by an LLM, potentially with sudo.")
    print("Ensure it runs ONLY in a SECURE, TRUSTED environment.")
    print("NEVER expose this directly to the internet without robust security.")
    print("---")
    print(f"Flask App Secret Key is set: {'Yes' if settings['FLASK_SECRET_KEY'] else 'NO - CRITICAL SECURITY ISSUE!'}")
    print(f"Web UI Username: {WEB_USERNAME}")
    print(f"Access the login page via http://<your-ip>:{port}/login or http://localhost:{port}/login")
    print(f"Server listening on: {host_ip}:{port}")
    print("---")
    # Use a production WSGI server (like Gunicorn or Waitress) instead of app.run(debug=False) for deployment
    # Example with Waitress (install with pip install waitress):
    # from waitress import serve
    # serve(app, host=host_ip, port=port)
    app.run(host=host_ip, port=port, debug=False) # debug=False is crucial for security