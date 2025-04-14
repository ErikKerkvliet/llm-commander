# llm-commander/app_models.py

from flask_login import UserMixin

# Define the User class for Flask-Login
class User(UserMixin):
    """Represents a user for login purposes."""
    def __init__(self, id):
        self.id = id