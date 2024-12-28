import logging
from logging import Formatter, FileHandler
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from functools import wraps
import re
import os
import hashlib
import time

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///firstapp.db'
app.secret_key = 'your_secret_key'  # Set a secret key for session handling

# Initialize the database
db = SQLAlchemy(app)

# Initialize Flask-Limiter
limiter = Limiter(
    get_remote_address,  # Use the client's IP address for rate limiting
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Optional global rate limits
)

# Initialize Flask-Talisman (for security headers)
talisman = Talisman(app)

# Logging Configuration
handler = FileHandler('app.log')
handler.setLevel(logging.INFO)  # Set the logging level
formatter = Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

# Define the User model
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.LargeBinary, nullable=False)  # Store hashed password as binary
    role = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"<User(username={self.username}, role={self.role})>"

USERNAME_PATTERN = r"^[a-zA-Z0-9_]+$"

# Constants for account lockout
MAX_ATTEMPTS = 3
LOCKOUT_DURATION = 30  # in seconds

# Store lockout information in session
def check_lockout():
    if 'lockout_time' in session:
        lockout_time = session['lockout_time']
        if time.time() < lockout_time + LOCKOUT_DURATION:
            return True  # Account is still locked
        else:
            session.pop('lockout_time', None)  # Remove lockout after duration
    return False  # Account is not locked

def extract_user_credentials(username):
    user = User.query.filter_by(username=username).first()
    if user:
        return user.username, user.password, user.role
    return None, None, None  # Return None if user not found

def password_verification(stored_password, provided_password):
    salt = stored_password[:16]
    stored_hash = stored_password[16:]
    provided_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode(), salt, 100000)
    return stored_hash == provided_hash

def authenticate_user(username, password):
    if check_lockout():
        flash('Account is locked. Please wait before trying again.', 'error')
        return redirect(url_for('login'))

    s_un, s_ps, s_role = extract_user_credentials(username)
    
    if s_un and password_verification(s_ps, password):
        session['username'] = s_un  # Store username in session
        session['role'] = s_role
        session['login_attempts'] = 0  # Reset attempts on successful login
        flash('Login successful!', 'success')
        app.logger.info(f'User {username} logged in successfully.')  # Log successful login
        return redirect(url_for('home'))
    else:
        # Increment login attempts
        attempts = session.get('login_attempts', 0) + 1
        session['login_attempts'] = attempts

        if attempts >= MAX_ATTEMPTS:
            session['lockout_time'] = time.time()  # Set lockout time
            flash('Too many failed login attempts. Your account is locked for 30 seconds.', 'error')
            app.logger.warning(f'User {username} locked out due to too many failed login attempts.')  # Log lockout
        else:
            flash('Invalid credentials. Please try again.', 'error')
            app.logger.warning(f'Failed login attempt for user {username}. Attempt {attempts} of {MAX_ATTEMPTS}.')  # Log failed attempt
    
    return redirect(url_for('login'))

def validate_username(un):
    return bool(re.match(USERNAME_PATTERN, un))

def validate_password(ps):
    return len(ps) >= 5

def hash_password(ps):
    salt = os.urandom(16)  # Use a longer salt for security
    hashed = hashlib.pbkdf2_hmac('sha256', ps.encode(), salt, 100000)
    return salt + hashed

def register_user(username, password, u_role):
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash('Username already exists. Please choose a different one.', 'error')
        return redirect(url_for('signup'))
    
    if not validate_username(username) or not validate_password(password):
        flash('Invalid Username or Password.', 'error')
        return redirect(url_for('signup'))

    hashed_password = hash_password(password)

    new_user = User(username=username, password=hashed_password, role=u_role)
    db.session.add(new_user)
    db.session.commit()
    flash('Registration successful! Please log in.', 'success')
    app.logger.info(f'New user {username} registered.')  # Log user registration
    return redirect(url_for('login'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session or session.get('role') != role:
                flash('Unauthorized access. You do not have permission to view this page.', 'error')
                return redirect(url_for('unauthorized'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Route to home page
@app.route('/')
def home():
    if 'username' in session:
        return render_template('index.html')
    else:
        flash('Please login first.', 'info')
        return redirect(url_for('login'))

# Route to login page with rate limiting
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit to 5 requests per minute
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        return authenticate_user(username, password)  # Redirect based on authentication
    return render_template('login.html')

# Route to signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_role = request.form['role']

        return register_user(username, password, user_role)  # Redirect based on registration
    return render_template('signup.html')

# Route to logout
@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    session.pop('login_attempts', None)  # Clear attempts on logout
    session.pop('lockout_time', None)  # Clear lockout time on logout
    flash('You have been logged out.', 'info')
    app.logger.info(f'User {session.get("username")} logged out.')  # Log logout event
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
@role_required('admin')
def admin():
    return "Admin only area"

@app.route('/unauthorized')
def unauthorized():
    return "Unauthorized access", 403

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure the database and tables are created
    app.run(debug=True)
