from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv
from flask_mail import Mail, Message
import random
import secrets
from werkzeug.utils import secure_filename
from PIL import Image, ImageDraw
import shutil
import threading

# Load environment variables
load_dotenv()

# Define IST timezone offset
IST = timezone(timedelta(hours=5, minutes=30))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465  # SSL port
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'karthikeyakumara3@gmail.com'
app.config['MAIL_PASSWORD'] = 'kntxivrlsuqhqhew'  # Your Gmail App Password
app.config['MAIL_DEFAULT_SENDER'] = 'karthikeyakumara3@gmail.com'

# Debug email configuration
if app.debug:
    print("\nEmail Configuration (Using SSL):")
    print(f"MAIL_SERVER: {app.config['MAIL_SERVER']}")
    print(f"MAIL_PORT: {app.config['MAIL_PORT']}")
    print(f"MAIL_USE_TLS: {app.config['MAIL_USE_TLS']}")
    print(f"MAIL_USE_SSL: {app.config['MAIL_USE_SSL']}")
    print(f"MAIL_USERNAME: {app.config['MAIL_USERNAME']}")
    print(f"MAIL_PASSWORD: {'*' * len(app.config['MAIL_PASSWORD']) if app.config['MAIL_PASSWORD'] else 'Not set'}")
    print(f"MAIL_DEFAULT_SENDER: {app.config['MAIL_DEFAULT_SENDER']}\n")

mail = Mail(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    is_email_verified = db.Column(db.Boolean, default=False, nullable=True)
    profile_picture = db.Column(db.String(255), default='default.jpg')
    votes = db.relationship('Vote', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def update_activity(self):
        self.last_activity = datetime.utcnow()
        db.session.commit()
        
    def has_voted_in_election(self, election_id):
        return Vote.query.filter_by(user_id=self.id, election_id=election_id).first() is not None

class Election(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    candidates = db.relationship('Candidate', backref='election', lazy=True)
    votes = db.relationship('Vote', backref='election', lazy=True)

    def update_active_status(self):
        # Get current IST time, but make it naive for comparison
        now_naive_ist = datetime.now(IST).replace(tzinfo=None)
        print(f"  [update_active_status] Checking Election ID {self.id} ('{self.title}')")
        print(f"    - Current Naive IST Time (now): {now_naive_ist}")

        # Stored dates are naive (assumed IST)
        start_date_naive_ist = self.start_date
        end_date_naive_ist = self.end_date
        print(f"    - Stored Start Date (Naive IST): {start_date_naive_ist}")
        print(f"    - Stored End Date (Naive IST): {end_date_naive_ist}")

        # Ensure we have valid dates before proceeding
        if not start_date_naive_ist or not end_date_naive_ist:
             print(f"    - ERROR: Missing start_date or end_date for Election ID {self.id}. Cannot determine status.")
             return self.is_active # Keep current status if dates are missing

        # Perform comparison using naive datetimes (all assumed IST)
        is_currently_active = start_date_naive_ist <= now_naive_ist <= end_date_naive_ist
        print(f"    - Comparison Result (start <= now <= end): {is_currently_active}")
        
        if self.is_active != is_currently_active:
            print(f"    - Status Change Detected: {self.is_active} -> {is_currently_active}")
            self.is_active = is_currently_active
            db.session.commit()
            print("    - Status Updated and Committed.")
        else:
            print("    - Status remains unchanged.")
            
        return self.is_active

    @property
    def total_votes(self):
        return len(self.votes)

    @property
    def voting_rate(self):
        total_users = User.query.filter_by(is_admin=False).count()
        if total_users == 0:
            return 0
        return round((self.total_votes / total_users) * 100, 1)

    @property
    def leading_candidate(self):
        if not self.candidates:
            return None
        return max(self.candidates, key=lambda c: len(c.votes))

    @property
    def time_remaining(self):
        if not self.is_active:
            return "Ended"
        remaining = self.end_date - datetime.utcnow()
        if remaining.days > 0:
            return f"{remaining.days} days"
        hours = remaining.seconds // 3600
        minutes = (remaining.seconds % 3600) // 60
        return f"{hours}h {minutes}m"

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
    votes = db.relationship('Vote', backref='candidate', lazy=True)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)
    election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    description = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Add relationship with User
    user = db.relationship('User', backref=db.backref('activities', lazy=True))

class EmailVerification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_activity(user_id, description, details=None):
    log = ActivityLog(user_id=user_id, description=description, details=details)
    db.session.add(log)
    db.session.commit()

def send_verification_email(user):
    otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    verification = EmailVerification(
        user_id=user.id,
        otp=otp,
        expires_at=expires_at
    )
    db.session.add(verification)
    db.session.commit()
    
    msg = Message(
        'Verify Your Email - Online Voting System',
        recipients=[user.email]
    )
    msg.body = f'''Hello {user.username},

Please verify your email address by entering the following OTP:
{otp}

This OTP will expire in 10 minutes.

If you did not request this verification, please ignore this email.

Best regards,
Online Voting System Team'''
    
    mail.send(msg)

def verify_email_config():
    """Verify email configuration is correct"""
    required_settings = [
        'MAIL_SERVER',
        'MAIL_PORT',
        'MAIL_USERNAME',
        'MAIL_PASSWORD',
        'MAIL_DEFAULT_SENDER'
    ]
    
    for setting in required_settings:
        if not app.config.get(setting):
            raise ValueError(f"Missing required email setting: {setting}")
    
    if app.config['MAIL_USERNAME'] != app.config['MAIL_DEFAULT_SENDER']:
        raise ValueError("MAIL_USERNAME and MAIL_DEFAULT_SENDER must match")

def send_otp_email(user, otp):
    try:
        print("\nStarting OTP email process (SSL config)...")
        verify_email_config()
        
        print(f"Recipient email: {user.email}")
        print(f"OTP to send: {otp}")
        print(f"Sender email: {app.config['MAIL_DEFAULT_SENDER']}")
        
        # Create message with HTML content
        msg = Message(
            'Your OTP for Registration - Online Voting System',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[user.email]
        )
        msg.html = f"""
        <html>
            <head>
                <link rel="preconnect" href="https://fonts.googleapis.com">
                <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
                <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;700&family=Poppins:wght@400;600&display=swap" rel="stylesheet">
            </head>
            <body>
                <h2>Hello {user.username},</h2>
                <p>Your OTP for registration is: <strong>{otp}</strong></p>
                <p>This OTP will expire in 10 minutes.</p>
                <p>If you did not request this OTP, please ignore this email.</p>
                <br>
                <p>Best regards,<br>Online Voting System Team</p>
            </body>
        </html>
        """
        
        # --- DETAILED LOGGING BEFORE SEND ---
        print("\n--- Preparing to send email ---")
        print(f"Using Server: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
        print(f"Using SSL: {app.config['MAIL_USE_SSL']}")
        print(f"Using TLS: {app.config['MAIL_USE_TLS']}")
        print(f"Auth User: {app.config['MAIL_USERNAME']}")
        print(f"Message Subject: {msg.subject}")
        print(f"Message Sender: {msg.sender}")
        print(f"Message Recipients: {msg.recipients}")
        print("--- End Pre-Send Log ---")
        # --- END DETAILED LOGGING ---
        
        print("\nAttempting to send OTP email via mail.send()...")
        mail.send(msg)
        print("OTP email sent successfully!")
        return True
    except Exception as e:
        print("\n--- ERROR DURING mail.send() ---")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Message: {str(e)}")
        import traceback
        print("Traceback:")
        traceback.print_exc()
        print("--- End Error Details ---")
        
        # Check for specific error types
        if "authentication failed" in str(e).lower():
            print("\nAuthentication Error: Please check your email password or App Password")
        elif "connection refused" in str(e).lower():
            print("\nConnection Error: Please check your internet connection and firewall settings")
        elif "timeout" in str(e).lower():
            print("\nTimeout Error: The email server is taking too long to respond")
        else:
            print("\nUnknown Error: Please check the error message above")
        
        return False

def send_password_reset_email(user):
    try:
        print("\nStarting password reset email process (SSL config)...")
        verify_email_config()
        
        print(f"Recipient email: {user.email}")
        
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=1)
        
        print("Creating reset token...")
        reset_token = PasswordResetToken(
            user_id=user.id,
            token=token,
            expires_at=expires_at
        )
        db.session.add(reset_token)
        db.session.commit()
        print("Reset token created successfully")
        
        reset_url = url_for('reset_password', token=token, _external=True)
        print(f"Reset URL: {reset_url}")
        
        print("Creating email message...")
        msg = Message(
            'Password Reset Request - Online Voting System',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[user.email]
        )
        msg.body = f'''Hello {user.username},

You have requested to reset your password. Click the following link to reset your password:
{reset_url}

This link will expire in 1 hour.

If you did not request this password reset, please ignore this email.

Best regards,
Online Voting System Team'''
        
        # --- DETAILED LOGGING BEFORE SEND ---
        print("\n--- Preparing to send password reset email ---")
        print(f"Using Server: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
        print(f"Using SSL: {app.config['MAIL_USE_SSL']}")
        print(f"Using TLS: {app.config['MAIL_USE_TLS']}")
        print(f"Auth User: {app.config['MAIL_USERNAME']}")
        print(f"Message Subject: {msg.subject}")
        print(f"Message Sender: {msg.sender}")
        print(f"Message Recipients: {msg.recipients}")
        print("--- End Pre-Send Log ---")
        # --- END DETAILED LOGGING ---
        
        print("\nAttempting to send password reset email via mail.send()...")
        mail.send(msg)
        print("Email sent successfully!")
        return True
    except Exception as e:
        print("\n--- ERROR DURING mail.send() [Password Reset] ---")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Message: {str(e)}")
        import traceback
        print("Traceback:")
        traceback.print_exc()
        print("--- End Error Details ---")
        db.session.rollback()  # Rollback the token creation if email fails
        return False

def generate_otp():
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def send_welcome_email(user):
    try:
        msg = Message(
            'Welcome to Online Voting System',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[user.email]
        )
        msg.body = f'''Dear {user.username},

Welcome to the Online Voting System!

Your registration has been successfully completed. You can now:
- Log in to your account
- View active elections
- Cast your votes
- View election results

Thank you for joining our platform. We look forward to your participation in the democratic process.

Best regards,
Online Voting System Team'''
        
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending welcome email: {str(e)}")
        return False

# Routes
@app.route('/')
def index():
    print("\n--- Fetching Elections for Index Page ---")
    all_elections = Election.query.order_by(Election.start_date.desc()).all() # Order for consistency
    print(f"Found {len(all_elections)} elections in total (ordered by start date desc)")
    
    active_elections = []
    inactive_elections = []
    
    for election in all_elections:
        print(f"\nProcessing Election ID {election.id}: '{election.title}'")
        # Update active status based on current time - This now includes detailed logging
        is_active = election.update_active_status()
        
        if is_active:
            active_elections.append(election)
            print(f"-> Classified as ACTIVE")
        else:
            inactive_elections.append(election)
            print(f"-> Classified as INACTIVE")
            # Add reason for inactivity if needed
            now_check = datetime.utcnow()
            if now_check < election.start_date:
                print(f"   Reason: Has not started yet (Starts at {election.start_date} UTC)")
            elif now_check > election.end_date:
                print(f"   Reason: Already ended (Ended at {election.end_date} UTC)")
            else:
                 print(f"   Reason: Status set to inactive, but time is within range? (investigate)")


    print(f"\n--- Classification Complete ---")
    print(f"Active elections count: {len(active_elections)}")
    print(f"Inactive elections count: {len(inactive_elections)}")
    
    return render_template('index.html', 
                         active_elections=active_elections,
                         inactive_elections=inactive_elections)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        print("\nLogin attempt detected")
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"Attempting login for username: {username}")
        
        user = User.query.filter_by(username=username).first()
        if user:
            print(f"User found: {user.username}")
            print(f"Email verified: {user.is_email_verified}")
            
            if user.check_password(password):
                print("Password correct")
                if user.is_email_verified:
                    print("Email verified, logging in user")
                    login_user(user)
                    user.update_activity()
                    log_activity(user.id, "User logged in")
                    flash('Login successful!', 'success')
                    return redirect(url_for('index'))
                else:
                    print("Email not verified")
                    flash('Please verify your email first.', 'warning')
                    return redirect(url_for('verify_otp', user_id=user.id))
            else:
                print("Incorrect password")
                flash('Invalid password', 'danger')
        else:
            print(f"User not found: {username}")
            flash('Invalid username', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        print("\nRegistration attempt detected")
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        print(f"Registering user: {username} ({email})")
        
        # Check constraints before creating user object
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"Username already exists: {username}")
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
            
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            print(f"Email already registered: {email}")
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
            
        if password != confirm_password:
            print("Passwords do not match")
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
            
        # Create user object (but don't commit yet)
        print("Creating new user object")
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)

        # Generate OTP (but don't commit yet)
        otp_code = generate_otp()
        print(f"Generated OTP: {otp_code}")
        otp_record = OTP(
            # user_id will be set after committing user
            otp=otp_code,
            expires_at=datetime.utcnow() + timedelta(minutes=10)
        )

        try:
            # Commit the user to get the ID
            db.session.flush() # Assigns ID without full commit yet
            if user.id is None:
                 # If flush didn't assign ID (rare, depends on DB setup), commit fully
                 db.session.commit()
                 print(f"User committed to get ID: {user.id}")
            else:
                print(f"User flushed, assigned ID: {user.id}")

            if user.id is None:
                raise Exception("Failed to obtain user ID after commit/flush.")

            # Set user_id for OTP record and add it
            otp_record.user_id = user.id
        db.session.add(otp_record)

            # Commit OTP record (and user if only flushed before)
        db.session.commit()
            print("OTP record created and committed.")

            # Send email in a background thread (pass app context)
            # Use app._get_current_object() to safely get the app instance for the thread
            app_context_for_thread = app._get_current_object()
            email_thread = threading.Thread(
                target=send_otp_email_threaded,
                args=(app_context_for_thread, user.id, user.email, user.username, otp_code)
            )
            email_thread.start()
            print("OTP email sending initiated in background thread.")

            # Redirect immediately
            flash('Registration successful! Please check your email for the OTP.', 'success')
            return redirect(url_for('verify_otp', user_id=user.id))

        except Exception as e:
            db.session.rollback() # Rollback any partial commits
            print(f"ERROR during registration commit or OTP creation: {str(e)}")
            # Log full traceback for debugging
            import traceback
            traceback.print_exc()
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register'))
        
    # GET request
    return render_template('register.html')

def send_otp_email_threaded(app_instance, user_id, user_email, user_username, otp):
    """
    Wrapper function to send OTP email within a thread, ensuring app context.
    """
    with app_instance.app_context():
        # Re-fetch user within the new context if needed, or use passed data
        # For simplicity here, we use passed data. If User object methods were needed, fetch user = User.query.get(user_id)
        print(f"\n[Thread:{threading.current_thread().name}] Attempting to send OTP email...")
        
        # Construct a temporary 'user-like' object or dict for send_otp_email if it expects an object
        # Or modify send_otp_email to accept individual arguments
        
        # Option 1: Modify send_otp_email (Let's assume we do this - simpler)
        # Option 2: Create a simple object
        class TempUser:
            def __init__(self, email, username):
                self.email = email
                self.username = username
        
        temp_user = TempUser(user_email, user_username)
        
        if not send_otp_email(temp_user, otp): # Pass the temporary user object
            print(f"\n[Thread:{threading.current_thread().name}] ERROR: Failed to send OTP email for user ID {user_id}.")
            # Note: We cannot easily rollback the user creation from here
            # The main route already proceeded. Error handling might need refinement.
            # Consider logging this failure persistently.
        else:
             print(f"\n[Thread:{threading.current_thread().name}] SUCCESS: OTP email function executed for user ID {user_id}.")

@app.route('/verify-otp/<int:user_id>', methods=['GET', 'POST'])
def verify_otp(user_id):
    print(f"\nOTP verification for user ID: {user_id}")
    user = User.query.get_or_404(user_id)
    print(f"User found: {user.username}")
    
    if request.method == 'POST':
        otp = request.form['otp']
        print(f"  >> [verify_otp] POST received. User: {user.username}, Entered OTP: '{otp}'") # Log input
        
        now = datetime.utcnow() # Get current time once for comparison
        print(f"  >> [verify_otp] Current UTC time: {now}")
        
        print(f"  >> [verify_otp] Querying for OTP record: user_id={user_id}, otp='{otp}', is_used=False")
        otp_record = OTP.query.filter_by(
            user_id=user_id,
            otp=otp,
            is_used=False
        ).first()
        
        if not otp_record:
            print(f"  >> [verify_otp] RESULT: OTP record NOT FOUND or already used.") # Log failure
            flash('Invalid OTP', 'danger')
            return redirect(url_for('verify_otp', user_id=user_id))
            
        print(f"  >> [verify_otp] Found OTP record: ID={otp_record.id}, Expires at: {otp_record.expires_at}, Is Used: {otp_record.is_used}") # Log found record details
            
        if otp_record.expires_at < now:
            print(f"  >> [verify_otp] RESULT: OTP EXPIRED (Expires: {otp_record.expires_at}, Now: {now}).") # Log expiry
            flash('OTP has expired', 'danger')
            return redirect(url_for('verify_otp', user_id=user_id))
            
        # If we reach here, OTP is valid and not expired
        print("  >> [verify_otp] RESULT: OTP verification SUCCESSFUL.") # Log success path

        try:
        # Mark OTP as used
            print("  >> [verify_otp] Marking OTP as used...")
        otp_record.is_used = True
        # Verify user's email
            print("  >> [verify_otp] Marking user email as verified...")
        user.is_email_verified = True
        db.session.commit()
            print("  >> [verify_otp] Database changes committed.")

            # Send welcome email (Best effort - don't block verification if it fails)
            try:
                print("  >> [verify_otp] Attempting to send welcome email...")
                if send_welcome_email(user):
                    print("  >> [verify_otp] Welcome email sent successfully.")
                else:
                    # Logged within the function, but add a note here too
                    print("  >> [verify_otp] Proceeding with verification despite welcome email failure.")
            except Exception as email_err:
                 print(f"  >> [verify_otp] CRITICAL ERROR sending welcome email: {email_err}")
                 # Optional: Decide if email failure should prevent login?
                 # Currently, it allows login even if email fails.

            # If commit and email attempt (optional) were successful, flash success and redirect
            print("  >> [verify_otp] Proceeding to success flash and redirect.")
        flash('Email verified successfully! You can now login.', 'success')
        return redirect(url_for('login'))
    
        except Exception as e: # This except corresponds to the outer try block
            db.session.rollback() # Rollback DB changes if commit failed
            print(f"  >> [verify_otp] ERROR during DB commit or final steps: {str(e)}")
            import traceback
            traceback.print_exc()
            flash('An error occurred during verification. Please try again later.', 'danger')
            # Redirect back to OTP page on error
            return redirect(url_for('verify_otp', user_id=user_id))
            
    
    return render_template('verify_otp.html', user_id=user_id, user=user)

@app.route('/resend-otp/<int:user_id>', methods=['POST'])
def resend_otp(user_id):
    print(f"\\nResend OTP request for user ID: {user_id}")
    user = User.query.get_or_404(user_id)
    
    if user.is_email_verified:
        print("User is already verified.")
        flash('Your email is already verified.', 'info')
        return redirect(url_for('login'))
        
    try:
        # Generate a new OTP
        new_otp = generate_otp()
        print(f"Generated new OTP: {new_otp}")
        
        # Find existing active OTPs for this user and mark them as used/invalid
        # This prevents old, potentially compromised OTPs from being used.
        now = datetime.utcnow()
        existing_otps = OTP.query.filter_by(user_id=user_id, is_used=False).filter(OTP.expires_at > now).all()
        if existing_otps:
            print(f"Found {len(existing_otps)} existing active OTPs. Invalidating them...")
            for old_otp in existing_otps:
                old_otp.is_used = True # Mark as used to invalidate
                # Optionally, you could also set expires_at = now
        
        # Create and save the new OTP record
        new_otp_record = OTP(
            user_id=user.id,
            otp=new_otp,
            expires_at=datetime.utcnow() + timedelta(minutes=10) # New expiration time
        )
        db.session.add(new_otp_record)
        db.session.commit()
        print("New OTP record created and saved.")
        
        # Send the new OTP email in a background thread
        email_thread = threading.Thread(target=send_otp_email_threaded, args=(app, user.id, user.email, user.username, new_otp))
        email_thread.start()
        print("New OTP email sending initiated in background thread.")
        
        flash('A new OTP has been sent to your email address.', 'success')
        
    except Exception as e:
        db.session.rollback()
        print(f"Error during OTP resend process: {str(e)}")
        flash('An error occurred while trying to resend the OTP. Please try again later.', 'danger')
        
    return redirect(url_for('verify_otp', user_id=user_id))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        print("\nPassword reset request received")
        email = request.form['email']
        print(f"Email provided: {email}")
        
        user = User.query.filter_by(email=email).first()
        if user:
            print(f"User found: {user.username}")
            if send_password_reset_email(user):
                print("Password reset email sent successfully")
                flash('Password reset instructions have been sent to your email.', 'success')
            else:
                print("Failed to send password reset email")
                flash('Error sending email. Please try again later.', 'danger')
        else:
            print(f"No user found with email: {email}")
            # For security reasons, show the same message even if email doesn't exist
            flash('If the email exists in our system, password reset instructions will be sent.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(
        token=token,
        is_used=False
    ).first()
    
    if not reset_token or reset_token.expires_at < datetime.utcnow():
        flash('Invalid or expired reset token')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('reset_password.html', token=token)
        
        user = User.query.get(reset_token.user_id)
        user.set_password(password)
        reset_token.is_used = True
        db.session.commit()
        print(f"  >> [reset_password] Password reset for user {user.username} completed.") # Add log
        
        # Check if user still needs email verification after password reset
        if not user.is_email_verified:
            print(f"  >> [reset_password] User {user.username} is not verified. Sending new OTP.") # Add log
            otp = generate_otp()
            otp_record = OTP(
                user_id=user.id,
                otp=otp,
                expires_at=datetime.utcnow() + timedelta(minutes=10)
            )
            db.session.add(otp_record)
            db.session.commit()
            
            if send_otp_email(user, otp):
                flash('Password reset successfully! Please check your email for a new verification OTP.', 'info')
                return redirect(url_for('verify_otp', user_id=user.id))
            else:
                # If OTP sending fails, still let them know password was reset, but verification failed
                flash('Password reset successfully, but failed to send verification email. Please contact support.', 'warning')
                return redirect(url_for('login')) # Or maybe redirect to profile?
        else:
            # If user was already verified, just confirm password reset
            print(f"  >> [reset_password] User {user.username} was already verified. Redirecting to login.") # Add log
            flash('Password has been reset successfully!', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, "User logged out")
    logout_user()
    return redirect(url_for('index'))

@app.route('/vote/<int:election_id>', methods=['GET', 'POST'])
@login_required
def vote(election_id):
    try:
        print(f"\n--- Vote Attempt for Election ID: {election_id} by User: {current_user.username} ---")
        election = Election.query.get_or_404(election_id)
        print(f"Found election: '{election.title}'")
        
        # Check 1: Is the election active?
        # Force an update check, just in case it wasn't updated recently
        is_currently_active = election.update_active_status() 
        print(f"Checking Active Status: Result from update_active_status() is {is_currently_active}")
        if not is_currently_active:
            print("-> VOTE BLOCKED: Election is not active.")
            flash('This election is not currently active for voting.', 'warning')
            return redirect(url_for('index'))
        print("-> Check 1 Passed: Election is active.")

        # Check 2: Has the user already voted?
        has_voted = current_user.has_voted_in_election(election_id)
        print(f"Checking Previous Vote Status: User has_voted_in_election({election_id}) is {has_voted}")
        if has_voted:
            print(f"-> VOTE BLOCKED: User {current_user.username} has already voted.")
            flash('You have already voted in this election.', 'info')
            return redirect(url_for('index'))
        print("-> Check 2 Passed: User has not voted yet.")
        
        # If GET request, show the voting form
        if request.method == 'GET':
            print("Request method is GET, rendering vote template.")
            return render_template('vote.html', election=election)
            
        # If POST request, process the vote
        if request.method == 'POST':
            print("\nProcessing POST request...")
            candidate_id = request.form.get('candidate')
            print(f"Candidate ID from form: {candidate_id}")
            
            # Check 3: Was a candidate selected?
            if not candidate_id:
                print("-> VOTE FAILED: No candidate selected.")
                flash('Please select a candidate.', 'danger')
                return redirect(url_for('vote', election_id=election_id))
            print("-> Check 3 Passed: Candidate ID provided.")
            
            # Check 4: Is the selected candidate valid for this election?
            try:
                candidate_id_int = int(candidate_id) # Ensure it's an integer
                candidate = Candidate.query.filter_by(
                    id=candidate_id_int,
                    election_id=election_id
                ).first()
            except ValueError:
                print("-> VOTE FAILED: Candidate ID is not a valid integer.")
                flash('Invalid candidate selection.', 'danger')
                return redirect(url_for('vote', election_id=election_id))
                
            if not candidate:
                print(f"-> VOTE FAILED: Candidate ID {candidate_id} not found or doesn't belong to election {election_id}.")
                flash('Invalid candidate selection.', 'danger')
                return redirect(url_for('vote', election_id=election_id))
            print(f"-> Check 4 Passed: Valid candidate found: '{candidate.name}' (ID: {candidate.id})")
            
            # Proceed to record the vote
            print(f"\nAttempting to record vote for candidate: {candidate.name}")
            new_vote = Vote(
                user_id=current_user.id,
                candidate_id=candidate.id, # Use the validated integer ID
                election_id=election_id
            )
            
            try:
                db.session.add(new_vote)
                current_user.update_activity() # Update last activity timestamp
                db.session.commit()
                print("Vote successfully saved to database.")
                
                log_activity(current_user.id, "Vote cast", f"Voted for {candidate.name} in {election.title}")
                flash('Your vote has been successfully recorded!', 'success')
                return redirect(url_for('index'))
            except Exception as e:
                db.session.rollback()
                print(f"!!! DATABASE ERROR while saving vote: {str(e)}")
                import traceback
                traceback.print_exc()
                flash('An error occurred while recording your vote. Please try again.', 'danger')
                return redirect(url_for('vote', election_id=election_id))
        
    except Exception as e:
        print(f"!!! UNEXPECTED ERROR in /vote/{election_id} route: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        traceback.print_exc()
        flash('An unexpected error occurred. Please try again later.', 'danger')
        return redirect(url_for('index'))

@app.route('/results/<int:election_id>')
def results(election_id):
    try:
        print(f"Fetching results for election ID: {election_id}")
        election = Election.query.get_or_404(election_id)
        print(f"Found election: {election.title}")
        
        # Determine if the election has ended (comparing naive IST times)
        now_naive_ist = datetime.now(IST).replace(tzinfo=None)
        election_ended = now_naive_ist > election.end_date if election.end_date else False # Handle case where end_date might be None
        print(f"Election End Date (Naive IST): {election.end_date}")
        print(f"Current Naive IST: {now_naive_ist}")
        print(f"Has election ended? {election_ended}")
        
        # Get all candidates for this election
        candidates = Candidate.query.filter_by(election_id=election_id).all()
        print(f"Found {len(candidates)} candidates")
        
        # Get all votes for this election
        votes = Vote.query.filter_by(election_id=election_id).all()
        print(f"Found {len(votes)} total votes")
        
        # Count votes for each candidate
        vote_counts = {}
        for candidate in candidates:
            count = Vote.query.filter_by(
                election_id=election_id,
                candidate_id=candidate.id
            ).count()
            vote_counts[candidate.id] = count
            print(f"Candidate {candidate.name} has {count} votes")
        
        # Calculate total votes
        total_votes = sum(vote_counts.values())
        print(f"Total votes: {total_votes}")
        
        # Calculate percentages
        percentages = {}
        for candidate_id, count in vote_counts.items():
            if total_votes > 0:
                percentage = (count / total_votes) * 100
            else:
                percentage = 0
            percentages[candidate_id] = round(percentage, 2)
            print(f"Candidate {candidate_id} has {percentage}% of votes")
        
        # Get winner(s)
        if vote_counts:
            max_votes = max(vote_counts.values())
            winners = [
                candidate for candidate in candidates
                if vote_counts[candidate.id] == max_votes
            ]
            print(f"Found {len(winners)} winners with {max_votes} votes each")
        else:
            winners = []
            print("No winners found (no votes)")
        
        # Check if current user has voted
        has_voted = False
        if current_user.is_authenticated:
            has_voted = Vote.query.filter_by(
                user_id=current_user.id,
                election_id=election_id
            ).first() is not None
            print(f"Current user has voted: {has_voted}")
        
        return render_template('results.html',
                             election=election,
                             candidates=candidates,
                             vote_counts=vote_counts,
                             percentages=percentages,
                             total_votes=total_votes,
                             winners=winners,
                             has_voted=has_voted,
                             election_ended=election_ended) # Pass the flag to the template
    except Exception as e:
        print(f"Error in results route: {str(e)}")
        print(f"Error type: {type(e)}")
        print(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No details available'}")
        flash('Error loading results. Please try again.')
        return redirect(url_for('index'))

# Admin Routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    # Get statistics
    total_users = User.query.count()
    active_elections = Election.query.filter_by(is_active=True).count()
    total_votes = Vote.query.count()
    voting_rate = round((total_votes / total_users * 100), 1) if total_users > 0 else 0
    
    # Get all users with their activity
    users = User.query.all()
    
    # Get all elections
    elections = Election.query.all()
    
    # Get recent activities with user information
    recent_activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         active_elections=active_elections, # Note: This count might be slightly off if status not updated yet
                         total_votes=total_votes,
                         voting_rate=voting_rate,
                         users=users,
                         elections=elections,
                         recent_activities=recent_activities)

@app.route('/admin/create_election', methods=['GET', 'POST'])
@login_required
def create_election():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        print("\n--- Admin Creating New Election ---")
        title = request.form.get('title')
        description = request.form.get('description')
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        print(f"Received Title: {title}")
        print(f"Received Start Date Str (IST from form): {start_date_str}")
        print(f"Received End Date Str (IST from form): {end_date_str}")
        
        try:
            # Parse dates as naive (implicitly IST)
            start_date_naive_ist = datetime.strptime(start_date_str, '%Y-%m-%dT%H:%M')
            end_date_naive_ist = datetime.strptime(end_date_str, '%Y-%m-%dT%H:%M')
            print(f"Parsed Naive Start Date (IST): {start_date_naive_ist}")
            print(f"Parsed Naive End Date (IST): {end_date_naive_ist}")

        except ValueError as e:
            print(f"!!! ERROR parsing dates: {e}")
            flash(f'Invalid date format. Please use YYYY-MM-DDTHH:MM. Error: {e}', 'danger')
            return render_template('admin/create_election.html')
        
        # Validate naive dates
        if start_date_naive_ist >= end_date_naive_ist:
            print("!!! ERROR: Start date must be before end date.")
            flash('Start date must be before end date.', 'danger')
            return render_template('admin/create_election.html')

        # Create new election using naive IST dates
        print("Creating election object with naive IST dates...")
        election = Election(
            title=title,
            description=description,
            start_date=start_date_naive_ist, # Store naive IST
            end_date=end_date_naive_ist,   # Store naive IST
            is_active=False # Default to False, update_active_status will correct it
        )
        db.session.add(election)
        
        # Add candidates
        candidate_names = request.form.getlist('candidate_name[]')
        candidate_descriptions = request.form.getlist('candidate_description[]')
        print(f"Received {len(candidate_names)} candidates.")
        
        # Need to commit election first to get its ID for candidates if relationship requires it,
        # OR pass the election object directly as done here.
        
        candidates_added = []
        for name, desc in zip(candidate_names, candidate_descriptions):
            if name.strip():  # Only add if name is not empty
                print(f"  Adding candidate: {name}")
                candidate = Candidate(
                    name=name,
                    description=desc,
                    election=election # Pass the election object
                )
                db.session.add(candidate)
                candidates_added.append(name)
            else:
                print("  Skipping empty candidate name.")
        
        try:
            print("Committing election and candidates to database...")
            db.session.commit()
            print(f"Election created with ID: {election.id}")
            print(f"Candidates added: {candidates_added}")
            
            # Now, update the active status based on the dates just saved
            print("Updating election active status...")
            election.update_active_status() # This will check dates and commit if status changes
            print(f"Final active status after update: {election.is_active}")
            
            log_activity(current_user.id, "Created new election", f"Created election '{title}' (ID: {election.id}) with status {election.is_active}")
            flash('Election created successfully!', 'success')
            return redirect(url_for('admin_dashboard')) # Redirect to dashboard to see it
        except Exception as e:
            db.session.rollback()
            print(f"!!! DATABASE ERROR during commit or status update: {str(e)}")
            import traceback
            traceback.print_exc()
            flash(f'Database error creating election: {str(e)}', 'danger')
            return render_template('admin/create_election.html')
            
    # For GET request
    return render_template('admin/create_election.html')

# Temporary route to make a user an admin (should be removed in production)
@app.route('/make_admin/<username>')
def make_admin(username):
    user = User.query.filter_by(username=username).first()
    if user:
        user.is_admin = True
        db.session.commit()
        log_activity(user.id, "User promoted to admin")
        flash(f'User {username} is now an admin', 'success')
    return redirect(url_for('index'))

@app.route('/admin/election/<int:election_id>/add_candidate', methods=['POST'])
@login_required
def add_candidate(election_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    election = Election.query.get_or_404(election_id)
    name = request.form.get('name')
    description = request.form.get('description')
    
    if name and description:
        candidate = Candidate(
            name=name,
            description=description,
            election=election
        )
        db.session.add(candidate)
        db.session.commit()
        log_activity(current_user.id, "Added new candidate", f"Added {name} to {election.title}")
        flash('Candidate added successfully!', 'success')
    else:
        flash('Please provide both name and description for the candidate.', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/election/<int:election_id>/delete', methods=['POST'])
@login_required
def delete_election(election_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    election = Election.query.get_or_404(election_id)
    
    # Delete all votes associated with this election
    Vote.query.filter_by(election_id=election_id).delete()
    
    # Delete all candidates associated with this election
    Candidate.query.filter_by(election_id=election_id).delete()
    
    # Delete the election
    db.session.delete(election)
    db.session.commit()
    
    log_activity(current_user.id, "Deleted election", f"Deleted election: {election.title} (with {election.total_votes} votes)")
    flash('Election deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/election/<int:election_id>/manage', methods=['GET'])
@login_required
def manage_election(election_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    election = Election.query.get_or_404(election_id)
    return render_template('admin/manage_election.html', election=election)

@app.route('/admin/election/<int:election_id>/candidate/<int:candidate_id>/delete', methods=['POST'])
@login_required
def delete_candidate(election_id, candidate_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    election = Election.query.get_or_404(election_id)
    candidate = Candidate.query.get_or_404(candidate_id)
    
    # Check if candidate belongs to the election
    if candidate.election_id != election_id:
        flash('Invalid candidate for this election.', 'danger')
        return redirect(url_for('manage_election', election_id=election_id))
    
    # Check if anyone has voted for this candidate
    if candidate.votes:
        flash('Cannot delete candidate with existing votes.', 'danger')
        return redirect(url_for('manage_election', election_id=election_id))
    
    # Delete the candidate
    db.session.delete(candidate)
    db.session.commit()
    
    log_activity(current_user.id, "Deleted candidate", f"Deleted candidate {candidate.name} from election: {election.title}")
    flash('Candidate deleted successfully!', 'success')
    return redirect(url_for('manage_election', election_id=election_id))

@app.route('/check_users')
def check_users():
    if not app.debug:
        return "Not available in production"
    users = User.query.all()
    return jsonify([{"username": user.username, "email": user.email} for user in users])

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_picture':
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"{current_user.id}_{file.filename}")
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    
                    # Delete old profile picture if it's not the default
                    if current_user.profile_picture != 'default.jpg':
                        old_file = os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_picture)
                        if os.path.exists(old_file):
                            os.remove(old_file)
                    
                    current_user.profile_picture = filename
                    db.session.commit()
                    flash('Profile picture updated successfully!', 'success')
                else:
                    flash('Invalid file type. Please upload an image file.', 'danger')
        
        elif action == 'update_info':
            new_username = request.form.get('username')
            new_email = request.form.get('email')
            
            # Check if username is already taken
            if new_username != current_user.username:
                existing_user = User.query.filter_by(username=new_username).first()
                if existing_user:
                    flash('Username already taken. Please choose another.', 'danger')
                    return redirect(url_for('profile'))
            
            # Check if email is already taken
            if new_email != current_user.email:
                existing_email = User.query.filter_by(email=new_email).first()
                if existing_email:
                    flash('Email already registered. Please use another.', 'danger')
                    return redirect(url_for('profile'))
                
                # If email is changed, mark as unverified
                current_user.is_email_verified = False
                # Send verification email
                otp = generate_otp()
                otp_record = OTP(
                    user_id=current_user.id,
                    otp=otp,
                    expires_at=datetime.utcnow() + timedelta(minutes=10)
                )
                db.session.add(otp_record)
                send_otp_email(current_user, otp)
                flash('Email changed. Please verify your new email address.', 'warning')
            
            current_user.username = new_username
            current_user.email = new_email
            db.session.commit()
            flash('Profile information updated successfully!', 'success')
        
        elif action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not current_user.check_password(current_password):
                flash('Current password is incorrect.', 'danger')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
            else:
                current_user.set_password(new_password)
                db.session.commit()
                flash('Password changed successfully!', 'success')
        
        return redirect(url_for('profile'))
    
    return render_template('profile.html')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# Add this configuration at the top of the file with other configurations
app.config['UPLOAD_FOLDER'] = 'static/profile_pictures'

@app.route('/debug/elections')
def debug_elections():
    if not app.debug:
        return "Not available in production"
    
    elections = Election.query.all()
    return jsonify([{
        "id": e.id,
        "title": e.title,
        "start_date": e.start_date.isoformat(),
        "end_date": e.end_date.isoformat(),
        "is_active": e.is_active
    } for e in elections])

@app.route('/create_sample_election')
def create_sample_election():
    if not app.debug:
        return "Not available in production"
    
    try:
        print("Starting sample election creation...")
        
        # Create a sample election
        election = Election(
            title="Sample Election 2024",
            description="This is a sample election to demonstrate the voting system.",
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow() + timedelta(days=7),
            is_active=True
        )
        print(f"Created election object: {election.title}")
        
        db.session.add(election)
        db.session.commit()
        print(f"Election saved to database with ID: {election.id}")
        
        # Add sample candidates
        candidates = [
            ("John Doe", "Experienced leader with a vision for the future"),
            ("Jane Smith", "Innovative thinker with fresh perspectives"),
            ("Robert Johnson", "Dedicated to community service and development")
        ]
        
        for name, description in candidates:
            candidate = Candidate(
                name=name,
                description=description,
                election_id=election.id
            )
            db.session.add(candidate)
            print(f"Added candidate: {name}")
        
        db.session.commit()
        print("All candidates saved to database")
        
        # Verify the election was created
        saved_election = Election.query.get(election.id)
        print(f"Retrieved election from database: {saved_election.title}")
        print(f"Election active status: {saved_election.is_active}")
        
        return redirect(url_for('index'))
    except Exception as e:
        print(f"Error creating sample election: {str(e)}")
        print(f"Error type: {type(e)}")
        print(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No details available'}")
        return f"Error creating sample election: {str(e)}"

@app.route('/create_admin')
def create_admin():
    if not app.debug:
        return "Not available in production"
    
    try:
        # Check if admin already exists
        admin = User.query.filter_by(username='admin').first()
        if admin:
            return "Admin user already exists"
        
        # Create admin user
        admin = User(
            username='admin',
            email='admin@example.com',
            is_admin=True,
            is_email_verified=True
        )
        admin.set_password('admin123')  # Set a default password
        db.session.add(admin)
        db.session.commit()
        
        return "Admin user created successfully! Username: admin, Password: admin123"
    except Exception as e:
        return f"Error creating admin user: {str(e)}"

@app.route('/create_custom_admin', methods=['GET', 'POST'])
def create_custom_admin():
    if not app.debug:
        return "Not available in production"
    
    if request.method == 'POST':
        try:
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
            
            # Check if user already exists
            if User.query.filter_by(username=username).first():
                flash(f"Username '{username}' already exists", 'danger')
                return redirect(url_for('create_custom_admin'))
            if User.query.filter_by(email=email).first():
                flash(f"Email '{email}' already registered", 'danger')
                return redirect(url_for('create_custom_admin'))
            
            # Create admin user
            admin = User(
                username=username,
                email=email,
                is_admin=True,
                is_email_verified=True # Automatically verify admin emails
            )
            admin.set_password(password)
            db.session.add(admin)
            db.session.commit()
            
            flash(f"Admin user '{username}' created successfully!", 'success')
            # Redirect to admin dashboard or user list might be better here
            return redirect(url_for('admin_dashboard')) 
        except Exception as e:
            flash(f"Error creating admin user: {str(e)}", 'danger')
            return redirect(url_for('create_custom_admin'))
    
    # GET request renders the new template
    return render_template('admin/create_custom_admin.html')

def backup_database():
    try:
        # Get the absolute path to the instance folder
        instance_path = app.instance_path
        db_path = os.path.join(instance_path, 'voting.db')
        
        # Check if the database file exists
        if not os.path.exists(db_path):
            print(f"Error: Database file not found at {db_path}")
            return False
            
        # Create backups directory if it doesn't exist (relative to project root)
        backup_dir = 'database_backups'
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        # Create backup filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(backup_dir, f'voting_backup_{timestamp}.db')
        
        # Copy the database file
        shutil.copy2(db_path, backup_file)
        print(f"Database backed up from {db_path} to: {backup_file}")
        return True
    except Exception as e:
        print(f"Error backing up database: {str(e)}")
        import traceback
        traceback.print_exc() # Add traceback for more details
        return False

# Add this route for manual backup
@app.route('/admin/backup_database')
@login_required
def admin_backup_database():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    if backup_database():
        flash('Database backup created successfully!', 'success')
    else:
        flash('Error creating database backup.', 'danger')
    
    return redirect(url_for('admin_dashboard'))

# Add this route for database reset
@app.route('/admin/reset_database', methods=['POST'])
@login_required
def admin_reset_database():
    if not app.debug:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
        
    # Add debug mode check for extra safety
    if not app.debug:
        flash('Database reset is only allowed in debug mode.', 'danger')
        return redirect(url_for('admin_dashboard'))

    try:
        print("\n--- Starting Database Reset Process ---")
        # 1. Create backup before reset
        print("Creating database backup...")
        if not backup_database():
             flash('Failed to create database backup. Reset aborted.', 'danger')
             return redirect(url_for('admin_dashboard'))
        print("Backup created.")

        # 2. Explicitly delete data from tables in reverse dependency order
        print("Explicitly deleting existing data...")
        Vote.query.delete()
        print("  - Deleted all Votes")
        OTP.query.delete()
        print("  - Deleted all OTPs")
        PasswordResetToken.query.delete()
        print("  - Deleted all Password Reset Tokens")
        ActivityLog.query.delete()
        print("  - Deleted all Activity Logs")
        Candidate.query.delete() # Candidates depend on Elections, but Votes depend on Candidates
        print("  - Deleted all Candidates")
        # We delete Elections after Candidates/Votes
        # We delete Users last, as other things might reference them
        User.query.delete()
        print("  - Deleted all Users (including old admin)")
        # Delete Elections after Candidates/Votes
        Election.query.delete()
        print("  - Deleted all Elections")

        # Commit the deletions
        db.session.commit()
        print("Data deletion committed.")

        # 3. Drop all tables
        print("Dropping all database tables...")
        db.drop_all()
        print("Tables dropped.")
        
        # 4. Recreate tables
        print("Recreating database tables...")
        db.create_all()
        print("Tables recreated.")
        
        # 5. Create default admin
        print("Creating default admin user...")
        admin = User(
            username='admin',
            email='admin@example.com',
            is_admin=True,
            is_email_verified=True
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        print("Default admin user created.")
        
        # Recreate default profile picture folder/file if needed
        print("Ensuring default profile picture exists...")
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        default_pic_path = os.path.join(app.config['UPLOAD_FOLDER'], 'default.jpg')
        # Always regenerate on reset to ensure color palette match
        # if not os.path.exists(default_pic_path):
        try:
            print("[Reset DB] Attempting to generate default profile picture with app colors...")
            img = Image.new('RGB', (200, 200), color='#2E3944') # Dark Blue/Grey background
            draw = ImageDraw.Draw(img)
            # Draw head (circle)
            draw.ellipse((70, 40, 130, 100), fill='#748D92') # Grey Blue head
            # Draw body (rounded rectangle)
            draw.rounded_rectangle((50, 110, 150, 180), radius=20, fill='#748D92') # Grey Blue body
            img.save(default_pic_path)
            print("[Reset DB] Default profile picture (re)generated.")
        except Exception as img_err:
            print(f"[Reset DB] ERROR generating default profile picture: {img_err}")

        print("--- Database Reset Complete ---")
        flash('Database reset successfully! All old data deleted. Default admin created.', 'success')
        # Log this activity if ActivityLog table exists (it does after create_all)
        log_activity(admin.id, "Database Reset", "Database completely reset.")

    except Exception as e:
        db.session.rollback()
        print(f"\n--- ERROR DURING DATABASE RESET --- ")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Message: {str(e)}")
        import traceback
        print("Traceback:")
        traceback.print_exc()
        print("--- End Error Details ---")
        flash(f'Error resetting database: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/create_sample_data')
@login_required
def create_sample_data():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))
    
    try:
        print("\nStarting sample data creation...")
        
        # Create sample elections with current time as start date
        now = datetime.utcnow()
        print(f"Current time: {now}")
        
        elections = [
            {
                'title': 'Student Council Election 2024',
                'description': 'Election for student council members',
                'start_date': now,
                'end_date': now + timedelta(days=7),
                'candidates': [
                    ('Alex Johnson', 'Experienced student leader'),
                    ('Sarah Williams', 'Advocate for student rights'),
                    ('Michael Brown', 'Focus on campus improvements')
                ]
            },
            {
                'title': 'Class President Election',
                'description': 'Election for class president',
                'start_date': now,
                'end_date': now + timedelta(days=8),
                'candidates': [
                    ('Emily Davis', 'Dedicated to student success'),
                    ('James Wilson', 'Innovative ideas for the class'),
                    ('Olivia Martinez', 'Strong leadership skills')
                ]
            }
        ]
        
        for election_data in elections:
            print(f"\nCreating election: {election_data['title']}")
            print(f"Start date: {election_data['start_date']}")
            print(f"End date: {election_data['end_date']}")
            
            # Create election with is_active=True
            election = Election(
                title=election_data['title'],
                description=election_data['description'],
                start_date=election_data['start_date'],
                end_date=election_data['end_date'],
                is_active=True
            )
            print(f"Election object created with is_active={election.is_active}")
            
            db.session.add(election)
            db.session.commit()
            print(f"Election saved to database with ID: {election.id}")
            
            for name, description in election_data['candidates']:
                print(f"Adding candidate: {name}")
                candidate = Candidate(
                    name=name,
                    description=description,
                    election_id=election.id
                )
                db.session.add(candidate)
            
            db.session.commit()
            print(f"All candidates saved for election {election.title}")
            
            # Verify the election was saved correctly
            saved_election = Election.query.get(election.id)
            print(f"Retrieved election from database: {saved_election.title}")
            print(f"Election active status: {saved_election.is_active}")
            print(f"Election start date: {saved_election.start_date}")
            print(f"Election end date: {saved_election.end_date}")
            
            # Force update active status
            saved_election.update_active_status()
            print(f"Updated active status: {saved_election.is_active}")
        
        print("\nSample data creation completed successfully!")
        flash('Sample data created successfully!', 'success')
    except Exception as e:
        print(f"\nError creating sample data: {str(e)}")
        print(f"Error type: {type(e)}")
        print(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No details available'}")
        flash(f'Error creating sample data: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/debug/database')
def debug_database():
    if not app.debug:
        return "Not available in production"
    
    try:
        print("\nFetching all database contents...")
        
        # Get all users
        users = User.query.all()
        print(f"\nUsers ({len(users)}):")
        for user in users:
            print(f"ID: {user.id}, Username: {user.username}, Email: {user.email}, Admin: {user.is_admin}, Verified: {user.is_email_verified}")
        
        # Get all elections
        elections = Election.query.all()
        print(f"\nElections ({len(elections)}):")
        for election in elections:
            print(f"ID: {election.id}, Title: {election.title}, Active: {election.is_active}")
            print(f"Start: {election.start_date}, End: {election.end_date}")
            print(f"Candidates: {[c.name for c in election.candidates]}")
        
        # Get all candidates
        candidates = Candidate.query.all()
        print(f"\nCandidates ({len(candidates)}):")
        for candidate in candidates:
            print(f"ID: {candidate.id}, Name: {candidate.name}, Election ID: {candidate.election_id}")
        
        return "Database contents printed to console. Check your terminal for details."
    except Exception as e:
        print(f"Error viewing database: {str(e)}")
        return f"Error: {str(e)}"

@app.route('/test_email')
def test_email():
    if not app.debug:
        return "Not available in production"
    
    try:
        print("\nTesting email configuration...")
        print(f"MAIL_SERVER: {app.config['MAIL_SERVER']}")
        print(f"MAIL_PORT: {app.config['MAIL_PORT']}")
        print(f"MAIL_USE_TLS: {app.config['MAIL_USE_TLS']}")
        print(f"MAIL_USE_SSL: {app.config['MAIL_USE_SSL']}")
        print(f"MAIL_USERNAME: {app.config['MAIL_USERNAME']}")
        print(f"MAIL_DEFAULT_SENDER: {app.config['MAIL_DEFAULT_SENDER']}")
        
        # Create a test message
        msg = Message(
            'Test Email - Online Voting System',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=['kumarakarthikeya_mangu@srmap.edu.in']  # Send to yourself for testing
        )
        msg.html = '''
        <html>
            <body>
                <h2>Test Email</h2>
                <p>This is a test email from the Online Voting System.</p>
                <p>If you receive this email, the email configuration is working correctly.</p>
                <br>
                <p>Best regards,<br>Online Voting System Team</p>
            </body>
        </html>
        '''
        
        print("\nAttempting to send test email...")
        mail.send(msg)
        print("Test email sent successfully!")
        
        return '''
            <h1>Email Test Successful!</h1>
            <p>Test email has been sent. Please check your inbox.</p>
            <p>If you don't receive the email within a few minutes, check your spam folder.</p>
            <p>Check the console for detailed logs.</p>
        '''
    except Exception as e:
        print(f"\nError sending test email: {str(e)}")
        print(f"Error type: {type(e)}")
        print(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No details available'}")
        
        return f'''
            <h1>Email Test Failed</h1>
            <p>Error: {str(e)}</p>
            <p>Check the console for detailed error logs.</p>
            <p>Common issues:</p>
            <ul>
                <li>Incorrect email password or App Password</li>
                <li>2-Step Verification not enabled</li>
                <li>Firewall blocking SMTP connections</li>
                <li>Incorrect email server settings</li>
            </ul>
        '''

@app.route('/test_otp')
def test_otp():
    if not app.debug:
        return "Not available in production"
    
    try:
        print("\n=== Starting OTP Functionality Test ===")
        
        # 1. Test OTP Generation
        print("\n1. Testing OTP Generation...")
        otp = generate_otp()
        print(f"Generated OTP: {otp}")
        
        # 2. Create a test user
        print("\n2. Creating test user...")
        test_user = User(
            username='test_otp_user',
            email='kumarakarthikeya_mangu@srmap.edu.in',  # Using your email for testing
            is_email_verified=False
        )
        test_user.set_password('test123')
        db.session.add(test_user)
        db.session.commit()
        print(f"Test user created with ID: {test_user.id}")
        
        # 3. Create OTP record
        print("\n3. Creating OTP record...")
        otp_record = OTP(
            user_id=test_user.id,
            otp=otp,
            expires_at=datetime.utcnow() + timedelta(minutes=10)
        )
        db.session.add(otp_record)
        db.session.commit()
        print(f"OTP record created with ID: {otp_record.id}")
        
        # 4. Send OTP email
        print("\n4. Sending OTP email...")
        otp_sent = send_otp_email(test_user, otp)
        print(f"OTP Email Status: {'Success' if otp_sent else 'Failed'}")
        
        # 5. Clean up test data
        print("\n5. Cleaning up test data...")
        db.session.delete(otp_record)
        db.session.delete(test_user)
        db.session.commit()
        print("Test data cleaned up")
        
        return '''
            <h1>OTP Functionality Test Results</h1>
            <p>Check the console for detailed test results.</p>
            <p>If the test shows "Success", your OTP functionality is working correctly.</p>
            <p>If you see any errors, check the console for detailed error messages.</p>
            <h2>Next Steps:</h2>
            <ol>
                <li>Check your email inbox for the OTP email</li>
                <li>Verify that the email contains the correct OTP</li>
                <li>If email is not received, check your spam folder</li>
                <li>If still not received, check the console for error messages</li>
            </ol>
            <h2>Troubleshooting:</h2>
            <ul>
                <li>Make sure your Gmail account has 2-Step Verification enabled</li>
                <li>Verify that you're using the correct App Password</li>
                <li>Check if your firewall is blocking SMTP connections</li>
                <li>Ensure the email server settings are correct</li>
            </ul>
        '''
    except Exception as e:
        print(f"\nError during OTP test: {str(e)}")
        print(f"Error type: {type(e)}")
        print(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No details available'}")
        
        # Clean up any partial test data
        try:
            if 'test_user' in locals():
                db.session.delete(test_user)
            if 'otp_record' in locals():
                db.session.delete(otp_record)
            db.session.commit()
        except:
            pass
        
        return f'''
            <h1>OTP Test Failed</h1>
            <p>Error: {str(e)}</p>
            <p>Check the console for detailed error logs.</p>
            <p>Common issues:</p>
            <ul>
                <li>Incorrect email password or App Password</li>
                <li>2-Step Verification not enabled</li>
                <li>Firewall blocking SMTP connections</li>
                <li>Incorrect email server settings</li>
            </ul>
        '''

# Add this route for resetting users (debug only)
@app.route('/admin/reset_users', methods=['POST'])
@login_required
def admin_reset_users():
    if not app.debug:
        flash('This function is only available in debug mode.', 'danger')
        return redirect(url_for('admin_dashboard'))
        
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))

    try:
        print("\n--- Starting User Reset Process (Excluding 'admin') ---")
        users_to_delete = User.query.filter(User.username != 'admin').all()
        deleted_count = 0
        
        for user in users_to_delete:
            print(f"Preparing to delete user: {user.username} (ID: {user.id})")
            
            # Delete associated records first to avoid foreign key constraints
            Vote.query.filter_by(user_id=user.id).delete()
            print(f"  - Deleted votes for user {user.id}")
            OTP.query.filter_by(user_id=user.id).delete()
            print(f"  - Deleted OTPs for user {user.id}")
            PasswordResetToken.query.filter_by(user_id=user.id).delete()
            print(f"  - Deleted Password Reset Tokens for user {user.id}")
            ActivityLog.query.filter_by(user_id=user.id).delete()
            print(f"  - Deleted Activity Logs for user {user.id}")
            
            # Now delete the user
            db.session.delete(user)
            print(f"  - Deleting user {user.username}")
            deleted_count += 1

        db.session.commit()
        print(f"--- User Reset Complete. Deleted {deleted_count} users. ---")
        flash(f'Successfully deleted {deleted_count} users (excluding admin).', 'success')
        log_activity(current_user.id, "Reset users", f"Deleted {deleted_count} non-admin users.")
        
    except Exception as e:
        db.session.rollback()
        print(f"\n--- ERROR DURING USER RESET --- ")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Message: {str(e)}")
        import traceback
        print("Traceback:")
        traceback.print_exc()
        print("--- End Error Details ---")
        flash(f'Error resetting users: {str(e)}', 'danger')

    return redirect(url_for('admin_dashboard'))

# Admin Route to View Data Summary
@app.route('/admin/view_data')
@login_required
def admin_view_data():
    if not app.debug:
        flash('This function is only available in debug mode.', 'danger')
        return redirect(url_for('admin_dashboard'))
        
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))

    try:
        print("\nFetching data summary for admin...")
        user_count = User.query.count()
        election_count_total = Election.query.count()
        election_count_active = Election.query.filter_by(is_active=True).count()
        election_count_inactive = Election.query.filter_by(is_active=False).count()
        candidate_count = Candidate.query.count()
        vote_count = Vote.query.count()
        recent_logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(20).all()
        
        print("Data fetched successfully.")
        return render_template('admin/view_data.html', 
                               user_count=user_count,
                               election_count_total=election_count_total,
                               election_count_active=election_count_active,
                               election_count_inactive=election_count_inactive,
                               candidate_count=candidate_count,
                               vote_count=vote_count,
                               recent_logs=recent_logs)
                               
    except Exception as e:
        print(f"\n--- ERROR FETCHING DATA SUMMARY --- ")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Message: {str(e)}")
        import traceback
        print("Traceback:")
        traceback.print_exc()
        print("--- End Error Details ---")
        flash(f'Error fetching data summary: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))

# Temporary Debug Route to List All Users
@app.route('/admin/list_all_users')
@login_required
def admin_list_all_users():
    # Security checks: Debug mode and Admin user
    if not app.debug:
        flash('This function is only available in debug mode.', 'danger')
        return redirect(url_for('admin_dashboard'))
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))

    try:
        print("\nFetching all users for admin list...")
        all_users = User.query.order_by(User.id).all()
        print(f"Found {len(all_users)} users.")
        # Render a template instead of returning raw HTML
        return render_template('admin/list_users.html', users=all_users)
    except Exception as e:
        print(f"\n--- ERROR LISTING USERS --- ")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Message: {str(e)}")
        import traceback
        print("Traceback:")
        traceback.print_exc()
        print("--- End Error Details ---")
        flash(f'Error listing users: {str(e)}', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/election/<int:election_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_election(election_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('index'))

    election = Election.query.get_or_404(election_id)

    if request.method == 'POST':
        print(f"\n--- Admin Editing Election ID: {election_id} ---")
        # Get updated data from form
        election.title = request.form.get('title')
        election.description = request.form.get('description')
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        print(f"Received Title: {election.title}")
        print(f"Received Start Date Str (IST from form): {start_date_str}")
        print(f"Received End Date Str (IST from form): {end_date_str}")

        try:
            # Parse dates as naive (implicitly IST)
            start_date_naive_ist = datetime.strptime(start_date_str, '%Y-%m-%dT%H:%M')
            end_date_naive_ist = datetime.strptime(end_date_str, '%Y-%m-%dT%H:%M')
            print(f"Parsed Naive Start (IST): {start_date_naive_ist}")
            print(f"Parsed Naive End (IST): {end_date_naive_ist}")

            # Validate naive dates
            if start_date_naive_ist >= end_date_naive_ist:
                raise ValueError("Start date must be before end date.")

            # Update election object with naive IST dates
            election.start_date = start_date_naive_ist
            election.end_date = end_date_naive_ist

            # Commit changes
            db.session.commit() 
            print("Election details updated in DB.")

            # Re-check and update active status AFTER committing date changes
            election.update_active_status() 
            print(f"Active status re-checked. Current status: {election.is_active}")
            
            log_activity(current_user.id, "Edited election", f"Edited election '{election.title}' (ID: {election.id})")
            flash('Election updated successfully!', 'success')
            return redirect(url_for('index')) # Or admin_dashboard

        except ValueError as e:
            db.session.rollback() # Rollback if validation/parsing fails
            print(f"!!! ERROR updating election: {e}")
            flash(f'Error updating election: {e}', 'danger')
            # Re-render edit page with error
            return render_template('admin/edit_election.html', election=election)
        except Exception as e:
            db.session.rollback()
            print(f"!!! UNEXPECTED ERROR updating election: {str(e)}")
            flash('An unexpected error occurred while updating the election.', 'danger')
            return render_template('admin/edit_election.html', election=election)

    # GET request: Render the edit form
    print(f"Rendering edit form for election ID: {election_id}")
    return render_template('admin/edit_election.html', election=election)

# New Route for dedicated Elections page
@app.route('/elections')
def elections_page():
    print("\n--- Fetching Elections for Elections Page ---")
    all_elections = Election.query.order_by(Election.start_date.desc()).all()
    print(f"Found {len(all_elections)} elections in total (ordered by start date desc)")
    
    active_elections = []
    inactive_elections = []
    
    for election in all_elections:
        print(f"\nProcessing Election ID {election.id}: '{election.title}'")
        is_active = election.update_active_status()
        
        if is_active:
            active_elections.append(election)
            print(f"-> Classified as ACTIVE")
        else:
            inactive_elections.append(election)
            print(f"-> Classified as INACTIVE")

    print(f"\n--- Classification Complete for Elections Page ---")
    print(f"Active elections count: {len(active_elections)}")
    print(f"Inactive elections count: {len(inactive_elections)}")
    
    return render_template('elections.html', 
                         active_elections=active_elections,
                         inactive_elections=inactive_elections)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            email = request.form.get('email')
            subject = request.form.get('subject')
            message = request.form.get('message')
            
            # Send email to support team
            support_msg = Message(
                subject=f"New Contact Form Submission: {subject}",
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=[app.config['MAIL_DEFAULT_SENDER']],  # Send to your support email
                html=f"""
                <html>
                    <body>
                        <h2>New Contact Form Submission</h2>
                        <p><strong>From:</strong> {name} ({email})</p>
                        <p><strong>Subject:</strong> {subject}</p>
                        <p><strong>Message:</strong></p>
                        <p>{message}</p>
                    </body>
                </html>
                """
            )
            mail.send(support_msg)
            
            # Send confirmation email to the user
            user_msg = Message(
                subject="Thank you for contacting us",
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=[email],
                html=f"""
                <html>
                    <body>
                        <h2>Thank you for contacting us!</h2>
                        <p>Dear {name},</p>
                        <p>We have received your message and will get back to you soon.</p>
                        <p>Here's a copy of your message:</p>
                        <p><strong>Subject:</strong> {subject}</p>
                        <p><strong>Message:</strong></p>
                        <p>{message}</p>
                        <br>
                        <p>Best regards,<br>Online Voting System Team</p>
                    </body>
                </html>
                """
            )
            mail.send(user_msg)
            
            flash('Thank you for your message! We have sent you a confirmation email.', 'success')
            return redirect(url_for('about'))
            
        except Exception as e:
            print(f"Error sending email: {str(e)}")
            flash('Sorry, there was an error sending your message. Please try again later.', 'danger')
            return redirect(url_for('about'))
    
    return redirect(url_for('about'))

@app.route('/test_contact_email')
def test_contact_email():
    if not app.debug:
        return "Email testing is only available in debug mode."
    
    try:
        print("\n=== Testing Contact Form Email Functionality ===")
        
        # Test data
        test_data = {
            'name': 'Test User',
            'email': 'kumarakarthikeya_mangu@srmap.edu.in',  # Your email for testing
            'subject': 'Test Contact Form',
            'message': 'This is a test message from the contact form.'
        }
        
        # Test sending to support team
        print("\n1. Testing support team email...")
        support_msg = Message(
            subject=f"Test Contact Form: {test_data['subject']}",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[app.config['MAIL_DEFAULT_SENDER']],
            html=f"""
            <html>
                <body>
                    <h2>Test Contact Form Submission</h2>
                    <p><strong>From:</strong> {test_data['name']} ({test_data['email']})</p>
                    <p><strong>Subject:</strong> {test_data['subject']}</p>
                    <p><strong>Message:</strong></p>
                    <p>{test_data['message']}</p>
                </body>
            </html>
            """
        )
        mail.send(support_msg)
        print("Support email sent successfully!")
        
        # Test sending to user
        print("\n2. Testing user confirmation email...")
        user_msg = Message(
            subject="Test: Thank you for contacting us",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[test_data['email']],
            html=f"""
            <html>
                <body>
                    <h2>Test: Thank you for contacting us!</h2>
                    <p>Dear {test_data['name']},</p>
                    <p>This is a test email to verify the contact form functionality.</p>
                    <p>Here's a copy of your test message:</p>
                    <p><strong>Subject:</strong> {test_data['subject']}</p>
                    <p><strong>Message:</strong></p>
                    <p>{test_data['message']}</p>
                    <br>
                    <p>Best regards,<br>Online Voting System Team</p>
                </body>
            </html>
            """
        )
        mail.send(user_msg)
        print("User confirmation email sent successfully!")
        
        return '''
            <h1>Email Test Successful!</h1>
            <p>Test emails have been sent to:</p>
            <ul>
                <li>Support team: {}</li>
                <li>Test user: {}</li>
            </ul>
            <p>Please check both email inboxes (and spam folders) to verify receipt.</p>
            <p>If you don't receive the emails within a few minutes, check the console for error messages.</p>
        '''.format(app.config['MAIL_DEFAULT_SENDER'], test_data['email'])
        
    except Exception as e:
        print(f"\nError during email test: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        print(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No details available'}")
        
        return f'''
            <h1>Email Test Failed</h1>
            <p>Error: {str(e)}</p>
            <p>Check the console for detailed error logs.</p>
            <p>Common issues:</p>
            <ul>
                <li>Incorrect email password or App Password</li>
                <li>2-Step Verification not enabled</li>
                <li>Firewall blocking SMTP connections</li>
                <li>Incorrect email server settings</li>
            </ul>
        '''

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('static/profile_pictures', exist_ok=True)
    os.makedirs('static/candidate_photos', exist_ok=True)
    os.makedirs('static/team', exist_ok=True)
    os.makedirs('static/images', exist_ok=True)
    
    # Generate default profile picture if it doesn't exist
    default_pic_path = os.path.join('static', 'profile_pictures', 'default.jpg')
    try:
        # Create a 200x200 image with app colors
        img = Image.new('RGB', (200, 200), '#2c3e50')  # Dark blue/grey background
        draw = ImageDraw.Draw(img) # Correct indentation

        # Draw head (circle)
        draw.ellipse([50, 50, 150, 150], fill='#3498db')  # Grey-blue for head

        # Draw body (rounded rectangle)
        draw.rounded_rectangle([40, 120, 160, 180], radius=10, fill='#3498db')  # Grey-blue for body

        img.save(default_pic_path) # Correct indentation
        print("[Startup] Default profile picture generated at:", default_pic_path)
    except Exception as e:
        print("[Startup] Error generating default profile picture:", str(e))
    
    app.run(debug=True) 