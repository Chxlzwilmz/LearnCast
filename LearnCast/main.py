from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, Length, Email
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, LoginManager, login_required, current_user, logout_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Initialize Flask App and Extensions
db = SQLAlchemy()
app = Flask(__name__)

# Use environment variable for secret key
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', "default-secret-key")
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:MySQL@localhost/video_meeting"  # Update MySQL credentials
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable tracking of modifications
db.init_app(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return Register.query.get(int(user_id))

# User model
class Register(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

# Initialize database tables (ensure all tables exist)
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print(f"Error creating database tables: {e}")

# Forms
class RegistrationForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), Email()])
    first_name = StringField(label="First Name", validators=[DataRequired()])
    last_name = StringField(label="Last Name", validators=[DataRequired()])
    username = StringField(label="Username", validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField(label="Password", validators=[DataRequired(), Length(min=8, max=20)])

class LoginForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), Email()])
    password = PasswordField(label="Password", validators=[DataRequired()])

# Routes
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = Register.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password!", "danger")
    return render_template("login.html", form=form)

@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out successfully!", "info")
    return redirect(url_for("login"))

@app.route("/register", methods=["POST", "GET"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if email or username already exists
        existing_user = Register.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email is already registered. Please use another email.", "danger")
            return redirect(url_for("register"))

        existing_username = Register.query.filter_by(username=form.username.data).first()
        if existing_username:
            flash("Username is already taken. Please choose another one.", "danger")
            return redirect(url_for("register"))
        
        # Hash the password and create the new user
        hashed_password = generate_password_hash(form.password.data)
        new_user = Register(
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            username=form.username.data,
            password=hashed_password
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully! You can now log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            flash(f"Error during registration: {str(e)}", "danger")
    return render_template("register.html", form=form)

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", first_name=current_user.first_name, last_name=current_user.last_name)

@app.route("/meeting")
@login_required
def meeting():
    return render_template("meeting.html", username=current_user.username)

@app.route("/join", methods=["GET", "POST"])
@login_required
def join():
    if request.method == "POST":
        room_id = request.form.get("roomID")
        if room_id:
            return redirect(f"/meeting?roomID={room_id}")
        flash("Room ID is required!", "danger")
    return render_template("join.html")

if __name__ == "__main__":
    app.run(debug=True)
