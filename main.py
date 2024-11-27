from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
import pyotp
from dotenv import load_dotenv
import os
from datetime import datetime, timedelta

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME")  # Set your email
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD")
  # Set your email app password

db = SQLAlchemy(app)
mail = Mail(app)
bcrypt = Bcrypt(app)


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)  # Encrypted password
    otp_secret = db.Column(db.String(16), nullable=False, default=pyotp.random_base32())
    otp_expiration = db.Column(db.DateTime, nullable=True)

# Initialize the database
@app.before_request
def create_tables():
    db.create_all()
    seed_database()

# Utility to seed the database with multiple users
def seed_database():
    """Seed the database with multiple user accounts."""
    users_to_seed = [
        {"email": "test1@example.com", "password": "password123"},
        {"email": "test2@example.com", "password": "password456"},
        {"email": "test3@example.com", "password": "password789"},
        {"email": "codablack24@gmail.com", "password": "password789"},
        {"email": "onuobodosampson@gmail.com", "password": "password789"},
    ]

    existing_emails = {user.email for user in User.query.all()}
    new_users = []

    for user_data in users_to_seed:
        if user_data["email"] not in existing_emails:
            hashed_password = bcrypt.generate_password_hash(user_data["password"]).decode('utf-8')
            new_users.append(
                User(email=user_data["email"], password=hashed_password)
            )

    if new_users:
        db.session.bulk_save_objects(new_users)
        db.session.commit()
        print(f"Seeded {len(new_users)} user(s) into the database.")
    else:
        print("No new users to seed.")

# Utility to send OTP
def send_otp(email, otp):
    msg = Message(
        subject="Your Login OTP",
        sender=os.environ.get("MAIL_USERNAME"),
        recipients=[email],
    )
    msg.body = f"Your OTP is {otp}. It is valid for 5 minutes."
    mail.send(msg)

# Endpoint to handle login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Invalid email or password"}), 401

    # Generate OTP
    totp = pyotp.TOTP(user.otp_secret)
    otp = totp.now()

    # Set expiration time for OTP
    user.otp_expiration = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()

    # Send OTP via email
    send_otp(user.email, otp)

    return jsonify({"message": "Login detected. OTP sent to your email."}), 200

# Endpoint to verify OTP
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({"error": "Email and OTP are required"}), 400

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    totp = pyotp.TOTP(user.otp_secret)
    if totp.verify(otp) and user.otp_expiration > datetime.utcnow():
        return jsonify({"message": "OTP verified successfully."}), 200
    else:
        return jsonify({"error": "Invalid or expired OTP."}), 400

if __name__ == '__main__':
    app.run(debug=True)



