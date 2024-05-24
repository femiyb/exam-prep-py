import logging
import os
import uuid
import requests
import re
import json
from flask import Flask, request, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, JWTManager
from flask_cors import CORS
from flask_migrate import Migrate
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "https://eloquent-tulumba-cc13e7.netlify.app"}})

# Set the SECRET_KEY, provide a default value if not set
secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')
serializer = URLSafeTimedSerializer(secret_key)

# Use the DATABASE_URL environment variable for the database URI
database_url = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql+psycopg2://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SECRET_KEY'] = secret_key
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Gemini API Configuration
gemini_api_key = os.environ.get("GEMINI_API_KEY")
if not gemini_api_key:
    raise ValueError("GEMINI_API_KEY environment variable not set.")
genai.configure(api_key=gemini_api_key)
model = genai.GenerativeModel('gemini-pro')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    reset_token = db.Column(db.String(200), nullable=True)
    email_confirmed = db.Column(db.Boolean, default=False)

def send_simple_message(to, subject, html):
    mailgun_domain = os.environ.get('MAILGUN_DOMAIN')
    mailgun_api_key = os.environ.get('MAILGUN_API_KEY')
    response = requests.post(
        f"https://api.eu.mailgun.net/v3/{mailgun_domain}/messages",
        auth=("api", mailgun_api_key),
        data={"from": f"Exam Prep App <mailgun@{mailgun_domain}>",
              "to": [to],
              "subject": subject,
              "html": html})
    
    logger.debug(f"Mailgun response: {response.status_code}, {response.text}")
    return response

@app.route('/api/register', methods=['OPTIONS', 'POST'])
def register():
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'Preflight request successful'})
        response.headers.add('Access-Control-Allow-Origin', 'https://eloquent-tulumba-cc13e7.netlify.app')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        return response
    elif request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        logger.debug(f'Registration attempt with email: {email}')
        if User.query.filter_by(email=email).first():
            logger.warning(f'Registration failed: Email already registered - {email}')
            return jsonify({'error': 'Email already registered'}), 409
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        token = serializer.dumps(email, salt='email-confirm')
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = f'<p>Thank you for registering! Please click the link to confirm your email address:</p><p><a href="{confirm_url}">{confirm_url}</a></p>'
        send_simple_message(email, "Please confirm your email", html)
        logger.debug(f'Registration successful: {email}. Confirmation email sent.')
        return jsonify({'message': 'Registration successful! Please check your email to confirm your address.'}), 201

@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        logger.error('Confirmation link expired.')
        return jsonify({'message': 'The confirmation link has expired.'}), 400
    except BadTimeSignature:
        logger.error('Invalid confirmation link.')
        return jsonify({'message': 'Invalid confirmation link.'}), 400

    user = User.query.filter_by(email=email).first()
    if user.email_confirmed:
        logger.info(f'Email already confirmed: {email}')
        return jsonify({'message': 'Account already confirmed.'}), 200
    
    user.email_confirmed = True
    db.session.commit()
    logger.info(f'Email confirmed successfully: {email}')
    return jsonify({'message': 'Email confirmed successfully!'})    

@app.route('/api/login', methods=['OPTIONS', 'POST'])
def login():
    if request.method == 'OPTIONS':
        response = jsonify({'message': 'Preflight request successful'})
        response.headers.add('Access-Control-Allow-Origin', 'https://eloquent-tulumba-cc13e7.netlify.app')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
        return response
    elif request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        logger.debug(f'Login attempt with email: {email}')
        user = User.query.filter_by(email=email).first()

        if not user:
            logger.warning(f'Login failed: Invalid credentials for email: {email}')
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not bcrypt.check_password_hash(user.password, password):
            logger.warning(f'Login failed: Invalid password for email: {email}')
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if not user.email_confirmed:
            logger.warning(f'Login failed: Email not confirmed for email: {email}')
            return jsonify({'error': 'Email not confirmed. Please confirm your email first.'}), 403

        access_token = create_access_token(identity={'id': user.id, 'email': user.email})
        logger.info(f'Login successful for email: {email}')
        return jsonify({'access_token': access_token})

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    logger.debug(f'Password reset request for email: {email}')
    user = User.query.filter_by(email=email).first()
    if not user:
        logger.warning(f'Password reset failed: Email not found - {email}')
        return jsonify({'error': 'Email not found'}), 404
    
    reset_token = str(uuid.uuid4())
    user.reset_token = reset_token
    db.session.commit()

    reset_url = url_for('reset_password', token=reset_token, _external=True)
    html = f'<p>Please click the link to reset your password:</p><p><a href="{reset_url}">{reset_url}</a></p>'
    send_simple_message(email, "Password Reset Request", html)
    logger.info(f'Password reset link sent to email: {email}')
    return jsonify({'message': 'Reset link sent to your email'}), 200

@app.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    data = request.get_json()
    new_password = data.get('new_password')
    logger.debug(f'Password reset attempt with token: {token}')
    
    user = User.query.filter_by(reset_token=token).first()
    if not user:
        logger.warning(f'Password reset failed: Invalid or expired reset token')
        return jsonify({'error': 'Invalid or expired reset token'}), 400
    
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed_password
    user.reset_token = None
    db.session.commit()
    logger.info(f'Password reset successfully for email: {user.email}')
    return jsonify({'message': 'Password reset successfully!'}), 200

@app.route('/evaluate-answer/<module>/<examType>', methods=['POST'])
def evaluate_answer(module, examType):
    print(f"Received request for module: {module}, examType: {examType}")
    data = request.json
    question_id = data.get('questionId')
    user_answer = data.get('answer')
    print(f"question_id: {question_id}, user_answer: {user_answer}")

    # Load the questions and proposed answers
    try:
        with open(f'json/questions-{module}-{examType}.json', 'r', encoding='utf-8') as file:
            questions = json.load(file)
    except FileNotFoundError:
        return jsonify({"error": "Questions file not found."}), 404

    # Find the question and its proposed answer by ID
    question_item = next((item for item in questions if item["id"] == question_id), None)
    if not question_item:
        return jsonify({"error": "Question not found."}), 404

    proposed_answer = question_item.get('proposedAnswer')

    # Crafting the prompt to include a request for a rating out of 10
    prompt_message = (
        f"Question: {question_item['question']}\n"
        f"User Answer: {user_answer}\n"
        f"Evaluate this answer and provide a rating out of 10. Write out a perfect reply, try to format and style it correctly"
    )

    try:
        # Generate Response from Gemini
        response = model.generate_content(
            contents=[{"parts": [{"text": prompt_message}]}],
            generation_config={
                "temperature": 0.7,  # Adjust this for creativity
                "max_output_tokens": 1000  # Limit response length
            }
        )

        # Extract the full response text
        full_response = response.candidates[0].content.parts[0].text

        # Extract Rating (Adjust this regex based on Gemini's response format)
        rating_match = re.search(r"(\d+)/10", full_response)
        rating = int(rating_match.group(1)) if rating_match else None

        return jsonify({"evaluation": full_response, "rating": rating, "proposedAnswer": proposed_answer}), 200

    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON data"}), 400
    except Exception as e:
        return jsonify({"error": f"Error: {e}"}), 500

@app.route('/api/test-email', methods=['GET'])
def test_email():
    email = request.args.get('email')
    if not email:
        return jsonify({'error': 'Email parameter is missing'}), 400
    
    subject = "Test Email"
    html = "<p>This is a test email sent from your Flask application using Mailgun.</p>"
    
    response = send_simple_message(email, subject, html)
    if response.status_code == 200:
        return jsonify({'message': 'Test email sent successfully'}), 200
    else:
        return jsonify({'error': 'Failed to send test email'}), 500

@app.route('/api/resend-confirmation', methods=['POST'])
def resend_confirmation():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if user.email_confirmed:
        return jsonify({'message': 'Email is already confirmed'}), 200
    
    token = serializer.dumps(email, salt='email-confirm')
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = f'<p>Please click the link to confirm your email address:</p><p><a href="{confirm_url}">{confirm_url}</a></p>'
    send_simple_message(email, "Resend Confirmation Email", html)
    return jsonify({'message': 'Confirmation email resent successfully'}), 200


if __name__ == '__main__':
    app.run(debug=True, port=int(os.environ.get('PORT', 5000)))
