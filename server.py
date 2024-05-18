import os
from flask import Flask, jsonify, request
from flask_cors import CORS
# Import the Blueprint
from evaluate_answer import evaluate_answer_bp
from get_questions import questions_bp

app = Flask(__name__)
CORS(app)  # Consider adjusting CORS for production

# Register the Blueprint with the Flask application
app.register_blueprint(questions_bp)
app.register_blueprint(evaluate_answer_bp)  # Register the Blueprint

@app.route('/')
def home():
    return "Hello, World!"

@app.route('/submit', methods=['POST'])
def submit():
    data = request.json  # Assuming JSON data is being submitted
    return jsonify({"received_data": data})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
