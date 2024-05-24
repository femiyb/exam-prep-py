<<<<<<< HEAD
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
=======
from flask import Flask, request
import openai
import os
import json
import difflib

app = Flask(__name__)

client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def parse_generated_content(content):
    try:
        lines = content.strip().split('\n')
        question = next((line.split('Question:', 1)[1].strip() for line in lines if 'question:' in line.lower()), None)
        options = [line.split(')', 1)[1].strip() for line in lines if ')' in line and line[0].isalpha() and line[1] == ')']
        correct_answer_line = next((line for line in lines if 'correct answer:' in line.lower()), None)

        if not options or not correct_answer_line:
            print(f"Failed to parse options or correct answer: {content}")
            return None

        correct_answer = correct_answer_line.split('Correct Answer:', 1)[1].strip()
        correct_answer = correct_answer.split(')', 1)[1].strip() if ')' in correct_answer else correct_answer

        return {
            "question": question,
            "options": options,
            "correctAnswer": correct_answer
        }
    except Exception as e:
        print(f"An error occurred during parsing: {e}")
        return None

def is_similar(new_question, questions):
    for question in questions:
        if difflib.SequenceMatcher(None, new_question["question"], question["question"]).ratio() > 0.75:
            return True
    return False

@app.route('/generate-question', methods=['POST'])
def generate_batch_questions():
    data = request.get_json()
    topic = data.get('topic', 'Default Topic')
    number_of_questions = 20

    try:
        with open('generated_content.json', 'r', encoding='utf-8') as file:
            questions = json.load(file)
    except FileNotFoundError:
        questions = []

    generated_count = 0
    while generated_count < number_of_questions:
        completion = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a knowledgeable assistant who creates insightful multiple-choice questions on various topics. Make each question unique."},
                {"role": "user", "content": f"Create a unique multiple-choice question about {topic} including four options labeled A to D and indicate the correct answer."}
            ]
        )

        parsed_content = parse_generated_content(completion.choices[0].message.content)
        if parsed_content and not is_similar(parsed_content, questions):
            parsed_content["id"] = len(questions) + 1
            questions.append(parsed_content)
            generated_count += 1

    with open('generated_content.json', 'w', encoding='utf-8') as file:
        json.dump(questions, file, ensure_ascii=False, indent=4)

    return json.dumps({"response": f"Batch of {number_of_questions} questions added successfully."}), 200, {'Content-Type': 'application/json'}

if __name__ == '__main__':
    app.run(debug=True, port=5003)
>>>>>>> server to heroku first commit
