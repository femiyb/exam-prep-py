import os
import json
from flask import Flask, request, jsonify, Blueprint
from flask_cors import CORS
import re
import google.generativeai as genai
from dotenv import load_dotenv

evaluate_answer_bp = Blueprint('evaluate_answer_bp', __name__)

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "https://eloquent-tulumba-cc13e7.netlify.app"}})

# Gemini API Configuration
gemini_api_key = os.environ.get("GEMINI_API_KEY")
if not gemini_api_key:
    raise ValueError("GEMINI_API_KEY environment variable not set.")
genai.configure(api_key=gemini_api_key)

# Instantiate the model
model = genai.GenerativeModel('gemini-pro')

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
        f"Evaluate this answer and provide a rating out of 10. Write out a perfect reply."
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
