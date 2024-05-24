from flask import Flask, request, jsonify
from flask_cors import CORS
import openai
import os
import json

app = Flask(__name__)
CORS(app)

# Set the OpenAI API key
openai.api_key = os.getenv("OPENAI_API_KEY")
# Creating a client instance with the OpenAI API key
client = openai.OpenAI(api_key=openai.api_key)

@app.route('/evaluate-answer-<module>-<examType>', methods=['POST'])
def evaluate_answer(module, examType):
    data = request.json
    question_id = data.get('questionId')
    user_answer = data.get('answer')

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
        f"Evaluate this answer and provide a rating out of 10."
    )

    # Use the client instance to call chat.completions.create
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt_message}
            ]
        )

        # Extracting the evaluation and attempting to parse the rating
        full_response = response.choices[0].message.content.strip()
        # Simple parsing strategy: extract the rating assuming it's included in the response
        rating_text = full_response.split('\n')[-1]
        rating_numbers = [int(s) for s in rating_text.split() if s.isdigit()]
        rating = rating_numbers[0] if rating_numbers else None  # Default to None if no rating found

        return jsonify({"evaluation": full_response, "rating": rating, "proposedAnswer": proposed_answer}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5008)
