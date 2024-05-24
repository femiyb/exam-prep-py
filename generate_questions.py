from flask import Flask, request, jsonify
import openai
import os
import json
import difflib

app = Flask(__name__)

# Ensure the OpenAI API key is correctly set
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
    topic = data.get('topic', 'Default Topic')  # Default topic if none provided
    number_of_questions = 20  # Target number of questions to generate

    try:
        # Load existing questions or initialize an empty list
        try:
            with open('generated_content.json', 'r', encoding='utf-8') as file:
                questions = json.load(file)
        except FileNotFoundError:
            questions = []

        generated_count = 0
        while generated_count < number_of_questions:
            completion = client.chat.completions.create(
                model="gpt-4",  # Ensure to use a model compatible with chat completions
                messages=[
                    {"role": "system", "content": "You are a knowledgeable assistant who creates insightful multiple-choice questions on various topics. Make each question unique."},
                    {"role": "user", "content": f"Create a unique multiple-choice question about {topic} including four options labeled A to D and indicate the correct answer."}
                ]
            )

            # Assuming the structure of the completion response aligns with OpenAI's documentation
            if completion.choices:
                message_content = completion.choices[0].message['content'] if 'message' in completion.choices[0] else ""
                parsed_content = parse_generated_content(message_content)
                if parsed_content and not is_similar(parsed_content, questions):
                    parsed_content["id"] = len(questions) + 1
                    questions.append(parsed_content)
                    generated_count += 1

        # Save the updated list of questions
        with open('generated_content.json', 'w', encoding='utf-8') as file:
            json.dump(questions, file, ensure_ascii=False, indent=4)

        return jsonify({"response": f"Batch of {number_of_questions} questions added successfully."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5005)
