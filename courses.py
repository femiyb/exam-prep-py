from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for all domains and routes

@app.route('/api/courses', methods=['GET'])
def get_courses():
    courses = [
        {'id': 1, 'name': 'Advanced Software Engineering'},
        {'id': 2, 'name': 'Research Methodology'},
        {'id': 3, 'name': 'Information Technology Security Governance'},
        {'id': 4, 'name': 'Internet and CyberSecurity'}
    ]
    return jsonify(courses)

if __name__ == '__main__':
    app.run(debug=True)
