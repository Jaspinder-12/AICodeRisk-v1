from flask import Flask, request, jsonify, send_from_directory
import os
from analyzer import analyze_code

app = Flask(__name__, static_folder='../frontend')

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    code = data.get('code', '')
    
    if not code:
        return jsonify({"error": "No code provided"}), 400
        
    try:
        result = analyze_code(code)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
