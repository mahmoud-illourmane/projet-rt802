from app import app
from flask import jsonify, request

from src.classes.tools import write_log

@app.route('/client/api/hello', methods=['GET'])
def hello():
    if request.method == 'GET':
        available = {
            'bool': "True"
        }
        return jsonify(available), 200
    
    return jsonify({
        "error": "Method Not Allowed"
    }), 405