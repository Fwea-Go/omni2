
from flask import Flask, send_from_directory, jsonify
import os

app = Flask(__name__)

@app.route('/list-tracks')
def list_tracks():
    original_files = os.listdir('originals')
    remix_files = os.listdir('remixes')
    return jsonify({
        "originals": original_files,
        "remixes": remix_files
    })

@app.route('/originals/<path:filename>')
def get_original(filename):
    return send_from_directory('originals', filename)

@app.route('/remixes/<path:filename>')
def get_remix(filename):
    return send_from_directory('remixes', filename)

if __name__ == '__main__':
    app.run(debug=True)






from flask import Flask, render_template, send_from_directory, jsonify
import os

app = Flask(__name__, static_folder='static', template_folder='templates')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/originals/<filename>')
def original_file(filename):
    return send_from_directory('originals', filename)

@app.route('/remixes/<filename>')
def remix_file(filename):
    return send_from_directory('remixes', filename)

@app.route('/api/tracks')
def get_tracks():
    original_files = sorted(os.listdir('originals'))
    remix_files = sorted(os.listdir('remixes'))
    return jsonify({'originals': original_files, 'remixes': remix_files})

if __name__ == '__main__':
    app.run(debug=True)
