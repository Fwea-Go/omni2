from flask import Flask, request, jsonify, render_template, redirect, url_for
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/clean-edit', methods=['POST'])
def clean_edit():
    file = request.files.get('audio')
    if not file:
        return jsonify({'message': 'No file uploaded'}), 400

    filename = os.path.join('uploads', file.filename)
    file.save(filename)
    # Simulate processing
    return jsonify({'message': 'Clean version processed. Ready for download.'})

@app.route('/api/master-track', methods=['POST'])
def master_track():
    file = request.files.get('audio')
    if not file:
        return jsonify({'message': 'No file uploaded'}), 400

    filename = os.path.join('uploads', file.filename)
    file.save(filename)
    # Simulate processing
    return jsonify({'message': 'Track mastered successfully. Ready for download.'})

@app.route('/unlock')
def unlock():
    unlocked = request.args.get('unlocked') == 'true'
    return render_template('portal.html', unlocked=unlocked)

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    app.run(debug=True)
