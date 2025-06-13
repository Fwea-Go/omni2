from flask import Flask, jsonify, render_template
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/track-list')
def get_track_list():
    originals = os.listdir('static/originals')
    remixes = os.listdir('static/remixes')

    matches = []
    for file in originals:
        base = os.path.splitext(file)[0]
        remix_match = f"{base}.mp3"
        if remix_match in remixes:
            matches.append({
                "name": base.replace('_', ' ').title(),
                "original": f"/static/originals/{file}",
                "remix": f"/static/remixes/{remix_match}"
            })
    return jsonify(matches)

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
