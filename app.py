from flask import Flask, jsonify, render_template, send_from_directory
import os

app = Flask(__name__, static_folder='static', template_folder='templates')

@app.route('/')
def index():
    return render_template('index.html')

# Serve original files directly
@app.route('/originals/<filename>')
def original_file(filename):
    return send_from_directory('static/originals', filename)

# Serve remixed files directly
@app.route('/remixes/<filename>')
def remix_file(filename):
    return send_from_directory('static/remixes', filename)

# API endpoint to get matched original/remix pairs
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
                "original": f"/originals/{file}",
                "remix": f"/remixes/{remix_match}"
            })
    return jsonify(matches)

if __name__ == '__main__':
    app.run(debug=True)
