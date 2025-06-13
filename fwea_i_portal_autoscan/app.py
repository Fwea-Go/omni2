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
