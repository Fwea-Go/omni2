from flask import Flask, render_template, request, send_from_directory, jsonify
import os

app = Flask(__name__, static_folder='static', template_folder='templates')

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

@app.route('/api/clean-edit', methods=['POST'])
def clean_edit():
    # Simulated endpoint
    return jsonify({'message': 'Clean version created!', 'file': '/static/sample-clean.mp3'})

@app.route('/api/master-track', methods=['POST'])
def master_track():
    # Simulated endpoint
    return jsonify({'message': 'Track mastered successfully!', 'file': '/static/sample-mastered.mp3'})



@app.route('/api/status')
def status():
    return jsonify({
        'status': '✅ FweA-I portal is live!',
        'message': 'Remix engine running. All vibes secured.',
        'version': 'v1.0',
    })



 if __name__ == '__main__':



    port = int(os.environ.get("PORT", 5000))  # Render sets this automatically
    app.run(host="0.0.0.0", port=port, debug=True)

