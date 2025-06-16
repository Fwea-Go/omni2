<<<<<<< HEAD
from flask import Flask, jsonify, render_template, send_from_directory
=======
from flask import Flask, render_template, request, send_from_directory, jsonify
>>>>>>> 2b197ffd46f5015d4ee5ad3e7dba757ec022e343
import os

app = Flask(__name__, static_folder='static', template_folder='templates')

@app.route('/')
def index():
    return render_template('index.html')

<<<<<<< HEAD
# Serve original files directly
@app.route('/originals/<filename>')
def original_file(filename):
    return send_from_directory('static/originals', filename)

# Serve remixed files directly
@app.route('/remixes/<filename>')
def remix_file(filename):
    return send_from_directory('static/remixes', filename)

# API endpoint to get matched original/remix pairs
=======
>>>>>>> 2b197ffd46f5015d4ee5ad3e7dba757ec022e343
@app.route('/api/track-list')
def get_track_list():
    originals = os.listdir('static/originals')
    remixes = os.listdir('static/remixes')
<<<<<<< HEAD

=======
>>>>>>> 2b197ffd46f5015d4ee5ad3e7dba757ec022e343
    matches = []
    for file in originals:
        base = os.path.splitext(file)[0]
        remix_match = f"{base}.mp3"
        if remix_match in remixes:
            matches.append({
                "name": base.replace('_', ' ').title(),
<<<<<<< HEAD
                "original": f"/originals/{file}",
                "remix": f"/remixes/{remix_match}"
            })
    return jsonify(matches)

if __name__ == '__main__':
    app.run(debug=True)
=======
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

@app.route('/api/tiers')
def remix_tiers():
    tiers = [
        {
            "id": "jit",
            "name": "Florida Jit",
            "price": 50,
            "description": "Basic flip. Good vibes, quick turnaround.",
            "features": ["1 Remix", "MP3 Delivery", "2 Revisions"]
        },
        {
            "id": "heat",
            "name": "Drop That Heat Bwoi!",
            "price": 150,
            "description": "Heat pack with extended bounce and polish.",
            "features": ["2 Remixes", "WAV & MP3", "Stems Included", "4 Revisions"]
        },
        {
            "id": "vibes",
            "name": "Came For Good Vibes",
            "price": 300,
            "description": "Premium treatment. Lush. Festival-ready.",
            "features": ["Up to 3 Remixes", "HQ Mastering", "Mix Stems", "Unlimited Revisions"]
        }
    ]
    return jsonify(tiers)

@app.route('/api/submit', methods=['POST'])
def submit_track():
    # Simulate file receipt
    data = request.get_json()
    name = data.get("artist_name", "Unknown Artist")
    tier = data.get("tier", "jit")
    return jsonify({
        "status": "success",
        "message": f"Submission received from {name} for the {tier} package.",
        "preview_ready_url": "/static/sample-preview.mp3"
    })

@app.route('/api/preview-unlock', methods=['POST'])
def unlock_preview():
    data = request.get_json()
    payment_status = data.get("paid", False)

    if payment_status:
        return jsonify({
            "status": "unlocked",
            "file": "/static/unlocked-preview.mp3"
        })
    else:
        return jsonify({
            "status": "locked",
            "message": "Payment required to unlock the full preview."
        }), 402

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))  # Render sets this automatically
    app.run(host="0.0.0.0", port=port, debug=True)
>>>>>>> 2b197ffd46f5015d4ee5ad3e7dba757ec022e343
