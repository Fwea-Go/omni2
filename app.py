import os
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/")
def home():
    return "Fwea-Go AI Portal is Live 🔊🔥"

@app.route("/api/clean-edit", methods=["POST"])
def clean_version():
    file = request.files.get("audio")
    email = request.form.get("email")
    return jsonify({"message": "✅ Clean version ready. Check your email!", "secureDownloadUrl": "/static/clean_preview.mp3"})

@app.route("/api/master-track", methods=["POST"])
def master_version():
    file = request.files.get("audio")
    email = request.form.get("email")
    return jsonify({"message": "✅ Mastered track ready. Check your email!", "secureDownloadUrl": "/static/mastered_preview.mp3"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)


from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/clean-edit", methods=["POST"])
def clean_edit():
    file = request.files.get("audio")
    email = request.form.get("email")

    if not file or not email:
        return jsonify({"message": "Missing file or email"}), 400

    # Process the file (clean version logic goes here)
    # Placeholder response:
    return jsonify({
        "message": "Clean version uploaded successfully.",
        "secureDownloadUrl": "https://your-storage.com/cleaned.mp3"
    })

@app.route("/api/master-track", methods=["POST"])
def master_track():
    file = request.files.get("audio")
    email = request.form.get("email")

    if not file or not email:
        return jsonify({"message": "Missing file or email"}), 400

    # Process the file (mastering logic goes here)
    # Placeholder response:
    return jsonify({
        "message": "Track mastered successfully.",
        "secureDownloadUrl": "https://your-storage.com/mastered.mp3"
    })



import os
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100MB limit

@app.route("/")
def home():
    return "Fwea-Go AI Portal is Live 🔊🔥"

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    try:
        filepath = os.path.join("/tmp", file.filename)
        file.save(filepath)
        return jsonify({"message": "Upload successful", "filename": file.filename}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)




from flask import Flask, request, jsonify
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/api/clean-edit", methods=["POST"])
def clean_edit():
    if 'audio' not in request.files:
        return jsonify({"message": "No audio file found"}), 400
    
    audio_file = request.files['audio']
    email = request.form.get('email', 'unknown')

    filepath = os.path.join(UPLOAD_FOLDER, f"clean_{audio_file.filename}")
    audio_file.save(filepath)

    return jsonify({
        "message": "✅ Clean version processed!",
        "secureDownloadUrl": "https://yourdomain.com/downloads/clean.mp3"
    })

@app.route("/api/master-track", methods=["POST"])
def master_track():
    if 'audio' not in request.files:
        return jsonify({"message": "No audio file found"}), 400

    audio_file = request.files['audio']
    email = request.form.get('email', 'unknown')

    filepath = os.path.join(UPLOAD_FOLDER, f"master_{audio_file.filename}")
    audio_file.save(filepath)

    return jsonify({
        "message": "✅ Mastered version ready!",
        "secureDownloadUrl": "https://yourdomain.com/downloads/mastered.mp3"
    })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
