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
