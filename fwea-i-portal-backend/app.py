from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import stripe

app = Flask(__name__)
CORS(app)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

@app.route("/")
def home():
    return "FweA-I API is alive 🎛️"

@app.route("/api/playlists")
def get_playlists():
    return jsonify({
        "originals": [{"title": "Track 1", "file": "/audio/track1-original.mp3"}],
        "remixes": [{"title": "Remix 1", "file": "/audio/track1-remix.mp3"}]
    })

@app.route("/api/clean-edit", methods=["POST"])
def clean_edit():
    file = request.files["audio"]
    path = os.path.join(UPLOAD_DIR, "clean_" + file.filename)
    file.save(path)
    return jsonify({"message": "Cleaned!", "file": path})

@app.route("/api/master-track", methods=["POST"])
def master_track():
    file = request.files["audio"]
    path = os.path.join(UPLOAD_DIR, "mastered_" + file.filename)
    file.save(path)
    return jsonify({"message": "Mastered!", "file": path})

@app.route("/create-checkout-session/<price_id>")
def create_checkout_session(price_id):
    session = stripe.checkout.Session.create(
        line_items=[{"price": price_id, "quantity": 1}],
        mode='payment',
        success_url='https://fweagoflavaz.com/success',
        cancel_url='https://fweagoflavaz.com/cancel',
    )
    return jsonify({"id": session.id})