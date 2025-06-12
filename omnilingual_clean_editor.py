# omnilingual_clean_editor.py

from flask import Flask, request, jsonify
from flask_cors import CORS
from langdetect import detect
from profanity_filter import ProfanityFilter
import whisper
import os

app = Flask(__name__)
CORS(app)

model = whisper.load_model("base")

@app.route('/api/clean-edit', methods=['POST'])
def clean_version():
    if 'audio' not in request.files:
        return jsonify({'message': 'No audio file uploaded'}), 400

    audio_file = request.files['audio']
    file_path = os.path.join("uploads", audio_file.filename)
    audio_file.save(file_path)

    try:
        # Transcribe and detect language
        result = model.transcribe(file_path)
        transcript = result['text']
        lang = detect(transcript)

        # Censor the transcript based on detected language
        pf = ProfanityFilter(languages=[lang])
        clean_transcript = pf.censor(transcript)

        # Return result
        return jsonify({
            'message': 'Clean version transcript ready!',
            'language': lang,
            'original': transcript,
            'cleaned': clean_transcript
        })

    except Exception as e:
        return jsonify({'message': f'Error processing file: {str(e)}'}), 500

if __name__ == '__main__':
    os.makedirs("uploads", exist_ok=True)
    app.run(debug=True)
