# app.py

import os
from datetime import datetime

from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client

app = Flask(__name__)

# Fix CORS configuration - allow your frontend origin
CORS(app, origins=["http://localhost:8000", "http://127.0.0.1:8000"], 
     methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"])

# ------------------------------------------------------------------------------
# 1) INITIALIZE SUPABASE CLIENT
# ------------------------------------------------------------------------------

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "Please set the SUPABASE_URL and SUPABASE_KEY environment variables."
    )

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


# ------------------------------------------------------------------------------
# 2) HELPERS
# ------------------------------------------------------------------------------

def append_log_to_user(user_id: int, new_text: str) -> bool:
    """
    Fetches the current log_text for this user from public.users,
    appends new_text (on its own line), and updates the table.
    Returns True if update succeeded, False otherwise.
    """
    try:
        # 1) Fetch existing log_text
        resp = (
            supabase.table("users")
            .select("log_text")
            .eq("id", user_id)
            .limit(1)
            .execute()
        )
        
        # Check if the response has data
        if not resp.data:
            app.logger.error(f"User ID {user_id} not found when appending log.")
            return False

        existing = resp.data[0].get("log_text") or ""

        # 2) Compute updated log_text
        timestamp = datetime.utcnow().isoformat() + "Z"
        # If existing is empty, don't prepend a newline
        if existing.strip() == "":
            updated = f"{new_text}"
        else:
            updated = f"{existing}\n{new_text}"

        # 3) Update the user's log_text
        upd = (
            supabase.table("users")
            .update({"log_text": updated})
            .eq("id", user_id)
            .execute()
        )
        
        # Check if update was successful by looking at the data
        if not upd.data:
            app.logger.error(f"Error updating log for user {user_id}")
            return False

        return True
        
    except Exception as e:
        app.logger.error(f"Exception in append_log_to_user: {e}")
        return False


# ------------------------------------------------------------------------------
# 3) ROUTES
# ------------------------------------------------------------------------------

# Add OPTIONS handler for preflight requests
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify({})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        return response

@app.route("/log", methods=["POST"])
def log_endpoint():
    """
    Expects JSON: { "user_id": <int>, "text": <string> }
    Appends `text` to public.users.log_text for that user_id.
    """
    try:
        payload = request.get_json()
        if not payload:
            return jsonify({"error": "Invalid JSON body"}), 400

        user_id = payload.get("user_id")
        text = payload.get("text")
        if not isinstance(user_id, int) or not isinstance(text, str):
            return jsonify({"error": "Must provide user_id (int) and text (string)"}), 400

        success = append_log_to_user(user_id, text)
        if not success:
            return jsonify({"error": "Failed to append log"}), 500

        return jsonify({"status": "logged"}), 200
        
    except Exception as e:
        app.logger.error(f"Exception in log_endpoint: {e}")
        return jsonify({"error": "Internal server error"}), 500
    


# Add a test route to verify the server is working
@app.route("/test", methods=["GET"])
def test_endpoint():
    return jsonify({"status": "Server is running", "message": "CORS should be working"}), 200


# ------------------------------------------------------------------------------
# 4) RUN THE APP
# ------------------------------------------------------------------------------

if __name__ == "__main__":
    # By default, Flask runs on port 5000
    app.run(host="0.0.0.0", port=5001, debug=True)