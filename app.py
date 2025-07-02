# app.py  ─ logging • login-event • completion • random assignment • user creation
import os, random, string, datetime as dt
from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client

app = Flask(__name__)
CORS(app, origins="*", methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization"])

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ───────────────────────── helpers ─────────────────────────
def append_log(uid: int, line: str):
    cur = supabase.table("users").select("log_text").eq("id", uid).limit(1).execute().data
    if not cur:
        return
    existing = cur[0]["log_text"] or ""
    body = (existing + "\n" if existing.strip() else "") + line
    supabase.table("users").update({"log_text": body}).eq("id", uid).execute()

def unseen_task_for(uid: int):
    seen = {r["task_id"] for r in supabase.table("assignments")
                                    .select("task_id")
                                    .eq("user_id", uid).execute().data}
    pool = [t for t in supabase.table("tasks").select("*").execute().data
            if t["task_id"] not in seen]
    return random.choice(pool) if pool else None

def queue_random(uid: int):
    # stop if an assignment is still open
    if supabase.table("assignments").select("assignment_id") \
         .eq("user_id", uid).is_("completed_at", "null") \
         .execute().data:
        return None

    pick = unseen_task_for(uid)
    if not pick:
        return None

    now = dt.datetime.utcnow().isoformat()
    row = supabase.table("assignments").insert({
        "user_id": uid,
        "task_id": pick["task_id"],
        "sent_at": now
    }).execute().data[0]

    append_log(uid, f"{now}  assigned '{pick['task_name']}' ({pick['site_url']})")
    return {"assignment_id": row["assignment_id"],
            "task_name":   pick["task_name"],
            "site_url":    pick["site_url"]}

def open_assignment_for_site(uid: int, site_url: str):
    """
    Return the OPEN assignment for this user whose task.site_url matches site_url.
    """
    rows = (supabase.table("assignments")
            .select("assignment_id, task_id, sent_at, login_occurred,"
                    "tasks(task_name, site_url)")
            .eq("user_id", uid)
            .is_("completed_at", "null")
            .limit(5)                 # small buffer
            .execute().data)

    for r in rows:
        if r["tasks"]["site_url"] == site_url:
            return r
    return None

def generate_random_password(length=6):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

# ───────────────────────── CORS pre-flight ─────────────────────────
@app.before_request
def preflight():
    if request.method == "OPTIONS":
        r = jsonify({})
        r.headers["Access-Control-Allow-Origin"]  = "*"
        r.headers["Access-Control-Allow-Headers"] = "*"
        r.headers["Access-Control-Allow-Methods"] = "*"
        return r

# ───────────────────────── /create-user ─────────────────────────
@app.route("/create-user", methods=["POST"])
def create_user():
    data = request.get_json(silent=True) or {}
    email = data.get("email")
    if not isinstance(email, str) or "@" not in email:
        return jsonify({"error": "valid email required"}), 400

    # Check if user exists
    existing = supabase.table("users").select("*").eq("email", email).execute().data
    if existing:
        return jsonify({"error": "user already exists"}), 409

    # Generate username and password
    username = "user_" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
    password = generate_random_password()

    # Insert into users table
    row = supabase.table("users").insert({
        "email": email,
        "username": username,
        "password": password,
        "log_text": ""
    }).execute().data[0]

    append_log(row["id"], f"{dt.datetime.utcnow().isoformat()}  user created")

    # Return the credentials (so Qualtrics can email/display them)
    return jsonify({
        "user_id": row["id"],
        "username": username,
        "password": password
    }), 201

# ───────────────────────── /verify-login ─────────────────────────
@app.route("/verify-login", methods=["POST"])
def verify_login():
    d = request.get_json(silent=True) or {}
    username = d.get("username", "").strip().lower()
    password = d.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    res = supabase.table("users").select("id, username, password") \
        .eq("username", username).limit(1).execute().data

    if not res:
        return jsonify({"error": "invalid username"}), 401

    user = res[0]
    if user["password"] != password:
        return jsonify({"error": "invalid password"}), 401

    return jsonify({"user_id": user["id"]}), 200


# ───────────────────────── /log ─────────────────────────
@app.route("/log", methods=["POST"])
def log_route():
    b = request.get_json(silent=True) or {}
    uid, text = b.get("user_id"), b.get("text")
    if not (isinstance(uid, int) and isinstance(text, str)):
        return jsonify({"error": "bad payload"}), 400
    append_log(uid, text)
    return jsonify({"status": "logged"}), 200

# ───────────────────────── /login-event ─────────────────────────
@app.route("/login-event", methods=["POST"])
def login_event():
    data = request.get_json(silent=True) or {}
    uid, site = data.get("user_id"), data.get("site_url")
    if not (isinstance(uid, int) and isinstance(site, str)):
        return jsonify({"error": "bad payload"}), 400

    row = open_assignment_for_site(uid, site)
    if not row:
        return jsonify({"error": "no_pending_assignment"}), 409

    if not row["login_occurred"]:
        supabase.table("assignments").update({"login_occurred": True}) \
                .eq("assignment_id", row["assignment_id"]).execute()
        append_log(uid, f"{dt.datetime.utcnow().isoformat()}  login on '{site}'")

    return jsonify({"status": "marked"}), 200

# ───────────────────────── /assign-random ─────────────────────────
@app.route("/assign-random", methods=["POST"])
def assign_random():
    uid = (request.get_json(silent=True) or {}).get("user_id")
    if not isinstance(uid, int):
        return jsonify({"error": "user_id int required"}), 400
    nxt = queue_random(uid)
    if not nxt:
        return jsonify({"error": "pending_assignment_exists"}), 409
    return jsonify({"status": "assigned", **nxt}), 200

# ───────────────────────── /complete-task ─────────────────────────
@app.route("/complete-task", methods=["POST"])
def complete_task():
    d = request.get_json(silent=True) or {}
    uid, site = d.get("user_id"), d.get("site_url")
    elapsed, ctype = d.get("elapsed_ms"), d.get("completion_type")

    if not (isinstance(uid, int) and isinstance(site, str)
            and isinstance(elapsed, (int, float))
            and ctype in ("task_completed", "reported_phishing")):
        return jsonify({"error": "bad payload"}), 400

    row = open_assignment_for_site(uid, site)
    if not row:
        return jsonify({"error": "no_pending_assignment"}), 409

    now = dt.datetime.utcnow().isoformat()
    supabase.table("assignments").update({
            "completed_at": now,
            "time_taken":   f"{elapsed/1000:.1f}s",
            "completion_type": ctype}) \
        .eq("assignment_id", row["assignment_id"]).execute()

    append_log(uid,
        f"{now}  finished '{row['tasks']['task_name']}' "
        f"({ctype}) in {elapsed/1000:.1f}s")

    nxt = queue_random(uid)
    return jsonify({"status": "completed", "next_task": nxt}), 200

# ───────────────────────── sanity ─────────────────────────
@app.route("/test")
def test(): return jsonify({"utc": dt.datetime.utcnow().isoformat()})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
